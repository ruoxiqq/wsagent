#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多智能体协作防御系统 (Multi-Agent Defense)

架构(7 个角色智能体 + 事件总线协作):
  感知层  : FileSensorAgent / NetworkSensorAgent / ProcessSensorAgent  -- 只看不动
  关联层  : CorrelatorAgent        -- 滑动窗口把多源信号聚类成 incident(确定性快路径)
  研判层  : TriageAgent            -- LLM 大脑推理(ReAct)，失败降级为规则评分
  响应层  : ResponderAgent         -- LLM 工具调用(Function Calling)驱动的动作执行器 + 可撤销 + 人工确认
  取证层  : ForensicsAgent         -- 证据链 + 误报学习

智能体的"智能"集中在 TriageAgent + ResponderAgent: TriageAgent 把关联后的事件交给
LLM 做推理判断(识别规则引擎覆盖不到的未知/变形攻击, 给出可解释判定), 并以工具调用
(Function Calling)形式产出处置动作; ResponderAgent 经护栏校验后由有界执行器完成动作。
当 LLM 不可用时自动降级为确定性规则评分+固定分级, 保证演示不中断。

安全警告：本程序为安全教学演示用的防御智能体！需 root 权限(iptables/kill)。
"""

import os
import re
import sys
import json
import time
import queue
import signal
import threading
import subprocess
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import config
from event_bus import EventBus
from llm_backend import llm
from action_executor import ActionExecutor, tool_catalog_text

# ANSI 颜色
C_RED = '\033[91m'
C_YEL = '\033[93m'
C_GRN = '\033[92m'
C_BLU = '\033[94m'
C_PUR = '\033[95m'
C_RST = '\033[0m'


# ============================================================
# 共享黑板：所有 Agent 共享的状态(告警/处置/事件/学习/撤销栈)
# ============================================================
class Blackboard:
    def __init__(self):
        self.active = False          # 防护是否激活
        self.running = True          # 系统是否运行
        self.alerts = []
        self.alerts_lock = threading.Lock()
        self.actions = []
        self.actions_lock = threading.Lock()
        self.threats_blocked = 0
        self.incidents = {}          # id -> incident(含 signals/verdict/actions)
        self.incidents_lock = threading.Lock()
        self.undo_stack = []         # 响应处置撤销栈
        self.undo_lock = threading.Lock()
        self.fp_learnings = {}       # 误报特征 -> 次数
        self.fp_lock = threading.Lock()
        self.pending_actions = []     # 待人工确认的高危动作 [{aid,incident_id,tool,args,status}]
        self.pending_lock = threading.Lock()
        # 已处置进程的 cmd 特征监控名单: 用于杀掉"自拉起/重生"的 Beacon
        self.kill_watchlist = []
        self.kill_watchlist_lock = threading.Lock()
        self._inc_ctr = 0
        self._act_ctr = 0
        self._ctr_lock = threading.Lock()

    def new_incident_id(self):
        with self._ctr_lock:
            self._inc_ctr += 1
            return self._inc_ctr

    def new_action_id(self):
        with self._ctr_lock:
            self._act_ctr += 1
            return self._act_ctr

    def pending_count(self):
        with self.pending_lock:
            return len([p for p in self.pending_actions if p['status'] == 'PENDING'])

    def add_alert(self, level, category, message, detail=''):
        with self.alerts_lock:
            alert = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': level, 'category': category,
                'message': message, 'detail': detail,
            }
            self.alerts.append(alert)
            if len(self.alerts) > 500:
                self.alerts = self.alerts[-500:]
        icons = {'CRITICAL': C_RED + '[!!!]', 'WARNING': C_YEL + '[!]', 'INFO': C_GRN + '[*]'}
        icon = icons.get(level, C_GRN + '[*]')
        print("{} {} [{}] {} {} {}".format(
            icon, alert['time'], category, message, detail, C_RST))

    def add_action(self, action_type, target, result, undo=None):
        with self.actions_lock:
            rec = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'type': action_type, 'target': target, 'result': result,
            }
            self.actions.append(rec)
            if len(self.actions) > 500:
                self.actions = self.actions[-500:]
        if undo:
            with self.undo_lock:
                self.undo_stack.append(undo)


# ============================================================
# Agent 基类
# ============================================================
class BaseAgent:
    def __init__(self, bus, bb, name):
        self.bus = bus
        self.bb = bb
        self.name = name
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self._wrap, name=self.name, daemon=True)
        self.thread.start()

    def _wrap(self):
        try:
            self.run()
        except Exception as e:
            self.bb.add_alert('WARNING', 'SYSTEM', 'Agent %s 异常' % self.name, str(e))

    def stop(self):
        pass  # 依赖 daemon 线程 + running 标志

    def run(self):
        raise NotImplementedError


# ============================================================
# 感知层：文件感知 Agent
# ============================================================
class FileSensorAgent(BaseAgent):
    """监控上传目录，发现新/改脚本文件即扫描特征并发布 raw.file 事件。只感知不处置。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'FileSensor')
        self.seen = {}  # path -> mtime

    def run(self):
        self.bb.add_alert('INFO', 'FILE', '文件感知 Agent 启动', '监控: ' + config.UPLOAD_DIR)
        while self.bb.running:
            if not self.bb.active:
                time.sleep(2)
                continue
            try:
                if os.path.isdir(config.UPLOAD_DIR):
                    for item in os.listdir(config.UPLOAD_DIR):
                        if item in ('.', '..', '.htaccess', 'index.html'):
                            continue
                        path = os.path.join(config.UPLOAD_DIR, item)
                        if not os.path.isfile(path):
                            continue
                        if not item.endswith(('.php', '.py', '.phtml', '.php5', '.php7')):
                            continue
                        mtime = os.path.getmtime(path)
                        if self.seen.get(path) == mtime:
                            continue
                        self.seen[path] = mtime
                        matches = self._scan(path)
                        snippet = self._snippet(path)
                        self.bus.publish('raw.file', {
                            'time': time.time(),
                            'source': 'FileSensor',
                            'filename': item,
                            'path': path,
                            'matches': matches,
                            'is_malicious': len(matches) >= 2,
                            'snippet': snippet,
                        })
            except Exception as e:
                self.bb.add_alert('WARNING', 'FILE', '文件感知异常', str(e))
            time.sleep(config.INTERVAL_FILE)

    def _scan(self, path):
        try:
            with open(path, 'r', errors='replace') as f:
                content = f.read(500000)
        except Exception:
            return []
        hits = []
        for pat, desc in config.WEBSHELL_PATTERNS:
            if re.search(pat, content, re.IGNORECASE):
                hits.append(desc)
        return hits

    def _snippet(self, path):
        try:
            with open(path, 'r', errors='replace') as f:
                return f.read(2000)
        except Exception:
            return ''


# ============================================================
# 感知层：网络感知 Agent
# ============================================================
class NetworkSensorAgent(BaseAgent):
    """网络感知 Agent: 既检测 C2 外联, 也做行为分析识别内网横向移动/端口扫描。
    解析 ss 全量连接, 按进程聚合其内网目标 IP/端口, 超过阈值即判定横向移动并
    发布 kind='lateral' 的 raw.net 事件(携带 pid / internal_ips / internal_ports),
    供研判层触发 block_subnet / kill_process_tree 等处置原语。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'NetSensor')
        self.recent = {}      # C2 事件节流: (peer,proc) -> last_emit
        self.behavior = {}    # 内网行为: key(pid/proc) -> [(time,ip,port,pid,proc,local)]
        self.recent_lat = {}  # 横向移动事件节流: (key,reason) -> last_emit

    @staticmethod
    def _parse_connection(line):
        if 'LISTEN' in line:
            return None
        parts = line.split()
        if len(parts) < 6:
            return None
        local = parts[4]
        peer = parts[5]
        proc = parts[-1]

        def _split_addr(a):
            if ':' not in a:
                return None, None
            ip, _, port = a.rpartition(':')
            return ip, port
        lip, lport = _split_addr(local)
        pip, pport = _split_addr(peer)
        if not pip:
            return None
        try:
            pport_i = int(pport)
        except ValueError:
            pport_i = None
        m = re.search(r'pid=(\d+)', proc)
        pid = m.group(1) if m else None
        return {'local_ip': lip, 'local_port': lport,
                'peer_ip': pip, 'peer_port': pport_i,
                'proc': proc, 'pid': pid}

    def _collect(self):
        try:
            result = subprocess.run(['ss', '-tunap'], capture_output=True,
                                    text=True, timeout=5)
        except Exception:
            return []
        conns = []
        for line in result.stdout.split('\n'):
            c = self._parse_connection(line)
            if c and c['peer_ip']:
                conns.append(c)
        return conns

    def run(self):
        sub = '内网监控:%s' % (','.join(config.INTERNAL_SUBNETS) or '无')
        self.bb.add_alert('INFO', 'NETWORK', '网络感知 Agent 启动',
                          'C2端口:%s C2_IP:%s | %s' % (
                              config.C2_PORT, config.C2_HOST_IP, sub))
        while self.bb.running:
            if not self.bb.active:
                time.sleep(2)
                continue
            try:
                self._scan_once()
            except Exception as e:
                self.bb.add_alert('WARNING', 'NETWORK', '网络感知异常', str(e))
            time.sleep(config.INTERVAL_NET)

    def _scan_once(self):
        now = time.time()
        conns = self._collect()
        for c in conns:
            is_port = (c['peer_port'] == config.C2_PORT)
            is_ip = (c['peer_ip'] == config.C2_HOST_IP)
            if is_port or is_ip:
                self._emit_c2(c, now, 'C2端口' if is_port else 'C2主机IP')
            elif config.ip_in_cidrs(c['peer_ip'], config.INTERNAL_SUBNETS):
                self._record_internal(c, now)
        self._evaluate_lateral(now)

    def _emit_c2(self, c, now, reason):
        key = (c['peer_ip'], c['proc'])
        if now - self.recent.get(key, 0) < 10:
            return
        self.recent[key] = now
        self.bus.publish('raw.net', {
            'time': now, 'source': 'NetSensor',
            'local': c['local_ip'], 'peer': c['peer_ip'],
            'reason': reason, 'process': c['proc'],
            'kind': 'c2', 'pid': c['pid'],
        })

    def _record_internal(self, c, now):
        key = c['pid'] or c['proc'] or c['peer_ip']
        rec = self.behavior.setdefault(key, [])
        rec.append((now, c['peer_ip'], c['peer_port'], c['pid'], c['proc'], c['local_ip']))
        self.behavior[key] = [t for t in rec if now - t[0] <= config.NET_WINDOW]

    def _evaluate_lateral(self, now):
        for key, rec in list(self.behavior.items()):
            if not rec:
                self.behavior.pop(key, None)
                continue
            ips = set(t[1] for t in rec)
            ports = set(t[2] for t in rec if t[2] is not None)
            reasons = []
            if len(ips) >= config.LATERAL_DISTINCT_IPS:
                reasons.append('横向移动: 同进程连接 %d 个内网IP' % len(ips))
            if len(ports) >= config.LATERAL_DISTINCT_PORTS:
                reasons.append('纵向端口扫描: 连接 %d 个不同端口' % len(ports))
            if not reasons:
                continue
            sig = tuple(sorted(reasons))
            lkey = (key, sig)
            if now - self.recent_lat.get(lkey, 0) < config.NET_WINDOW:
                continue
            self.recent_lat[lkey] = now
            pid = rec[-1][3]
            proc = rec[-1][4]
            local = rec[-1][5]
            self.bus.publish('raw.net', {
                'time': now, 'source': 'NetSensor',
                'local': local,
                'peer': sorted(ips)[0] if ips else '',
                'reason': '; '.join(reasons),
                'process': proc,
                'kind': 'lateral',
                'pid': pid,
                'internal_ips': sorted(ips),
                'internal_ports': sorted(p for p in ports if p is not None),
            })


# ============================================================
# 感知层：进程感知 Agent
# ============================================================
class ProcessSensorAgent(BaseAgent):
    """用 ps 检测可疑进程，发布 raw.proc 事件。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'ProcSensor')
        self.emitted = set()

    def run(self):
        self.bb.add_alert('INFO', 'PROCESS', '进程感知 Agent 启动', '监控恶意进程特征')
        while self.bb.running:
            if not self.bb.active:
                time.sleep(2)
                continue
            try:
                result = subprocess.run(['ps', 'aux'], capture_output=True,
                                        text=True, timeout=5)
                for line in result.stdout.split('\n')[1:]:
                    parts = line.split(None, 10)
                    if len(parts) < 11:
                        continue
                    user, pid, command = parts[0], parts[1], parts[10]
                    reason = self._is_suspicious(user, command)
                    watch = False
                    if not reason:
                        # 命中"已封禁进程监控名单" -> 视为自拉起重生, 强制上报
                        w = self._watch_match(command)
                        if w:
                            reason = '已封禁进程重生(命中监控:%s)' % w[:40]
                            watch = True
                    if not reason:
                        continue
                    if pid in self.emitted:
                        continue
                    self.emitted.add(pid)
                    self.bus.publish('raw.proc', {
                        'time': time.time(),
                        'source': 'ProcSensor',
                        'pid': pid,
                        'user': user,
                        'cmd': command[:300],
                        'reason': reason,
                        'watch': watch,
                    })
            except Exception:
                pass
            time.sleep(config.INTERVAL_PROC)

    def _is_suspicious(self, user, command):
        for pat, desc in config.SUSPICIOUS_PROCESS_PATTERNS:
            if re.search(pat, command, re.IGNORECASE):
                return desc
        for bad in config.KNOWN_BAD_PROCESSES:
            if bad in command:
                return 'Beacon 后门(%s)' % bad
        if user == config.WEB_SERVER_USER and 'python' in command.lower():
            if '/tmp/' in command or 'beacon' in command.lower():
                return 'Web 服务用户运行可疑 Python'
        return None

    def _watch_match(self, command):
        """进程 cmd 是否命中"已封禁进程监控名单"(自拉起防护)。"""
        with self.bb.kill_watchlist_lock:
            for tok in self.bb.kill_watchlist:
                if tok and tok in command:
                    return tok
        return None


# ============================================================
# 关联层：CorrelatorAgent (确定性快路径)
# ============================================================
class CorrelatorAgent(BaseAgent):
    """滑动窗口聚类：把时间窗内的多源信号聚成 incident 交研判。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'Correlator')
        self.window = []          # [(time, topic, event)]
        self.last_incident_sig = None
        self.last_incident_time = 0

    def run(self):
        self.bb.add_alert('INFO', 'SYSTEM', '关联层 Agent 启动',
                          '窗口:%ss' % config.CORRELATION_WINDOW)
        q = self.bus.subscribe('raw.file', 'raw.net', 'raw.proc')
        while self.bb.running:
            try:
                ev = q.get(timeout=1)
            except queue.Empty:
                continue
            now = time.time()
            topic = ev.get('source', '').replace('FileSensor', 'raw.file') \
                .replace('NetSensor', 'raw.net').replace('ProcSensor', 'raw.proc')
            # 用 topic 字段更稳
            topic = self._topic_of(ev)
            self.window.append((now, topic, ev))
            # 裁剪窗口
            self.window = [x for x in self.window if now - x[0] <= config.CORRELATION_WINDOW]
            self._maybe_emit(now)

    def _topic_of(self, ev):
        src = ev.get('source', '')
        return {'FileSensor': 'raw.file', 'NetSensor': 'raw.net',
                'ProcSensor': 'raw.proc'}.get(src, src)

    def _maybe_emit(self, now):
        files = [e for _, t, e in self.window if t == 'raw.file' and e.get('is_malicious')]
        procs = [e for _, t, e in self.window if t == 'raw.proc']
        nets = [e for _, t, e in self.window if t == 'raw.net']
        c2 = [e for e in nets if e.get('kind') != 'lateral']
        laterals = [e for e in nets if e.get('kind') == 'lateral']

        sig = (len(files) > 0, len(procs) > 0, len(c2) > 0, len(laterals) > 0)
        # 需要有新信号且与上次不同才发
        if sig == self.last_incident_sig and now - self.last_incident_time < config.CORRELATION_WINDOW:
            return

        incident = None
        if laterals and procs:
            incident = self._build('高危', '内网横向移动 + 可疑进程', files, procs, nets)
        elif laterals:
            incident = self._build('高危', '内网横向移动/端口扫描', files, procs, nets)
        elif c2 and procs:
            incident = self._build('高危', '命令控制外联 + 可疑进程', files, procs, nets)
        elif files and procs:
            incident = self._build('中危', 'WebShell 上传 + 执行', files, procs, nets)
        elif c2:
            incident = self._build('中高危', 'C2 外联通信', files, procs, nets)
        elif files and config.SINGLE_SIGNAL_HIGH_RISK:
            incident = self._build('低中危', 'WebShell 上传', files, procs, nets)
        elif procs and config.SINGLE_SIGNAL_HIGH_RISK:
            incident = self._build('低危', '可疑进程', files, procs, nets)

        if incident:
            self.last_incident_sig = sig
            self.last_incident_time = now
            inc_id = self.bb.new_incident_id()
            incident['id'] = inc_id
            with self.bb.incidents_lock:
                self.bb.incidents[inc_id] = incident
            self.bb.add_alert('WARNING', 'CORRELATION',
                              '关联层产出事件 #%d' % inc_id, incident['summary'])
            self.bus.publish('incident', incident)

    def _build(self, level, summary, files, procs, nets):
        return {
            'time': time.time(),
            'level': level,
            'summary': summary,
            'signals': {
                'files': [{'filename': f['filename'], 'matches': f['matches'],
                            'path': f['path']} for f in files[-3:]],
                'processes': [{'pid': p['pid'], 'user': p['user'],
                                'cmd': p['cmd'][:120], 'reason': p['reason'],
                                'watch': p.get('watch', False)} for p in procs[-3:]],
                'network': [{'local': n.get('local'), 'peer': n.get('peer'),
                              'reason': n.get('reason'), 'process': n.get('process'),
                              'kind': n.get('kind'), 'pid': n.get('pid'),
                              'internal_ips': n.get('internal_ips'),
                              'internal_ports': n.get('internal_ports')} for n in nets[-3:]],
            }
        }


# ============================================================
# 研判层：TriageAgent (LLM 大脑 + 规则降级)
# ============================================================
def derive_actions(conf, incident):
    """按置信度分级, 从 incident.signals 派生处置动作(供规则降级与 LLM 无 actions 时兜底)。

    关键改动:
      - 已确认的 C2 外联(kind='c2')视为强 IoC, 无论置信度高低一律阻断对端 IP;
      - 与 C2 关联的进程改用 kill_process_tree 杀整棵树, 更抗自拉起;
      - 横向移动仍按原阈值处置。
    """
    sig = incident.get('signals', {})
    actions = []
    nets = sig.get('network', [])
    laterals = [n for n in nets if n.get('kind') == 'lateral']
    c2 = [n for n in nets if n.get('kind') == 'c2']
    # 1) 已确认 C2: 无条件阻断对端 IP(强 IoC, 且 iptables 规则幂等, 可 undo)
    if c2:
        seen = set()
        for n in c2:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', n.get('peer', ''))
            if m and m.group(1) not in seen:
                seen.add(m.group(1))
                actions.append({'tool': 'block_ip', 'args': {'ip': m.group(1)}})
    # 2) 隔离文件(达到 ISOLATE 门槛)
    if conf >= config.TIER_ISOLATE:
        for f in sig.get('files', []):
            p = f.get('path', '')
            if p:
                actions.append({'tool': 'quarantine_file', 'args': {'path': p}})
    # 3) 横向移动: 阻断内网靶机网段(达 BLOCK 门槛才做, 避免误伤正常内网)
    if conf >= config.TIER_BLOCK and laterals and config.INTERNAL_SUBNETS:
        actions.append({'tool': 'block_subnet',
                        'args': {'cidr': config.INTERNAL_SUBNETS[0]}})
    # 4) 终止进程(>=85): 与 C2 关联用 kill_process_tree 杀整棵树, 否则单 kill
    if conf >= 85:
        for p in sig.get('processes', []):
            if c2:
                actions.append({'tool': 'kill_process_tree',
                                'args': {'ppid': p.get('pid', ''), 'cmd': p.get('cmd', '')}})
            else:
                actions.append({'tool': 'kill_process',
                                'args': {'pid': p.get('pid', ''), 'cmd': p.get('cmd', '')}})
        for n in laterals:
            pid = n.get('pid')
            if pid:
                actions.append({'tool': 'kill_process_tree', 'args': {'ppid': pid}})
    return actions


class TriageAgent(BaseAgent):
    """智能所在：把 incident 喂给 LLM 推理，得可解释判定；LLM 不可用则规则评分。"""

    SYSTEM_PROMPT = (
        "你是一名网络安全研判与处置智能体。你将收到多个感知智能体关联后的安全事件证据。\n"
        "请判断是否是真实攻击, 识别 kill-chain 阶段"
        "(侦察/武器化/投递/利用/安装/命令控制/行动), 给出 0-100 置信度, \n"
        "用一句话中文说明依据, 并决定应执行的处置动作列表 actions。\n"
        "你只能从下方工具箱中选择动作, 并填入参数(优先从 incident.signals 取 path/ip/pid/cmd)。\n"
        "若证据显示内网横向移动(同进程连多个内网 IP, 或连 445/22/3389/5985 等端口), "
        "可调用 block_subnet(阻断内网靶机网段) 或 kill_process_tree(终止枢轴进程树)。\n"
        "网络证据字段说明: kind='c2'(外联C2) 或 'lateral'(内网横向移动); "
        "lateral 证据额外含 internal_ips(被扫描的内网IP列表)、internal_ports(端口列表)、pid(发起进程)。\n"
        "只返回 JSON, 不要额外文字。格式:\n"
        '{"is_attack": true/false, "stage": "阶段名", "confidence": 0-100, '
        '"reasoning": "中文一句话", "actions": [{"tool": "工具名", "args": {参数}}]}'
        "\n可用工具箱:\n" + tool_catalog_text() + "\n"
    )

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'Triage')

    def run(self):
        self.bb.add_alert('INFO', 'SYSTEM', '研判大脑 Agent 启动',
                          'LLM后端:%s' % config.LLM_BACKEND)
        q = self.bus.subscribe('incident')
        while self.bb.running:
            try:
                incident = q.get(timeout=1)
            except queue.Empty:
                continue
            verdict = self._triage(incident)
            src = verdict.get('source', 'rules')
            tag = '[LLM研判]' if src == 'llm' else '[规则降级]'
            with self.bb.incidents_lock:
                if incident['id'] in self.bb.incidents:
                    self.bb.incidents[incident['id']]['verdict'] = verdict
            self.bb.add_alert('CRITICAL', 'TRIAGE',
                              '%s 事件 #%d: %s (置信度 %s)' % (
                                  tag, incident['id'],
                                  '攻击' if verdict['is_attack'] else '正常',
                                  verdict['confidence']),
                              verdict['reasoning'])
            self.bus.publish('verdict', {'incident_id': incident['id'],
                                         'incident': incident, 'verdict': verdict})

    def _triage(self, incident):
        # 先尝试 LLM
        if llm.is_available():
            user_prompt = json.dumps(incident, ensure_ascii=False, indent=2)
            text = llm.chat(self.SYSTEM_PROMPT, user_prompt)
            if text:
                v = self._parse_json(text)
                if v:
                    v['source'] = 'llm'
                    v['llm_raw'] = text[:500]
                    return v
                self.bb.add_alert('WARNING', 'TRIAGE',
                                  'LLM 返回无法解析为 JSON，降级规则评分', text[:200])
            else:
                self.bb.add_alert('WARNING', 'TRIAGE',
                                  'LLM 调用失败(检查密钥/网络/后端是否可达)，已降级规则评分', '')
        # 降级：规则评分
        return self._rule_score(incident)

    def _parse_json(self, text):
        try:
            return self._coerce(json.loads(text))
        except Exception:
            pass
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            try:
                return self._coerce(json.loads(m.group(0)))
            except Exception:
                return None
        return None

    def _coerce(self, obj):
        try:
            actions = obj.get('actions', []) or []
            if not isinstance(actions, list):
                actions = []
            return {
                'is_attack': bool(obj.get('is_attack', True)),
                'stage': str(obj.get('stage', '未知')),
                'confidence': int(float(obj.get('confidence', 50))),
                'reasoning': str(obj.get('reasoning', '')),
                'response': str(obj.get('response', 'alert')),
                'actions': actions,
            }
        except Exception:
            return None

    def _rule_score(self, incident):
        sig = incident.get('signals', {})
        score = 0
        reasons = []
        nets = sig.get('network', [])
        c2_nets = [n for n in nets if n.get('kind') == 'c2']
        has_lateral = any(n.get('kind') == 'lateral' for n in nets)
        procs = sig.get('processes', [])
        watch_hit = any(p.get('watch') for p in procs)
        if nets:
            score += 40
            reasons.append('C2外联(+40)')
        if has_lateral:
            score += 45
            reasons.append('内网横向移动(+45)')
        if procs:
            score += 30
            reasons.append('可疑进程(+30)')
        if watch_hit:
            score += 30
            reasons.append('已封禁进程重生(+30)')
        files = sig.get('files', [])
        if files:
            mx = max((len(f.get('matches', [])) for f in files), default=0)
            if mx >= 2:
                score += 30
                reasons.append('WebShell命中>=2(+30)')
            elif mx >= 1:
                score += 10
                reasons.append('WebShell命中1(+10)')
        if nets and procs and files:
            score += 15
            reasons.append('多源关联(+15)')
        # 误报学习：命中 FP 特征则降分
        fp = self._fp_check(incident)
        if fp:
            score = max(0, score - 25)
            reasons.append('命中误报特征(-25)')
        score = min(score, 100)
        actions = derive_actions(score, incident)
        # 已确认 C2 或命中被监控名单 -> 一定判为攻击
        is_attack = score >= 40 or bool(c2_nets) or watch_hit
        # 处置等级: 确认 C2 至少 block; 其余按置信度
        if score >= 85:
            response = 'kill'
        elif score >= 80 or c2_nets:
            response = 'block'
        elif score >= 60:
            response = 'isolate'
        else:
            response = 'alert'
        return {
            'is_attack': is_attack,
            'stage': '命令控制' if nets else ('利用' if files else '未知'),
            'confidence': score,
            'reasoning': '规则评分: ' + ' '.join(reasons),
            'response': response,
            'actions': actions,
            'source': 'rules',
        }

    def _fp_check(self, incident):
        key = self._fp_key(incident)
        with self.bb.fp_lock:
            return self.bb.fp_learnings.get(key, 0) > 0

    @staticmethod
    def _fp_key(incident):
        sig = incident.get('signals', {})
        return json.dumps({
            'f': bool(sig.get('files')),
            'p': bool(sig.get('processes')),
            'n': bool(sig.get('network')),
            'sum': sig.get('files') and sig['files'][0].get('filename', ''),
        }, sort_keys=True)


# ============================================================
# 响应层：ResponderAgent (LLM 工具调用驱动 + 护栏 + 可撤销 + 人工确认)
# ============================================================
class ResponderAgent(BaseAgent):
    """LLM 以 Function-Calling 产出动作列表, 本 Agent 经护栏校验后由有界执行器完成;
    高危动作可人工确认(approve), 所有可逆动作可撤销(undo)。"""

    def __init__(self, bus, bb, executor):
        super().__init__(bus, bb, 'Responder')
        self.executor = executor

    def run(self):
        self.bb.add_alert('INFO', 'SYSTEM', '响应处置 Agent 启动',
                          'LLM 工具调用 + 护栏 + 可撤销')
        q = self.bus.subscribe('verdict')
        while self.bb.running:
            try:
                msg = q.get(timeout=1)
            except queue.Empty:
                continue
            self._respond(msg)

    def _respond(self, msg):
        incident = msg['incident']
        v = msg['verdict']
        conf = int(v.get('confidence', 0))
        src = v.get('source', 'rules')

        # LLM 产出的动作; 没有则用规则分级兜底
        actions = v.get('actions') or derive_actions(conf, incident)
        # 用信号补全 kill 动作所需的 cmd(用于清理其丢弃的临时文件)
        sig = incident.get('signals', {})
        procs_by_pid = {p.get('pid'): p for p in sig.get('processes', [])}
        for a in actions:
            if a.get('tool') in ('kill_process', 'kill_process_tree'):
                pid = (a.get('args') or {}).get('pid') or (a.get('args') or {}).get('ppid')
                if pid and pid in procs_by_pid and 'cmd' not in (a.get('args') or {}):
                    a.setdefault('args', {})['cmd'] = procs_by_pid[pid].get('cmd', '')

        # 自拉起防护: 命中"已封禁进程监控名单"的进程, 无论置信度直接杀整棵树
        for p in sig.get('processes', []):
            if self._proc_in_watch(p.get('cmd', '')):
                pid = p.get('pid')
                if pid:
                    actions.append({'tool': 'kill_process_tree',
                                    'args': {'ppid': pid, 'cmd': p.get('cmd', '')}})

        # 防御纵深: 确认 C2 外联无论研判来源(LLM/规则)一律阻断对端 IP
        for n in sig.get('network', []):
            if n.get('kind') == 'c2':
                m = re.search(r'(\d+\.\d+\.\d+\.\d+)', n.get('peer', ''))
                if m:
                    ip = m.group(1)
                    if not any(a.get('tool') == 'block_ip'
                               and a.get('args', {}).get('ip') == ip for a in actions):
                        actions.append({'tool': 'block_ip', 'args': {'ip': ip}})

        # 完全不是攻击、低置信、无动作 -> 仅记录
        if not v.get('is_attack', True) and conf < config.TIER_ALERT and not actions:
            self.bb.add_alert('INFO', 'RESPONSE',
                              '事件 #%d 置信度低，仅记录不处置' % incident['id'], '')
            return

        self.bb.threats_blocked += 1
        taken = []
        undo_items = []

        for a in actions:
            ok, reason = self.executor.validate(a)
            if not ok:
                self.bb.add_alert('WARNING', 'RESPONSE',
                                  '动作校验失败 %s: %s' % (a.get('tool'), reason), '')
                taken.append('[拒绝]%s:%s' % (a.get('tool'), reason))
                continue
            if self.executor.needs_approval(a['tool']):
                aid = self.bb.new_action_id()
                with self.bb.pending_lock:
                    self.bb.pending_actions.append({
                        'aid': aid, 'incident_id': incident['id'],
                        'tool': a['tool'], 'args': a.get('args', {}), 'status': 'PENDING'})
                tgt = self.executor._target(a['tool'], a.get('args', {}))
                taken.append('[待审批#%d]%s %s' % (aid, a['tool'], tgt))
                self.bb.add_alert('WARNING', 'RESPONSE',
                                  '事件#%d 高危动作待确认: %s (输入 approve %d)' % (
                                      incident['id'], a['tool'], aid), '')
            else:
                ok2, res, undo = self.executor.execute(a)
                taken.append('%s %s' % (a['tool'], res))
                if undo:
                    undo_items.append(undo)
                # 处置攻击性进程后, 记录其 cmd 到监控名单, 杀掉自拉起重生
                if a['tool'] in ('kill_process', 'kill_process_tree') and v.get('is_attack'):
                    self._add_watch((a.get('args') or {}).get('cmd', ''))

        self.bb.add_alert('CRITICAL', 'RESPONSE',
                          '事件 #%d 处置完成(置信度%d/%s): %s' % (
                              incident['id'], conf, src,
                              ' | '.join(taken) if taken else '仅告警'),
                          v.get('reasoning', ''))
        if undo_items:
            with self.bb.undo_lock:
                self.bb.undo_stack.append(
                    {'incident_id': incident['id'], 'items': undo_items})
        self.bus.publish('action', {'incident_id': incident['id'], 'taken': taken,
                                    'confidence': conf})

    def _proc_in_watch(self, cmd):
        if not cmd:
            return False
        with self.bb.kill_watchlist_lock:
            return any(tok and tok in cmd for tok in self.bb.kill_watchlist)

    def _add_watch(self, cmd):
        cmd = (cmd or '').strip()
        if not cmd:
            return
        tok = cmd[:120]
        with self.bb.kill_watchlist_lock:
            if tok not in self.bb.kill_watchlist:
                self.bb.kill_watchlist.append(tok)

    def undo_last(self):
        """撤销最近一组可逆处置(支持 quarantine/block/block_subnet/disable_account)。"""
        with self.bb.undo_lock:
            if not self.bb.undo_stack:
                return False, '无可撤销处置'
            bundle = self.bb.undo_stack.pop()
        undone = []
        for item in reversed(bundle['items']):
            try:
                if item['type'] == 'quarantine':
                    if os.path.exists(item['dst']):
                        os.rename(item['dst'], item['src'])
                        undone.append('恢复文件 %s' % item['src'])
                elif item['type'] == 'block':
                    subprocess.run(['iptables', '-D', 'OUTPUT', '-d', item['ip'], '-j', 'DROP'],
                                   capture_output=True, timeout=5)
                    undone.append('移除阻断 %s' % item['ip'])
                elif item['type'] == 'block_subnet':
                    subprocess.run(['iptables', '-D', 'OUTPUT', '-d', item['cidr'], '-j', 'DROP'],
                                   capture_output=True, timeout=5)
                    undone.append('移除网段阻断 %s' % item['cidr'])
                elif item['type'] == 'disable_account':
                    subprocess.run(['usermod', '-U', item['user']], capture_output=True, timeout=5)
                    undone.append('解锁账户 %s' % item['user'])
            except Exception as e:
                undone.append('撤销失败 %s: %s' % (item, e))
        self.bb.add_alert('INFO', 'RESPONSE',
                          '撤销事件 #%d 处置' % bundle['incident_id'], '; '.join(undone))
        return True, undone


# ============================================================
# 取证层：ForensicsAgent (证据链 + 误报学习)
# ============================================================
class ForensicsAgent(BaseAgent):
    """汇总 verdict+action 形成证据链报告；接收误报反馈更新学习。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'Forensics')
        self.timeline = []

    def run(self):
        self.bb.add_alert('INFO', 'SYSTEM', '取证复盘 Agent 启动', '证据链 + 误报学习')
        q = self.bus.subscribe('verdict', 'action')
        while self.bb.running:
            try:
                ev = q.get(timeout=1)
            except queue.Empty:
                continue
            self.timeline.append({'time': datetime.now().strftime('%H:%M:%S'), 'ev': ev})
            if len(self.timeline) > 1000:
                self.timeline = self.timeline[-1000:]
            if 'verdict' in ev:
                with self.bb.incidents_lock:
                    self.bb.incidents.get(ev['incident_id'], {}).setdefault('timeline', [])
                    self.bb.incidents[ev['incident_id']]['timeline'].append(
                        {'verdict': ev['verdict']})
            if 'taken' in ev:
                with self.bb.incidents_lock:
                    self.bb.incidents.get(ev['incident_id'], {}).setdefault('timeline', [])
                    self.bb.incidents[ev['incident_id']]['timeline'].append(
                        {'actions': ev['taken']})

    def mark_fp(self, inc_id):
        """标记某事件为误报，写入学习。"""
        with self.bb.incidents_lock:
            inc = self.bb.incidents.get(inc_id)
        if not inc:
            return False, '事件 #%d 不存在' % inc_id
        key = TriageAgent._fp_key(inc)
        with self.bb.fp_lock:
            self.bb.fp_learnings[key] = self.bb.fp_learnings.get(key, 0) + 1
        self.bb.add_alert('INFO', 'FORENSICS',
                          '事件 #%d 标记为误报，已学习' % inc_id, '')
        return True, '已学习，未来相似特征将降分'


# ============================================================
# 主编排器 + 控制台
# ============================================================
class MultiAgentDefense:
    def __init__(self):
        self.bus = EventBus()
        self.bb = Blackboard()
        self.file_sensor = FileSensorAgent(self.bus, self.bb)
        self.net_sensor = NetworkSensorAgent(self.bus, self.bb)
        self.proc_sensor = ProcessSensorAgent(self.bus, self.bb)
        self.correlator = CorrelatorAgent(self.bus, self.bb)
        self.triage = TriageAgent(self.bus, self.bb)
        self.executor = ActionExecutor(self.bb, hitl=config.HITL_DESTRUCTIVE)
        self.responder = ResponderAgent(self.bus, self.bb, self.executor)
        self.forensics = ForensicsAgent(self.bus, self.bb)
        self.agents = [self.file_sensor, self.net_sensor, self.proc_sensor,
                       self.correlator, self.triage, self.responder, self.forensics]

    def start(self):
        self.bb.running = True
        for a in self.agents:
            a.start()
        print(C_GRN + "[*] 多智能体防御系统已启动 (7 Agent 协作，防护默认关闭)" + C_RST)
        print(C_BLU + "    LLM 大脑: %s  |  模型: %s" % (
            config.LLM_BACKEND,
            config.OLLAMA_MODEL if config.LLM_BACKEND == 'ollama' else config.CLOUD_MODEL) + C_RST)

    def stop(self):
        self.bb.running = False
        self.bb.active = False
        print(C_YEL + "[*] 多智能体防御系统已停止" + C_RST)

    def activate(self):
        self.bb.active = True
        print(C_GRN + "[+] 防护模式: ON (7 Agent 协同防御已激活)" + C_RST)

    def deactivate(self):
        self.bb.active = False
        print(C_YEL + "[!] 防护模式: OFF" + C_RST)

    # ---- 控制台命令 ----
    def cmd_status(self):
        b = self.bb
        print("  " + "=" * 56)
        print("  多智能体防御系统状态")
        print("  " + "-" * 56)
        print("  防护模式:   %s" % (
            C_GRN + "ON" + C_RST if b.active else C_YEL + "OFF" + C_RST))
        print("  LLM 大脑:   %s (%s)" % (config.LLM_BACKEND,
            '可用' if llm.is_available() else C_RED + '不可用(将降级规则评分)' + C_RST))
        print("  拦截威胁:   %d" % b.threats_blocked)
        with b.alerts_lock:
            print("  告警总数:   %d" % len(b.alerts))
        with b.actions_lock:
            print("  处置动作:   %d" % len(b.actions))
        with b.incidents_lock:
            print("  事件总数:   %d" % len(b.incidents))
        with b.undo_lock:
            print("  可撤销处置: %d 组" % len(b.undo_stack))
        pc = b.pending_count()
        print("  待审批动作: %d 个%s" % (pc, C_YEL + ' (输入 pending 查看)' + C_RST if pc else ''))
        with b.fp_lock:
            print("  误报学习:   %d 条" % len(b.fp_learnings))
        print("  " + "=" * 56)

    def cmd_alerts(self):
        with self.bb.alerts_lock:
            alerts = list(self.bb.alerts)
        if not alerts:
            print("  [!] 暂无告警")
            return
        print("  " + "=" * 60)
        print("  告警列表 (最近 %d 条):" % len(alerts))
        print("  " + "=" * 60)
        colors = {'CRITICAL': C_RED, 'WARNING': C_YEL, 'INFO': C_GRN}
        for a in alerts[-30:]:
            c = colors.get(a['level'], '')
            print("  %s[%s] [%s] %s%s" % (c, a['time'], a['category'], a['message'], C_RST))
            if a['detail']:
                print("        %s%s%s" % (c, a['detail'][:80], C_RST))

    def cmd_actions(self):
        with self.bb.actions_lock:
            actions = list(self.bb.actions)
        if not actions:
            print("  [!] 暂无处置记录")
            return
        print("  " + "=" * 60)
        for a in actions[-30:]:
            print("  [%s] %s -> %s" % (a['time'], a['type'], a['target']))
            print("        %s" % a['result'])

    def cmd_report(self, inc_id=None):
        with self.bb.incidents_lock:
            ids = sorted(self.bb.incidents.keys())
            if inc_id is None:
                if not ids:
                    print("  [!] 暂无事件")
                    return
                inc_id = ids[-1]
            inc = self.bb.incidents.get(inc_id)
        if not inc:
            print("  [!] 事件 #%s 不存在" % inc_id)
            return
        print(C_PUR + "  " + "=" * 60 + C_RST)
        print(C_PUR + "  取证报告 - 事件 #%d" % inc_id + C_RST)
        print(C_PUR + "  " + "=" * 60 + C_RST)
        print("  等级: %s  |  摘要: %s" % (inc.get('level'), inc.get('summary')))
        sig = inc.get('signals', {})
        if sig.get('files'):
            print("  [文件证据]")
            for f in sig['files']:
                print("    - %s  命中: %s" % (f['filename'], ', '.join(f['matches'])))
        if sig.get('processes'):
            print("  [进程证据]")
            for p in sig['processes']:
                print("    - PID %s (%s)  %s" % (p['pid'], p['reason'], p['cmd'][:60]))
        if sig.get('network'):
            print("  [网络证据]")
            for n in sig['network']:
                kind = n.get('kind')
                tag = ' [横向移动]' if kind == 'lateral' else (' [C2]' if kind == 'c2' else '')
                print("    - %s -> %s  (%s)%s" % (n.get('local'), n.get('peer'),
                                                  n.get('reason'), tag))
                if n.get('internal_ips'):
                    print("        内网目标: %s  端口: %s" % (
                        ', '.join(n['internal_ips']),
                        ', '.join(str(p) for p in (n.get('internal_ports') or []))))
        v = inc.get('verdict')
        if v:
            print("  [研判结论]")
            print("    攻击: %s  |  阶段: %s  |  置信度: %s" % (
                v.get('is_attack'), v.get('stage'), v.get('confidence')))
            print("    依据: %s" % v.get('reasoning'))
            print("    来源: %s" % v.get('source'))
            acts = v.get('actions') or []
            if acts:
                print("    建议动作(LLM 工具调用):")
                for a in acts:
                    print("      - %s(%s)" % (a.get('tool'), a.get('args')))
            else:
                print("    建议: %s" % v.get('response'))
        tl = inc.get('timeline', [])
        if tl:
            print("  [处置时间线]")
            for t in tl:
                if 'verdict' in t:
                    print("    - 研判完成")
                if 'actions' in t:
                    print("    - 处置: %s" % ', '.join(t['actions']))
        print("  " + "=" * 60)

    def cmd_undo(self):
        ok, msg = self.responder.undo_last()
        if ok:
            print(C_GRN + "  [+] 已撤销: %s" % msg + C_RST)
        else:
            print(C_YEL + "  [!] %s" % msg + C_RST)

    def cmd_fp(self, inc_id):
        try:
            inc_id = int(inc_id)
        except ValueError:
            print("  [!] 用法: fp <事件ID>")
            return
        ok, msg = self.forensics.mark_fp(inc_id)
        print(("  [+] " if ok else "  [!] ") + msg)

    def cmd_pending(self):
        with self.bb.pending_lock:
            items = [p for p in self.bb.pending_actions if p['status'] == 'PENDING']
        if not items:
            print("  [!] 暂无待审批动作")
            return
        print("  " + "=" * 56)
        print("  待人工确认的高危动作:")
        for p in items:
            tgt = self.executor._target(p['tool'], p['args'])
            print("    #%d  事件#%d  %s %s" % (p['aid'], p['incident_id'], p['tool'], tgt))
        print("  执行: approve <ID> | approve all   拒绝: deny <ID> | deny all")
        print("  " + "=" * 56)

    def cmd_approve(self, token):
        if token == 'all':
            with self.bb.pending_lock:
                todo = [p for p in self.bb.pending_actions if p['status'] == 'PENDING']
        else:
            try:
                aid = int(token)
            except ValueError:
                print("  [!] 用法: approve <动作ID>|all")
                return
            with self.bb.pending_lock:
                todo = [p for p in self.bb.pending_actions
                        if p['status'] == 'PENDING' and p['aid'] == aid]
        if not todo:
            print("  [!] 无匹配的待审批动作")
            return
        for p in todo:
            p['status'] = 'APPROVED'
            ok, res, undo = self.executor.execute(
                {'tool': p['tool'], 'args': p['args']})
            if undo:
                with self.bb.undo_lock:
                    self.bb.undo_stack.append(
                        {'incident_id': p['incident_id'], 'items': [undo]})
            self.bb.add_alert('INFO', 'RESPONSE',
                              '已批准执行 #%d: %s -> %s' % (p['aid'], p['tool'], res), '')
            print(C_GRN + "  [+] 已执行 #%d: %s %s" % (p['aid'], p['tool'], res) + C_RST)

    def cmd_deny(self, token):
        if token == 'all':
            with self.bb.pending_lock:
                todo = [p for p in self.bb.pending_actions if p['status'] == 'PENDING']
        else:
            try:
                aid = int(token)
            except ValueError:
                print("  [!] 用法: deny <动作ID>|all")
                return
            with self.bb.pending_lock:
                todo = [p for p in self.bb.pending_actions
                        if p['status'] == 'PENDING' and p['aid'] == aid]
        if not todo:
            print("  [!] 无匹配的待审批动作")
            return
        for p in todo:
            p['status'] = 'DENIED'
            print(C_YEL + "  [!] 已拒绝 #%d: %s" % (p['aid'], p['tool']) + C_RST)

    def cmd_incidents(self):
        with self.bb.incidents_lock:
            ids = sorted(self.bb.incidents.keys())
        if not ids:
            print("  [!] 暂无事件")
            return
        for i in ids:
            with self.bb.incidents_lock:
                inc = self.bb.incidents[i]
            v = inc.get('verdict', {})
            print("  #%d  %s  %s  置信度:%s" % (
                i, inc.get('summary', ''), inc.get('level', ''),
                v.get('confidence', '-')))

    def cmd_log(self, n=30):
        import os
        logf = os.environ.get('DEFENSE_LOG_FILE', '/var/log/defense-llm.log')
        if not os.path.exists(logf):
            print("  [!] 暂无日志文件: %s" % logf)
            return
        try:
            with open(logf, 'r', encoding='utf-8') as f:
                lines = f.readlines()[-n:]
            print("  === LLM 调用日志 (最近 %d 行, %s) ===" % (len(lines), logf))
            for ln in lines:
                print("  " + ln.rstrip())
        except Exception as e:
            print("  [!] 读取日志失败: %s" % e)


def main():
    defense = MultiAgentDefense()
    defense.start()

    def sig_handler(sig, frame):
        defense.stop()
        sys.exit(0)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    print()
    print("命令: on | off | status | alerts | actions | incidents | report [id] | log | undo | fp <id> | pending | approve <ID>|all | deny <ID>|all | exit")
    print("  on/off        开关防护(对比有无防御)")
    print("  log           查看 LLM 调用日志(是否真调了 API / 成功或失败)")
    print("  report [id]   查看取证报告(LLM 研判依据 + 建议动作)")
    print("  undo          撤销最近一组处置")
    print("  fp <id>       标记事件为误报(写入学习)")
    print("  pending        查看待人工确认的高危动作")
    print("  approve <ID>|all   批准执行待确认动作(高危需确认时)")
    print("  deny <ID>|all     拒绝执行待确认动作")
    print()

    while True:
        try:
            active = "ON" if defense.bb.active else "OFF"
            user_input = input("Defense(%s)> " % active).strip()
            if not user_input:
                continue
            parts = user_input.split()
            cmd = parts[0].lower()
            if cmd in ('exit', 'quit'):
                defense.stop()
                print("  [*] 再见")
                break
            elif cmd in ('on', 'start'):
                defense.activate()
            elif cmd in ('off', 'stop'):
                defense.deactivate()
            elif cmd == 'status':
                defense.cmd_status()
            elif cmd == 'alerts':
                defense.cmd_alerts()
            elif cmd == 'actions':
                defense.cmd_actions()
            elif cmd == 'incidents':
                defense.cmd_incidents()
            elif cmd == 'report':
                defense.cmd_report(int(parts[1]) if len(parts) > 1 else None)
            elif cmd == 'log':
                defense.cmd_log()
            elif cmd == 'undo':
                defense.cmd_undo()
            elif cmd == 'fp':
                defense.cmd_fp(parts[1] if len(parts) > 1 else '')
            elif cmd == 'pending':
                defense.cmd_pending()
            elif cmd == 'approve':
                defense.cmd_approve(parts[1] if len(parts) > 1 else '')
            elif cmd == 'deny':
                defense.cmd_deny(parts[1] if len(parts) > 1 else '')
            elif cmd == 'help':
                print("  on/off/status/alerts/actions/incidents/report/undo/fp/pending/approve/deny/exit")
            else:
                print("  [!] 未知命令: %s (输入 help)" % cmd)
        except (KeyboardInterrupt, EOFError):
            print()
            continue
        except Exception as e:
            print("  [!] 错误: %s" % e)


if __name__ == '__main__':
    main()
