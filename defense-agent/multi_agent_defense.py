#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多智能体协作防御系统 (Multi-Agent Defense)

架构(7 个角色智能体 + 事件总线协作):
  感知层  : FileSensorAgent / NetworkSensorAgent / ProcessSensorAgent  -- 只看不动
  关联层  : CorrelatorAgent        -- 滑动窗口把多源信号聚类成 incident(确定性快路径)
  研判层  : TriageAgent            -- LLM 大脑推理(ReAct)，失败降级为规则评分
  响应层  : ResponderAgent         -- 分级响应 + 可撤销
  取证层  : ForensicsAgent         -- 证据链 + 误报学习

智能体的"智能"集中在 TriageAgent: 它把关联后的事件交给 LLM 做推理判断，
能识别规则引擎覆盖不到的未知/变形攻击，并给出可解释的判定依据。
当 LLM 不可用时自动降级为确定性规则评分，保证演示不中断。

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
        self._inc_ctr = 0
        self._ctr_lock = threading.Lock()

    def new_incident_id(self):
        with self._ctr_lock:
            self._inc_ctr += 1
            return self._inc_ctr

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
    """用 ss 检测到 C2 端口/IP 的外联，发布 raw.net 事件。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'NetSensor')
        self.recent = {}  # (peer,pid) -> last_emit

    def run(self):
        self.bb.add_alert('INFO', 'NETWORK', '网络感知 Agent 启动',
                          'C2端口:%s C2_IP:%s' % (config.C2_PORT, config.C2_HOST_IP))
        while self.bb.running:
            if not self.bb.active:
                time.sleep(2)
                continue
            try:
                result = subprocess.run(['ss', '-tunap'], capture_output=True,
                                        text=True, timeout=5)
                for line in result.stdout.split('\n'):
                    is_port = str(config.C2_PORT) in line
                    is_ip = config.C2_HOST_IP in line
                    if not (is_port or is_ip):
                        continue
                    if 'LISTEN' in line:
                        continue
                    if 'ESTAB' not in line and 'SYN' not in line:
                        continue
                    parts = line.split()
                    if len(parts) < 6:
                        continue
                    local_addr = parts[4]
                    peer_addr = parts[5]
                    proc_info = parts[-1] if parts else ''
                    key = (peer_addr, proc_info)
                    now = time.time()
                    if now - self.recent.get(key, 0) < 10:
                        continue
                    self.recent[key] = now
                    reason = 'C2端口' if is_port else 'C2主机IP'
                    self.bus.publish('raw.net', {
                        'time': now,
                        'source': 'NetSensor',
                        'local': local_addr,
                        'peer': peer_addr,
                        'reason': reason,
                        'process': proc_info,
                    })
            except Exception:
                pass
            time.sleep(config.INTERVAL_NET)


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

        sig = (len(files) > 0, len(procs) > 0, len(nets) > 0)
        # 需要有新信号且与上次不同才发
        if sig == self.last_incident_sig and now - self.last_incident_time < config.CORRELATION_WINDOW:
            return

        incident = None
        if nets and procs:
            incident = self._build('高危', '命令控制外联 + 可疑进程', files, procs, nets)
        elif files and procs:
            incident = self._build('中危', 'WebShell 上传 + 执行', files, procs, nets)
        elif nets:
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
                                'cmd': p['cmd'][:120], 'reason': p['reason']} for p in procs[-3:]],
                'network': [{'local': n['local'], 'peer': n['peer'],
                              'reason': n['reason'], 'process': n['process']} for n in nets[-3:]],
            }
        }


# ============================================================
# 研判层：TriageAgent (LLM 大脑 + 规则降级)
# ============================================================
class TriageAgent(BaseAgent):
    """智能所在：把 incident 喂给 LLM 推理，得可解释判定；LLM 不可用则规则评分。"""

    SYSTEM_PROMPT = (
        "你是一名网络安全研判分析智能体。你将收到来自多个感知智能体关联后的安全事件证据。\n"
        "请判断这是否是一次真实攻击，识别攻击所处的 kill-chain 阶段"
        "(侦察/武器化/投递/利用/安装/命令控制/行动)，给出 0-100 的置信度，\n"
        "用一句话中文说明推理依据，并推荐处置强度。\n"
        "只返回 JSON，不要任何额外文字。格式:\n"
        '{"is_attack": true/false, "stage": "阶段名", "confidence": 0-100, '
        '"reasoning": "中文一句话", "response": "alert|isolate|block|kill"}'
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
            return {
                'is_attack': bool(obj.get('is_attack', True)),
                'stage': str(obj.get('stage', '未知')),
                'confidence': int(float(obj.get('confidence', 50))),
                'reasoning': str(obj.get('reasoning', '')),
                'response': str(obj.get('response', 'alert')),
            }
        except Exception:
            return None

    def _rule_score(self, incident):
        sig = incident.get('signals', {})
        score = 0
        reasons = []
        if sig.get('network'):
            score += 40
            reasons.append('C2外联(+40)')
        if sig.get('processes'):
            score += 30
            reasons.append('可疑进程(+30)')
        files = sig.get('files', [])
        if files:
            mx = max((len(f.get('matches', [])) for f in files), default=0)
            if mx >= 2:
                score += 30
                reasons.append('WebShell命中>=2(+30)')
            elif mx >= 1:
                score += 10
                reasons.append('WebShell命中1(+10)')
        if sig.get('network') and sig.get('processes') and files:
            score += 15
            reasons.append('多源关联(+15)')
        # 误报学习：命中 FP 特征则降分
        fp = self._fp_check(incident)
        if fp:
            score = max(0, score - 25)
            reasons.append('命中误报特征(-25)')
        score = min(score, 100)
        resp = 'alert' if score < 40 else ('isolate' if score < 70 else
                  ('block' if score < 85 else 'kill'))
        return {
            'is_attack': score >= 40,
            'stage': '命令控制' if sig.get('network') else ('利用' if files else '未知'),
            'confidence': score,
            'reasoning': '规则评分: ' + ' '.join(reasons),
            'response': resp,
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
# 响应层：ResponderAgent (分级响应 + 可撤销)
# ============================================================
class ResponderAgent(BaseAgent):
    """按置信度/建议分级处置：告警→隔离→阻断→终止，动作可撤销。"""

    def __init__(self, bus, bb):
        super().__init__(bus, bb, 'Responder')

    def run(self):
        self.bb.add_alert('INFO', 'SYSTEM', '响应处置 Agent 启动', '分级响应')
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
        resp = v.get('response', 'alert')
        # 建议提升
        if resp == 'kill':
            conf = max(conf, 85)
        elif resp == 'block':
            conf = max(conf, 80)
        elif resp == 'isolate':
            conf = max(conf, 60)

        sig = incident.get('signals', {})
        undo_bundle = {'incident_id': incident['id'], 'items': []}
        taken = []

        if not v.get('is_attack') and conf < config.TIER_ALERT:
            self.bb.add_alert('INFO', 'RESPONSE',
                              '事件 #%d 置信度低，仅记录不处置' % incident['id'], '')
            return

        self.bb.threats_blocked += 1

        # 隔离文件
        if conf >= config.TIER_ISOLATE:
            for f in sig.get('files', []):
                ok, info = self._quarantine(f.get('path', ''))
                taken.append('隔离 %s' % f.get('filename', ''))
                if ok:
                    undo_bundle['items'].append(info)

        # 阻断网络
        if conf >= config.TIER_BLOCK:
            for n in sig.get('network', []):
                ok, info = self._block(n.get('peer', ''))
                if ok:
                    taken.append('阻断 %s' % n.get('peer', ''))
                    undo_bundle['items'].append(info)

        # 终止进程 + 删除文件
        if conf >= 85 or resp == 'kill':
            for p in sig.get('processes', []):
                self._kill(p.get('pid', ''))
                taken.append('终止 PID %s' % p.get('pid', ''))
            for bad in config.KNOWN_BAD_PROCESSES:
                if os.path.exists('/tmp/.system_update.py') and bad == '/tmp/.system_update.py':
                    try:
                        os.remove('/tmp/.system_update.py')
                        taken.append('删除 /tmp/.system_update.py')
                    except Exception:
                        pass

        self.bb.add_alert('CRITICAL', 'RESPONSE',
                          '事件 #%d 处置完成(置信度%d): %s' % (
                              incident['id'], conf, ' | '.join(taken) if taken else '仅告警'),
                          v.get('reasoning', ''))
        if undo_bundle['items']:
            with self.bb.undo_lock:
                self.bb.undo_stack.append(undo_bundle)
        self.bus.publish('action', {'incident_id': incident['id'], 'taken': taken,
                                    'confidence': conf})

    def _quarantine(self, path):
        try:
            if not path or not os.path.exists(path):
                return False, None
            os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
            dst = os.path.join(config.QUARANTINE_DIR,
                               os.path.basename(path) + '.' + str(int(time.time())))
            os.rename(path, dst)
            self.bb.add_action('QUARANTINE', path, '-> ' + dst,
                               undo={'type': 'quarantine', 'src': path, 'dst': dst})
            return True, {'type': 'quarantine', 'src': path, 'dst': dst}
        except Exception as e:
            self.bb.add_action('QUARANTINE', path, '失败: ' + str(e))
            return False, None

    def _block(self, peer):
        try:
            m = re.search(r'(\d+\.\d+\.\d+\.\d+)', peer)
            if not m:
                return False, None
            ip = m.group(1)
            subprocess.run(['iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'],
                           capture_output=True, timeout=5)
            self.bb.add_action('BLOCK_IP', ip, 'iptables OUTPUT DROP',
                               undo={'type': 'block', 'ip': ip})
            return True, {'type': 'block', 'ip': ip}
        except Exception as e:
            self.bb.add_action('BLOCK_IP', peer, '失败: ' + str(e))
            return False, None

    def _kill(self, pid):
        try:
            subprocess.run(['kill', '-9', str(pid)], capture_output=True, timeout=5)
            self.bb.add_action('KILL', pid, '已终止')
        except Exception as e:
            self.bb.add_action('KILL', pid, '失败: ' + str(e))

    def undo_last(self):
        """撤销最近一组可逆处置。"""
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
        self.responder = ResponderAgent(self.bus, self.bb)
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
                print("    - %s -> %s  (%s)" % (n['local'], n['peer'], n['reason']))
        v = inc.get('verdict')
        if v:
            print("  [研判结论]")
            print("    攻击: %s  |  阶段: %s  |  置信度: %s" % (
                v.get('is_attack'), v.get('stage'), v.get('confidence')))
            print("    依据: %s" % v.get('reasoning'))
            print("    来源: %s  |  建议: %s" % (v.get('source'), v.get('response')))
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
    print("命令: on | off | status | alerts | actions | incidents | report [id] | log | undo | fp <id> | exit")
    print("  on/off        开关防护(对比有无防御)")
    print("  log           查看 LLM 调用日志(是否真调了 API / 成功或失败)")
    print("  report [id]   查看取证报告(LLM 研判依据)")
    print("  undo          撤销最近一组处置")
    print("  fp <id>       标记事件为误报(写入学习)")
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
            elif cmd == 'help':
                print("  on/off/status/alerts/actions/incidents/report/undo/fp/exit")
            else:
                print("  [!] 未知命令: %s (输入 help)" % cmd)
        except (KeyboardInterrupt, EOFError):
            print()
            continue
        except Exception as e:
            print("  [!] 错误: %s" % e)


if __name__ == '__main__':
    main()
