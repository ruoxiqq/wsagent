#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
处置动作执行器 (Action Executor) + 工具箱 + 护栏 (Guardrail)

LLM 研判后以 Function-Calling 方式产出动作列表 [{tool, args}], 本模块负责:
  1. 工具箱注册 (quarantine_file / block_ip / block_subnet / kill_process /
     kill_process_tree / disable_account)
  2. 护栏校验: 动作必须在允许清单内, 参数类型/格式必须合法
  3. 执行: 调用有界代码完成动作, 返回结果与可撤销信息
  4. 可逆动作的 undo 信息由调用方收集到撤销栈

设计原则: LLM 只决定"调哪个工具 + 传什么参数", 真正的执行由受约束的代码完成,
绝不给 LLM 裸 shell 权限。这是现代安全智能体(Agentic)的标准做法。
"""

import os
import re
import time
import subprocess
import config


IP_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
CIDR_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
PID_RE = re.compile(r'^\d+$')
USER_RE = re.compile(r'^[A-Za-z0-9_.-]+$')


class ActionError(Exception):
    pass


def _run(cmd, timeout=5):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ============================================================
# 各工具实现 (有界代码, 不含 LLM 不可控逻辑)
# ============================================================
def _do_quarantine(path):
    if not path:
        raise ActionError('路径为空')
    if not os.path.exists(path):
        raise ActionError('文件不存在: %s' % path)
    os.makedirs(config.QUARANTINE_DIR, exist_ok=True)
    dst = os.path.join(config.QUARANTINE_DIR,
                       os.path.basename(path) + '.' + str(int(time.time())))
    os.rename(path, dst)
    return '隔离 -> %s' % dst, {'type': 'quarantine', 'src': path, 'dst': dst}


def _rule_exists(rule):
    """iptables -C 检查规则是否已存在(returncode==0 表示存在)。"""
    return _run(['iptables', '-C'] + rule).returncode == 0


def _do_block_ip(ip):
    rule = ['OUTPUT', '-d', ip, '-j', 'DROP']
    if _rule_exists(rule):
        return 'iptables 已阻断 %s (跳过)' % ip, None
    _run(['iptables', '-A'] + rule)
    return 'iptables 阻断 %s' % ip, {'type': 'block', 'ip': ip}


def _do_block_subnet(cidr):
    rule = ['OUTPUT', '-d', cidr, '-j', 'DROP']
    if _rule_exists(rule):
        return 'iptables 已阻断网段 %s (跳过)' % cidr, None
    _run(['iptables', '-A'] + rule)
    return 'iptables 阻断网段 %s' % cidr, {'type': 'block_subnet', 'cidr': cidr}


def _clean_dropped_file(cmd):
    """进程 cmd 里若含可疑临时脚本路径, 终止后一并清理。"""
    cleaned = []
    for m in re.finditer(r'(/[^\s\'"]+\.py)', cmd or ''):
        p = m.group(1)
        if os.path.exists(p) and ('/tmp/' in p or any(b in p for b in config.KNOWN_BAD_PROCESSES)):
            try:
                os.remove(p)
                cleaned.append('删除 %s' % p)
            except Exception:
                pass
    return cleaned


def _do_kill(pid, cmd=''):
    pid = str(pid)
    _run(['kill', '-9', pid])
    cleaned = _clean_dropped_file(cmd)
    suffix = ('; ' + '; '.join(cleaned)) if cleaned else ''
    return '终止 PID %s%s' % (pid, suffix), None


def _do_kill_tree(ppid, cmd=''):
    ppid = str(ppid)
    try:
        _run(['kill', '-9', '-%s' % ppid])   # 杀进程组
    except Exception:
        _run(['kill', '-9', ppid])
    cleaned = _clean_dropped_file(cmd)
    suffix = ('; ' + '; '.join(cleaned)) if cleaned else ''
    return '终止进程树 PPID %s%s' % (ppid, suffix), None


def _do_disable_account(user):
    if not USER_RE.match(user):
        raise ActionError('非法用户名: %s' % user)
    _run(['usermod', '-L', user])
    return '锁定账户 %s' % user, {'type': 'disable_account', 'user': user}


# ============================================================
# 工具箱定义 (LLM 可调用动作的允许清单)
# ============================================================
TOOLS = {
    'quarantine_file': {
        'desc': '隔离可疑文件(移动到隔离区)',
        'params': {'path': 'str 绝对路径'},
        'destructive': False,
        'reversible': True,
        'fn': _do_quarantine,
    },
    'block_ip': {
        'desc': '阻断到某 IP 的出站连接 (iptables DROP)',
        'params': {'ip': 'IPv4'},
        'destructive': True,
        'reversible': True,
        'fn': _do_block_ip,
    },
    'block_subnet': {
        'desc': '阻断到某内网网段的出站连接, 用于处置横向移动',
        'params': {'cidr': 'CIDR 如 192.168.62.0/24'},
        'destructive': True,
        'reversible': True,
        'fn': _do_block_subnet,
    },
    'kill_process': {
        'desc': '终止指定 PID 的进程(并清理其丢弃的临时文件)',
        'params': {'pid': 'int', 'cmd': 'str(可选, 用于清理文件)'},
        'destructive': True,
        'reversible': False,
        'fn': _do_kill,
    },
    'kill_process_tree': {
        'desc': '终止整个进程树(处理提权/持久化), 用于处置横向移动',
        'params': {'ppid': 'int', 'cmd': 'str(可选)'},
        'destructive': True,
        'reversible': False,
        'fn': _do_kill_tree,
    },
    'disable_account': {
        'desc': '锁定某系统账户(处置凭证窃取/提权)',
        'params': {'user': 'str'},
        'destructive': True,
        'reversible': True,
        'fn': _do_disable_account,
    },
}


def tool_catalog_text():
    """生成给 LLM prompt 用的工具箱说明文本。"""
    lines = []
    for name, meta in TOOLS.items():
        params = ', '.join('%s:%s' % (k, v) for k, v in meta['params'].items())
        tag = ' [高危需人工确认]' if meta['destructive'] else ''
        lines.append('- %s(%s): %s%s' % (name, params, meta['desc'], tag))
    return '\n'.join(lines)


# ============================================================
# 执行器 (含护栏校验)
# ============================================================
class ActionExecutor:
    def __init__(self, bb, hitl=True, allowed=None):
        self.bb = bb
        self.hitl = hitl
        self.allowed = set(allowed) if allowed else set(TOOLS.keys())

    @staticmethod
    def _target(tool, args):
        a = args or {}
        return str(a.get('path') or a.get('ip') or a.get('cidr')
                   or a.get('pid') or a.get('ppid') or a.get('user') or '')

    def validate(self, action):
        """返回 (ok, reason)。护栏: 工具在清单内 + 参数格式合法。"""
        if not isinstance(action, dict):
            return False, '动作不是对象'
        tool = action.get('tool')
        if tool not in TOOLS:
            return False, '未知工具: %s' % tool
        if tool not in self.allowed:
            return False, '工具不在允许清单: %s' % tool
        args = action.get('args', {}) or {}
        if tool == 'quarantine_file':
            if not isinstance(args.get('path'), str) or not os.path.isabs(args.get('path', '')):
                return False, 'path 必须是绝对路径'
        elif tool == 'block_ip':
            if not IP_RE.match(str(args.get('ip', ''))):
                return False, 'ip 格式非法'
        elif tool == 'block_subnet':
            if not CIDR_RE.match(str(args.get('cidr', ''))):
                return False, 'cidr 格式非法'
        elif tool in ('kill_process', 'kill_process_tree'):
            key = args.get('pid', args.get('ppid', ''))
            if not PID_RE.match(str(key)):
                return False, 'pid/ppid 必须是数字'
        elif tool == 'disable_account':
            if not USER_RE.match(str(args.get('user', ''))):
                return False, 'user 非法'
        return True, ''

    def needs_approval(self, tool):
        """该工具是否需要人工确认 (高危且开启 HITL)。"""
        return self.hitl and TOOLS[tool]['destructive']

    def execute(self, action):
        """立即执行(已通过校验且无需审批)。返回 (ok, result_text, undo_info)。"""
        tool = action['tool']
        args = action.get('args', {}) or {}
        try:
            if tool == 'quarantine_file':
                res, undo = _do_quarantine(args['path'])
            elif tool == 'block_ip':
                res, undo = _do_block_ip(args['ip'])
            elif tool == 'block_subnet':
                res, undo = _do_block_subnet(args['cidr'])
            elif tool == 'kill_process':
                res, undo = _do_kill(args.get('pid'), args.get('cmd', ''))
            elif tool == 'kill_process_tree':
                res, undo = _do_kill_tree(args.get('ppid', args.get('pid')), args.get('cmd', ''))
            elif tool == 'disable_account':
                res, undo = _do_disable_account(args['user'])
            else:
                return False, '未知工具', None
            self.bb.add_action(tool.upper(), self._target(tool, args), res, undo=undo)
            return True, res, undo
        except ActionError as e:
            self.bb.add_action(tool.upper(), self._target(tool, args), '失败: ' + str(e))
            return False, '失败: ' + str(e), None
        except Exception as e:
            self.bb.add_action(tool.upper(), self._target(tool, args), '异常: ' + str(e))
            return False, '异常: ' + str(e), None
