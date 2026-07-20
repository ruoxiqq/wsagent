#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多智能体防御系统 - 集中配置

所有可调参数集中在此。支持环境变量覆盖，便于不改代码切换 LLM 后端。
教学提示：LLM 后端可在 Ollama(本地) 与 云API 之间切换，详见 start-llm-brain.bat。
"""

import os
import ipaddress


def _env(key, default):
    return os.environ.get(key, default)


def ip_in_cidrs(ip, cidrs):
    """判断 ip 是否落在任一 cidr 内(用于内网横向移动识别)。"""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in cidrs:
        try:
            if addr in ipaddress.ip_network(c, strict=False):
                return True
        except ValueError:
            continue
    return False


# ========== LLM 大脑配置 ==========
# 后端选择: ollama | cloud | disabled
#   ollama  : 本地 Ollama (推荐教学，无需外网)，Windows 宿主机运行，CentOS 跨网调用
#   cloud   : OpenAI 兼容云 API (DeepSeek / Qwen / OpenAI 等)，需联网与 API Key
#   disabled: 关闭 LLM，研判 Agent 自动降级为规则评分 (演示兜底)
LLM_BACKEND = _env('DEFENSE_LLM_BACKEND', 'cloud')

# --- Ollama (本地) ---
# Windows 宿主机 IP，Ollama 默认 11434。start-llm-brain.bat 会设 OLLAMA_HOST=0.0.0.0
OLLAMA_URL = _env('OLLAMA_URL', 'http://192.168.163.1:11434')
OLLAMA_MODEL = _env('OLLAMA_MODEL', 'qwen2.5:7b')

# --- 云 API (OpenAI 兼容) ---
# 以 DeepSeek 为例: https://api.deepseek.com ; model: deepseek-chat
# 以 Qwen 为例:    https://dashscope.aliyuncs.com/compatible-mode/v1 ; model: qwen-plus
CLOUD_API_URL = _env('CLOUD_API_URL', 'https://api.siliconflow.cn/v1')
CLOUD_API_KEY = _env('CLOUD_API_KEY', 'sk-lcjrjprepquqmqvgeltsikjywkqenyborrhaivxtbjmhpkaq')
CLOUD_MODEL = _env('CLOUD_MODEL', 'deepseek-ai/DeepSeek-V3.2')

# LLM 调用超时(秒)。本地小模型在 CPU 上较慢，建议 60s
LLM_TIMEOUT = int(_env('DEFENSE_LLM_TIMEOUT', '60'))
# LLM 失败后降级为规则评分，不再重试的冷却时间(秒)
LLM_COOLDOWN = int(_env('DEFENSE_LLM_COOLDOWN', '30'))


# ========== 监控目标配置 ==========
UPLOAD_DIR = _env('DEFENSE_UPLOAD_DIR', '/var/www/vulnerable/uploads/')
QUARANTINE_DIR = _env('DEFENSE_QUARANTINE_DIR', '/tmp/quarantine')
C2_PORT = int(_env('DEFENSE_C2_PORT', '8888'))
C2_HOST_IP = _env('DEFENSE_C2_HOST_IP', '192.168.163.1')  # Windows 宿主机 C2 IP
WEB_SERVER_USER = _env('DEFENSE_WEB_USER', 'apache')

# 已知恶意进程特征路径
KNOWN_BAD_PROCESSES = [
    '/tmp/.system_update.py',   # WebShell 部署的 Beacon
    'beacon.py',                # 独立 Beacon
]

# ========== 内网横向移动检测配置 ==========
# 需要监控"内网靶机网段"(被控主机向这些网段发起的扫描/连接视为横向移动嫌疑)。
# 本实验室 CentOS 靶机为 192.168.62.128, 内网靶机网段为 192.168.62.0/24。
INTERNAL_SUBNETS = [_s.strip() for _s in
                    _env('DEFENSE_INTERNAL_SUBNETS', '192.168.62.0/24').split(',') if _s.strip()]

# 敏感内网端口: 命中即强烈暗示横向移动(提权/凭证窃取/服务利用)
SENSITIVE_PORTS = [int(_x) for _x in
                   _env('DEFENSE_SENSITIVE_PORTS',
                        '445,139,135,22,3389,5985,5986,1433,3306,5432,6379')
                   .split(',') if _x.strip()]

# 行为阈值: 同一进程在时间窗内连到多少个不同内网 IP / 不同端口, 判定为横向移动
LATERAL_DISTINCT_IPS = int(_env('DEFENSE_LATERAL_IPS', '3'))
LATERAL_DISTINCT_PORTS = int(_env('DEFENSE_LATERAL_PORTS', '5'))
# 行为观察滑动窗口(秒): 窗口内聚合同一进程的内网连接
NET_WINDOW = int(_env('DEFENSE_NET_WINDOW', '20'))

# ========== 关联引擎配置 ==========
# 滑动时间窗(秒)：窗内多源信号聚类成一个 incident
CORRELATION_WINDOW = int(_env('DEFENSE_CORR_WINDOW', '30'))
# 单信号高危也直接产生 incident (不一定要多源)
SINGLE_SIGNAL_HIGH_RISK = True

# ========== 响应分级阈值 (基于置信度/评分 0-100) ==========
TIER_ALERT = int(_env('DEFENSE_TIER_ALERT', '40'))      # <40 仅告警
TIER_ISOLATE = int(_env('DEFENSE_TIER_ISOLATE', '60'))  # 40-69 隔离文件
TIER_BLOCK = int(_env('DEFENSE_TIER_BLOCK', '80'))      # 70-84 +阻断网络
# >=85 终止进程 + 删除文件

# ========== 人工确认 (Human-in-the-Loop) ==========
# 高危动作(kill/block/disable_account)是否需要人工确认后执行。
# 教学演示默认 false(自动执行, 便于观察完整响应); 设为 true 开启人工确认,
# 待审批动作在控制台用 approve <ID> / approve all 执行。
HITL_DESTRUCTIVE = _env('DEFENSE_HITL', 'false').lower() in ('1', 'true', 'yes', 'y')

# ========== 采样间隔(秒) ==========
INTERVAL_FILE = float(_env('DEFENSE_IV_FILE', '1'))
INTERVAL_NET = float(_env('DEFENSE_IV_NET', '2'))
INTERVAL_PROC = float(_env('DEFENSE_IV_PROC', '3'))


# ========== WebShell 特征规则 (感知层复用) ==========
WEBSHELL_PATTERNS = [
    (r'eval\s*\(', 'eval() 函数调用'),
    (r'assert\s*\(', 'assert() 函数调用'),
    (r'system\s*\(', 'system() 命令执行'),
    (r'exec\s*\(', 'exec() 命令执行'),
    (r'shell_exec\s*\(', 'shell_exec() 命令执行'),
    (r'passthru\s*\(', 'passthru() 命令执行'),
    (r'proc_open\s*\(', 'proc_open() 进程操作'),
    (r'popen\s*\(', 'popen() 进程操作'),
    (r'base64_decode\s*\(', 'base64 解码(常见混淆)'),
    (r'str_rot13\s*\(', 'str_rot13(混淆)'),
    (r'gzinflate\s*\(', 'gzinflate(压缩混淆)'),
    (r'str_replace\s*\(.*chr\s*\(', 'chr+str_replace 混淆'),
    (r'\$_(POST|GET|REQUEST|COOKIE)\s*\[', '用户输入直接作为命令'),
    (r'preg_replace\s*\(.*\/e', 'preg_replace /e 修饰符执行'),
    (r'create_function\s*\(', 'create_function() 动态函数'),
    (r'call_user_func\s*\(', 'call_user_func() 动态调用'),
    (r'fsockopen\s*\(', 'fsockopen 网络连接'),
    (r'socket_create\s*\(', 'socket_create 网络连接'),
    (r'file_put_contents\s*\(.*\$_(POST|GET)', '用户输入写入文件'),
    (r'move_uploaded_file', '文件上传处理'),
    (r'nohup\s+python', '后台执行 Python(Beacon 部署特征)'),
    (r'struct\.unpack', '二进制数据处理(键盘记录特征)'),
    (r'/dev/input/event', '键盘设备读取(键盘记录特征)'),
    (r'keylog', '键盘记录关键词'),
    (r'socket\.connect', 'Socket 连接(C2 通信特征)'),
]

SUSPICIOUS_PROCESS_PATTERNS = [
    (r'/tmp/\.\w+\.py', '隐藏 Python 脚本(临时目录)'),
    (r'beacon\.py', 'Beacon 后门程序'),
    (r'/dev/input/event', '读取键盘设备的进程'),
    (r'keylog', '键盘记录进程'),
]

SUSPICIOUS_PORTS = [8888, 1337, 31337, 9999, 5555]
