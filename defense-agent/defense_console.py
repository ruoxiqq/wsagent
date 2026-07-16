#!/usr/bin/env python3
"""
防御智能体控制台

交互式命令行界面，用于启动/关闭防护、查看告警和处置记录。

命令列表：
  on / start         - 开启防护模式
  off / stop         - 关闭防护模式
  toggle             - 切换防护模式
  status             - 查看当前状态
  alerts             - 查看告警列表
  actions            - 查看处置记录
  monitor            - 实时监控模式（持续刷新）
  scan               - 立即扫描一次上传目录
  clear              - 清空告警和处置记录
  exit / quit        - 退出

安全警告：此程序为安全教学演示用的防御控制台！
"""

import sys
import os
import time
import threading
import signal

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import defense_agent


class DefenseConsole:
    """防御智能体控制台"""

    def __init__(self):
        self.agent = defense_agent.DefenseAgent()
        self.agent_thread = None
        self.monitor_mode = False

    def print_banner(self):
        print("""
╔══════════════════════════════════════════════╗
║          防御智能体控制台                    ║
║          WebShell 攻防演示系统               ║
╚══════════════════════════════════════════════╝
""")
        print("命令: on | off | toggle | status | alerts | actions | monitor | scan | exit")
        print()

    def cmd_on(self):
        if not self.agent.running:
            self.agent.start()
        self.agent.activate()

    def cmd_off(self):
        self.agent.deactivate()

    def cmd_toggle(self):
        if not self.agent.running:
            self.agent.start()
        self.agent.toggle()

    def cmd_status(self):
        status = self.agent.get_status()
        print("  " + "=" * 50)
        print("  防御智能体状态:")
        print("  " + "-" * 50)
        running_text = "\033[92m运行中\033[0m" if status['running'] else "\033[91m已停止\033[0m"
        active_text = "\033[92mON (防护激活)\033[0m" if status['active'] else "\033[93mOFF (防护关闭)\033[0m"
        print("  运行状态:     {}".format(running_text))
        print("  防护模式:     {}".format(active_text))
        print("  拦截威胁数:   {}".format(status['threats_blocked']))
        print("  告警总数:     {}".format(status['alert_count']))
        print("  处置动作数:   {}".format(status['action_count']))
        print("  " + "=" * 50)

    def cmd_alerts(self):
        alerts = self.agent.get_alerts()
        if not alerts:
            print("  [!] 暂无告警")
            return
        print("  " + "=" * 60)
        print("  告警列表 (最近 {} 条):".format(len(alerts)))
        print("  " + "=" * 60)
        for a in alerts[-30:]:
            level_colors = {
                'CRITICAL': '\033[91m',
                'WARNING': '\033[93m',
                'INFO': '\033[92m'
            }
            reset = '\033[0m'
            color = level_colors.get(a['level'], '')
            print("  {}[{}] [{}] {}{}".format(
                color, a['time'], a['category'], a['message'], reset
            ))
            if a['detail']:
                print("        详情: {}".format(a['detail']))
        print("  " + "=" * 60)

    def cmd_actions(self):
        actions = self.agent.get_actions()
        if not actions:
            print("  [!] 暂无处置记录")
            return
        print("  " + "=" * 60)
        print("  处置记录 (最近 {} 条):".format(len(actions)))
        print("  " + "=" * 60)
        for a in actions[-30:]:
            print("  [{}] {} -> {}".format(a['time'], a['type'], a['target']))
            print("        结果: {}".format(a['result']))
        print("  " + "=" * 60)

    def cmd_monitor(self):
        """实时监控模式"""
        self.monitor_mode = True
        print("  [*] 实时监控模式 (按 Ctrl+C 退出)")
        print("  " + "=" * 60)
        last_alert_count = 0

        try:
            while self.monitor_mode:
                status = self.agent.get_status()
                alerts = self.agent.get_alerts()

                # 清屏效果（用回车覆盖）
                active_badge = "\033[92m[防护ON]\033[0m" if status['active'] else "\033[93m[防护OFF]\033[0m"
                running_badge = "\033[92m[运行中]\033[0m" if status['running'] else "\033[91m[已停止]\033[0m"

                print("\r  {} {} 拦截:{} 告警:{} 处置:{}    ".format(
                    running_badge, active_badge,
                    status['threats_blocked'],
                    status['alert_count'],
                    status['action_count']
                ), end='', flush=True)

                # 打印新告警
                if len(alerts) > last_alert_count:
                    new_alerts = alerts[last_alert_count:]
                    print()  # 换行
                    for a in new_alerts:
                        level_colors = {
                            'CRITICAL': '\033[91m',
                            'WARNING': '\033[93m',
                            'INFO': '\033[92m'
                        }
                        reset = '\033[0m'
                        color = level_colors.get(a['level'], '')
                        print("  {}[{}] {} | {} | {}{}".format(
                            color, a['time'], a['category'], a['message'],
                            a['detail'][:60] if a['detail'] else '', reset
                        ))
                    last_alert_count = len(alerts)

                time.sleep(0.5)
        except KeyboardInterrupt:
            self.monitor_mode = False
            print("\n  [*] 退出实时监控")

    def cmd_scan(self):
        """立即扫描上传目录"""
        print("  [*] 立即扫描上传目录: {}".format(defense_agent.UPLOAD_DIR))
        if not os.path.isdir(defense_agent.UPLOAD_DIR):
            print("  [!] 上传目录不存在")
            return

        found_threats = 0
        for item in os.listdir(defense_agent.UPLOAD_DIR):
            if item in ('.', '..', '.htaccess', 'index.html'):
                continue
            filepath = os.path.join(defense_agent.UPLOAD_DIR, item)
            if not os.path.isfile(filepath):
                continue

            is_script = item.endswith(('.php', '.py', '.phtml'))
            if is_script:
                is_malicious, matches = self.agent.scan_file(filepath)
                if is_malicious:
                    print("  \033[91m[!!!] 恶意文件: {}\033[0m".format(item))
                    print("        命中规则: {}".format(', '.join(matches)))
                    found_threats += 1
                    if self.agent.active:
                        self.agent.quarantine_file(filepath)
                elif matches:
                    print("  \033[93m[!]  可疑文件: {}\033[0m".format(item))
                    print("        命中规则: {}".format(', '.join(matches)))
                else:
                    print("  \033[92m[OK] 正常文件: {}\033[0m".format(item))
            else:
                print("  \033[92m[OK] 非脚本文件: {}\033[0m".format(item))

        print("  扫描完成，发现 {} 个威胁文件".format(found_threats))

    def cmd_clear(self):
        """清空记录"""
        with self.agent.alerts_lock:
            self.agent.alerts.clear()
        with self.agent.actions_lock:
            self.agent.actions.clear()
        self.agent.threats_blocked = 0
        print("  [+] 已清空所有告警和处置记录")

    def run(self):
        self.print_banner()

        # 启动防御智能体（默认防护关闭）
        print("  [*] 启动防御智能体...")
        self.agent.start()
        print()

        while True:
            try:
                if not self.monitor_mode:
                    active = "ON" if self.agent.active else "OFF"
                    prompt = "Defense({})> ".format(active)
                else:
                    continue

                user_input = input(prompt).strip()
                if not user_input:
                    continue

                parts = user_input.split()
                cmd = parts[0].lower()

                if cmd in ('exit', 'quit'):
                    self.agent.stop()
                    print("  [*] 再见")
                    break
                elif cmd in ('on', 'start'):
                    self.cmd_on()
                elif cmd in ('off', 'stop'):
                    self.cmd_off()
                elif cmd == 'toggle':
                    self.cmd_toggle()
                elif cmd == 'status':
                    self.cmd_status()
                elif cmd == 'alerts':
                    self.cmd_alerts()
                elif cmd == 'actions':
                    self.cmd_actions()
                elif cmd == 'monitor':
                    self.cmd_monitor()
                elif cmd == 'scan':
                    self.cmd_scan()
                elif cmd == 'clear':
                    self.cmd_clear()
                elif cmd == 'help':
                    print("  命令列表:")
                    print("    on / start   - 开启防护模式")
                    print("    off / stop   - 关闭防护模式")
                    print("    toggle       - 切换防护模式")
                    print("    status       - 查看状态")
                    print("    alerts       - 查看告警")
                    print("    actions      - 查看处置记录")
                    print("    monitor      - 实时监控")
                    print("    scan         - 立即扫描")
                    print("    clear        - 清空记录")
                    print("    exit / quit  - 退出")
                else:
                    print("  [!] 未知命令: {} (输入 help 查看)".format(cmd))

            except KeyboardInterrupt:
                if self.monitor_mode:
                    self.monitor_mode = False
                    print()
                    continue
                print()
                continue
            except EOFError:
                print()
                break
            except Exception as e:
                print("  [!] 错误: {}".format(e))


def main():
    console = DefenseConsole()

    def signal_handler(sig, frame):
        console.agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    console.run()


if __name__ == '__main__':
    main()
