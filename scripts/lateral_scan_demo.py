#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
【仅限授权教学实验】横向移动 / 内网端口扫描 演示载荷
============================================================
用途: 在已被 WebShell 控制的靶机上运行, 模拟攻击者"落地后横向移动"行为,
以便触发防御系统的"内网横向移动检测"(NetworkSensor 行为分析 -> 关联层高危事件
-> 研判层 block_subnet + kill_process_tree)。

这与 beacon.py 同属攻击侧演示载荷; 仅可在你自己的授权实验环境(本仓库 lab)中使用。

用法:
  python3 lateral_scan_demo.py                 # 扫描 192.168.62.0/24 的常见端口
  python3 lateral_scan_demo.py 192.168.62.0/24 22,445,3389,1433,3306
  python3 lateral_scan_demo.py 192.168.62.130   # 单主机多端口
"""
import sys
import socket
import threading
from itertools import product

DEFAULT_SUBNET = "192.168.62.0/24"
DEFAULT_PORTS = [22, 445, 3389, 5985, 1433, 3306, 5432, 6379, 139, 135, 80, 443, 8080]
TIMEOUT = 0.4


def parse_targets(arg):
    """解析 '10.0.0.0/24' 或 '10.0.0.5' 为目标 IP 列表。"""
    if '/' in arg:
        net, _, bits = arg.partition('/')
        a, b, c, _ = net.split('.')
        base = (int(a) << 24) | (int(b) << 16) | (int(c) << 8)
        n = int(bits)
        host_bits = 32 - n
        out = []
        for i in range(1, (1 << host_bits) - 1):
            ipint = base | i
            out.append("%d.%d.%d.%d" % ((ipint >> 24) & 255, (ipint >> 16) & 255,
                                        (ipint >> 8) & 255, ipint & 255))
        return out
    return [arg]


def scan(ip, port, results):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        s.connect((ip, port))
        results.append((ip, port, "OPEN"))
    except Exception:
        pass
    finally:
        s.close()


def main():
    subnet = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SUBNET
    ports = [int(p) for p in sys.argv[2].split(',')] if len(sys.argv) > 2 else DEFAULT_PORTS
    hosts = parse_targets(subnet)
    print("[*] 横向扫描演示: %d 主机 x %d 端口" % (len(hosts), len(ports)))
    results = []
    threads = []
    for ip, port in product(hosts, ports):
        t = threading.Thread(target=scan, args=(ip, port, results), daemon=True)
        t.start()
        threads.append(t)
        # 控制并发, 避免瞬间打满
        if len(threads) >= 200:
            for x in threads:
                x.join()
            threads = []
    for t in threads:
        t.join()
    opens = sorted(results)
    print("[+] 开放端口: %d 个" % len(opens))
    for ip, port, st in opens[:50]:
        print("    %s:%d  %s" % (ip, port, st))
    if len(opens) > 50:
        print("    ... (其余 %d 个省略)" % (len(opens) - 50))


if __name__ == '__main__':
    main()
