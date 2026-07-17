#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
事件总线 (Event Bus / 共享黑板)

多智能体协作的神经中枢：按 topic 发布/订阅，线程安全。
每个 Agent 持有自己的队列，订阅感兴趣的 topic，在自己的线程里消费，
互不阻塞——这就是"协作"而非"单体"的关键。

Topic 约定:
  raw.file   - 文件感知事件
  raw.net    - 网络感知事件
  raw.proc   - 进程感知事件
  incident   - 关联层产出的攻击事件
  verdict    - 研判大脑产出的判定结果
  action     - 响应处置层产出的处置记录
  feedback   - 取证层/人工的误报反馈
"""

import queue
import threading
from collections import defaultdict


class EventBus:
    def __init__(self):
        self._subs = defaultdict(list)  # topic -> [Queue, ...]
        self._lock = threading.Lock()

    def subscribe(self, *topics):
        """
        订阅一个或多个 topic，返回一个共享队列。
        Agent 在自己的线程里 queue.get() 消费。
        """
        q = queue.Queue()
        with self._lock:
            for t in topics:
                self._subs[t].append(q)
        return q

    def publish(self, topic, event):
        """向某 topic 的所有订阅者投递事件(非阻塞)。"""
        with self._lock:
            subs = list(self._subs[topic])
        for q in subs:
            q.put(event)
