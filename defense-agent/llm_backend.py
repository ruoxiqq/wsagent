#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LLM 后端抽象层

统一 chat(messages) 接口，底层可在 Ollama(本地) 与 OpenAI 兼容云 API 之间切换。
仅用标准库 urllib，无额外依赖，CentOS 7 自带 Python3 即可运行。

教学要点：这一层是"智能体"的智能来源。研判 Agent 通过它让 LLM 对安全事件
做推理(ReAct)，从而具备规则引擎没有的"面对未知攻击也能判断"的能力。
"""

import json
import os
import time
import urllib.request
import urllib.error

import config


# ========== 调用日志（落盘，便于判断"是否真的调了 LLM API"） ==========
LOG_FILE = os.environ.get('DEFENSE_LOG_FILE', '/var/log/defense-llm.log')


def _log(msg):
    """写一行带时间戳的日志到 LOG_FILE，失败静默（不阻塞主流程）。"""
    try:
        ts = time.strftime('%Y-%m-%d %H:%M:%S')
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write('[%s] %s\n' % (ts, msg))
    except Exception:
        pass


class LLMBackend:
    """LLM 后端：Ollama 或 云API，统一 chat 接口。"""

    def __init__(self, backend=None):
        self.backend = backend or config.LLM_BACKEND
        self.timeout = config.LLM_TIMEOUT
        # 失败冷却：连续失败后短时间内不再调用，直接降级
        self._last_fail = 0.0
        self._fail_count = 0

    # ---- 对外主接口 ----
    def chat(self, system_prompt, user_prompt):
        """
        发送一轮对话，返回模型文本回复。
        失败返回 None (调用方应降级为规则评分)。
        """
        if self.backend == 'disabled':
            _log('LLM CALL SKIP backend=disabled')
            return None
        if not self._ready():
            _log('LLM CALL SKIP backend=%s cooldown active (fail_count=%d)'
                 % (self.backend, self._fail_count))
            return None

        model = config.OLLAMA_MODEL if self.backend == 'ollama' else config.CLOUD_MODEL
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        t0 = time.time()
        try:
            if self.backend == 'ollama':
                text = self._call_ollama(messages)
            else:
                text = self._call_cloud(messages)
            dt = (time.time() - t0) * 1000
            self._fail_count = 0
            _log('LLM CALL OK  backend=%s model=%s latency=%.0fms resp_len=%d'
                 % (self.backend, model, dt, len(text)))
            return text
        except Exception as e:
            dt = (time.time() - t0) * 1000
            self._mark_fail()
            _log('LLM CALL FAIL backend=%s model=%s latency=%.0fms error=%s'
                 % (self.backend, model, dt, e))
            return None

    def is_available(self):
        """是否可用(未被冷却且未禁用)。不主动发请求，仅看状态。"""
        return self.backend != 'disabled' and self._ready()

    # ---- 内部 ----
    def _ready(self):
        if self._fail_count >= 3 and (time.time() - self._last_fail) < config.LLM_COOLDOWN:
            return False
        return True

    def _mark_fail(self):
        self._fail_count += 1
        self._last_fail = time.time()

    def _call_ollama(self, messages):
        url = config.OLLAMA_URL.rstrip('/') + '/api/chat'
        payload = {
            "model": config.OLLAMA_MODEL,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.2},
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url, data=data, headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode('utf-8'))
        return body.get("message", {}).get("content", "")

    def _call_cloud(self, messages):
        if not config.CLOUD_API_KEY:
            raise RuntimeError("CLOUD_API_KEY 未设置")
        url = config.CLOUD_API_URL.rstrip('/') + '/chat/completions'
        payload = {
            "model": config.CLOUD_MODEL,
            "messages": messages,
            "temperature": 0.2,
            "stream": False,
        }
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(
            url, data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": "Bearer " + config.CLOUD_API_KEY,
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            body = json.loads(resp.read().decode('utf-8'))
        choices = body.get("choices", [])
        if not choices:
            return ""
        return choices[0].get("message", {}).get("content", "")


# 模块级单例，供各 Agent 共享
llm = LLMBackend()
