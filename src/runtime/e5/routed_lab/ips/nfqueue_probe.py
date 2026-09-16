#!/usr/bin/env python3
"""Bind and release the registered NFQUEUE as a kernel capability probe."""

from __future__ import annotations

import os

from netfilterqueue import NetfilterQueue


queue_num = int(os.environ.get("NFQUEUE_NUM", "5"))
queue = NetfilterQueue()
queue.bind(queue_num, lambda packet: packet.accept())
queue.unbind()
print(f"NFQUEUE_BIND_OK queue={queue_num}", flush=True)
