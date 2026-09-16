"""Unbound Python-module logger for resolver-level evidence.

Unbound injects ``log_info``, ``log_err``, and the MODULE_* constants into
Python-module globals when it loads this file; they are intentionally not
ordinary Python imports.
"""

# ruff: noqa: F821

import json
import os
import time


LOG = os.environ.get("UNBOUND_EVENT_LOG", "/app/log/unbound_events.jsonl")


def _append(row):
    with open(LOG, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")


def init(id, cfg):
    log_info("e5-v2 e5mod: init id=%d port=%d" % (id, cfg.port))
    return True


def init_standard(id, env):
    log_info("e5-v2 e5mod: init_standard id=%d port=%d" % (id, env.cfg.port))
    return True


def deinit(id):
    log_info("e5-v2 e5mod: deinit id=%d" % id)
    return True


def inform_super(id, qstate, superqstate, qdata):
    return True


def operate(id, event, qstate, qdata):
    if event == MODULE_EVENT_NEW or event == MODULE_EVENT_PASS:
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True
    if event == MODULE_EVENT_MODDONE:
        qname = qstate.qinfo.qname_str if qstate.qinfo else ""
        rcode = -1
        if qstate.return_msg and qstate.return_msg.rep:
            rcode = int(qstate.return_msg.rep.flags) & 0xF
        _append(
            {
                "schema_version": 1,
                "event": "resolver_response",
                "run_id": os.environ.get("RUN_ID", "unregistered"),
                "rep": int(os.environ.get("REP", "0")),
                "policy": os.environ.get("POLICY_MODE", "unregistered"),
                "workload": os.environ.get("WORKLOAD", "unregistered"),
                "mono_ns": time.monotonic_ns(),
                "wall_ns": time.time_ns(),
                "qname": qname,
                "trial_id": qname.rstrip(".").split(".", 1)[0] if qname else None,
                "rcode": rcode,
            }
        )
        qstate.ext_state[id] = MODULE_FINISHED
        return True
    log_err("e5-v2 e5mod: unexpected event")
    qstate.ext_state[id] = MODULE_ERROR
    return True


log_info("e5-v2 e5mod: script loaded")
