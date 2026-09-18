from __future__ import annotations

import sys
from pathlib import Path
from subprocess import CompletedProcess

E5_ROOT = Path(__file__).resolve().parents[2] / "src" / "runtime" / "e5"
sys.path.insert(0, str(E5_ROOT / "routed_lab" / "resolver"))

import cache_probe  # noqa: E402
from cache_probe import parse_cache_lookup_output  # noqa: E402


def test_cache_lookup_parser_requires_exact_qname_and_a_record() -> None:
    output = """msg: reply from cache
key: r01-t000-abc.bank.com. IN A
data: 6.6.6.6
key: sub.r01-t000-abc.bank.com. IN A
data: 192.0.2.2
key: r01-t000-abc.bank.com. IN AAAA
data: 2001:db8::1
"""
    assert parse_cache_lookup_output("r01-t000-abc.bank.com.", output) == ["6.6.6.6"]


def test_cache_lookup_parser_deduplicates_rrset_and_ignores_metadata() -> None:
    output = """msg: r01-t000-abc.bank.com. 203.0.113.9
r01-t000-abc.bank.com. 300 IN A 203.0.113.9
r01-t000-abc.bank.com. 300 IN A 203.0.113.9
"""
    assert parse_cache_lookup_output("r01-t000-abc.bank.com.", output) == ["203.0.113.9"]


def test_cache_lookup_parser_accepts_key_record_with_ttl() -> None:
    output = "key: r01-t000-abc.bank.com. 300 IN A 203.0.113.9\n"
    assert parse_cache_lookup_output("r01-t000-abc.bank.com.", output) == ["203.0.113.9"]


def test_cache_lookup_parser_rejects_expired_records() -> None:
    output = """key: r01-t000-abc.bank.com. IN A
data: 203.0.113.9
ttl: 0
"""
    assert parse_cache_lookup_output("r01-t000-abc.bank.com.", output) == []


def test_cache_lookup_returns_valid_hit_and_preserves_qname(monkeypatch) -> None:
    qname = "r01-t000-abc.bank.com."

    def fake_run(command, **kwargs):
        assert command == [
            "unbound-control",
            "-c",
            "/etc/unbound/unbound.conf",
            "cache_lookup",
            qname,
        ]
        return CompletedProcess(command, 0, stdout=f"key: {qname} IN A\ndata: 203.0.113.80\n", stderr="")

    monkeypatch.setattr(cache_probe.subprocess, "run", fake_run)
    result = cache_probe.cache_lookup(qname)
    assert result["probe_status"] == "hit"
    assert result["probe_valid"] is True
    assert result["cache_hit"] is True
    assert result["answers"] == ["203.0.113.80"]
    assert result["qname"] == qname
    assert result["stdout"]
    assert result["probe_duration_ns"] >= 0


def test_cache_lookup_returns_valid_miss(monkeypatch) -> None:
    qname = "r01-t000-empty.bank.com."

    def fake_run(command, **kwargs):
        return CompletedProcess(command, 0, stdout="msg: no matching cache entry\n", stderr="")

    monkeypatch.setattr(cache_probe.subprocess, "run", fake_run)
    result = cache_probe.cache_lookup(qname)
    assert result["probe_status"] == "miss"
    assert result["probe_valid"] is True
    assert result["cache_hit"] is False
    assert result["answers"] == []


def test_cache_lookup_preserves_error_status(monkeypatch) -> None:
    qname = "r01-t000-error.bank.com."

    def fake_run(command, **kwargs):
        return CompletedProcess(command, 1, stdout="", stderr="control socket unavailable")

    monkeypatch.setattr(cache_probe.subprocess, "run", fake_run)
    result = cache_probe.cache_lookup(qname)
    assert result["probe_status"] == "error"
    assert result["probe_valid"] is False
    assert result["cache_hit"] is None
    assert result["stderr"] == "control socket unavailable"
