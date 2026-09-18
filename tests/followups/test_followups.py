import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src/followups"))

import struct

import pytest

from analyze_followups import Fragment, OrphanWindow, W, naive_snapshot, parse_ethernet, rescore, record_order_max_ratio

KEY = ("10.82.0.100", "10.81.0.53", 17, 42)


def test_tail_before_head_is_orphan_until_head_arrives():
    window = OrphanWindow()
    tail=Fragment(100,KEY,40,False)
    window.observe(tail)
    assert window.snapshot(101)["orphan_count"]==1
    window.observe(Fragment(102,KEY,0,True))
    assert window.snapshot(103)["orphan_count"]==0
    assert naive_snapshot([tail,Fragment(102,KEY,0,True)],101)==(1,1)


@pytest.mark.parametrize("component,replacement",[(0,"10.82.0.200"),(1,"10.81.0.99"),(2,6),(3,43)])
def test_matching_uses_complete_datagram_key(component,replacement):
    wrong=list(KEY);wrong[component]=replacement
    window=OrphanWindow();window.observe(Fragment(1,tuple(wrong),0,True))
    window.observe(Fragment(2,KEY,40,False))
    assert window.snapshot(3)["orphan_count"]==1


def test_head_expiry_does_not_revoke_a_real_match():
    window=OrphanWindow();window.observe(Fragment(10,KEY,0,True))
    window.observe(Fragment(20,KEY,40,False))
    assert window.snapshot(W+11)["orphan_count"]==0
    assert window.snapshot(W+20)["samples"]==1
    assert window.snapshot(W+21)["samples"]==0


def test_stale_head_and_unfragmented_packet_do_not_match_tail():
    window=OrphanWindow();window.observe(Fragment(1,KEY,0,True))
    window.observe(Fragment(W+2,KEY,40,False))
    window.observe(Fragment(W+3,KEY,0,False))
    assert window.snapshot(W+3)["orphan_count"]==1


def test_majority_equality_any_positive_and_minimum_volume():
    window=OrphanWindow()
    for i in range(7):window.observe(Fragment(i,KEY,40,False))
    assert not window.snapshot(7)["orphan_any"]
    # Four matched tails and four unmatched tails: majority threshold equality.
    window=OrphanWindow();window.observe(Fragment(0,KEY,0,True))
    for i in range(8):
        key=KEY if i<4 else (*KEY[:3],100+i)
        window.observe(Fragment(10+i,key,40,False))
    result=window.snapshot(18)
    assert result["orphan_ratio"]==.5 and result["orphan_majority"] and result["orphan_any"]


def test_no_future_head_leakage_and_retained_duplicate_observations():
    tail=Fragment(20,KEY,40,False);future=Fragment(40,KEY,0,True)
    assert naive_snapshot([tail,tail,future],30)==(2,2)
    assert naive_snapshot([tail,tail,future],40)==(2,0)


def test_ipv4_offset_parser_and_truncation():
    ethernet=bytes(12)+b'\x08\x00'
    header=struct.pack('!BBHHHBBH4s4s',0x45,0,28,42,0x2000,64,17,0,bytes([10,82,0,100]),bytes([10,81,0,53]))
    parsed=parse_ethernet(ethernet+header+b'12345678',100)
    assert parsed.offset==0 and parsed.more and parsed.key==KEY
    broken=ethernet+header+b'12'
    with pytest.raises(ValueError,match="Truncated IPv4"):parse_ethernet(broken,100)
    with pytest.raises(ValueError,match="linktype"):parse_ethernet(ethernet,100,101)


def test_locked_gate_requires_entropy_not_just_count_and_uniqueness():
    arrival=[i/10000 for i in range(70)]
    # 63 distinct IDs / 70 packets passes U=.9, but H < 6.
    payload=[('benign',i) for i in range(63)]+[('benign',0)]*7
    row=rescore(arrival,payload,[1.])[0]
    assert row['samples']==70 and row['unique_ratio']==.9 and row['entropy']<6
    assert not row['B5_locked']


def test_record_order_diagnostic_does_not_reorder_future_heads():
    tail=Fragment(200,KEY,40,False);head=Fragment(100,KEY,0,True)
    assert record_order_max_ratio([tail,head])==1
    assert record_order_max_ratio([head,tail])==0
