#!/usr/bin/env python3
"""ambe_convention_diff.py — derive the c-Bridge CC-CC vs IPSC 49-bit AMBE transform.

Feed it a pcap that captured ONE call on both UDP 42422 (CC-CC, from the
c-Bridge to cc2obp) and the IPSC voice (GROUP_VOICE, from the repeater). It:

  * pulls the 49-bit AMBE frames out of each side (CC-CC 7-byte units; IPSC
    19-byte block at payload offset 33, frames at bit 0/50/100),
  * picks ONE IPSC source as the known-good reference (the repeater = Form A),
  * drops silence/idle (all-zero) frames,
  * SEARCHES the relative frame offset between the two streams (they start at
    different points), and at each offset tests whether c-Bridge (Form B) maps
    to IPSC (Form A) by a fixed bit PERMUTATION and/or a fixed XOR mask — the
    two conventions that produce "metadata perfect, audio garbled".

Usage: ambe_convention_diff.py capture.pcap [ipsc_source_ip]
No dependencies. Handles pcap linktypes EN10MB, RAW, and Linux SLL/SLL2.
"""
import struct, sys
from collections import Counter

def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        end = ">" if magic == b"\xa1\xb2\xc3\xd4" else "<"
        nano = False
    elif magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        end = ">" if magic == b"\xa1\xb2\x3c\x4d" else "<"
        nano = True
    else:
        sys.exit("not a classic pcap (capture with tcpdump -w, not pcapng)")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off, pkts = 24, []
    while off + 16 <= len(data):
        _s, _f, caplen, _ = struct.unpack(end + "IIII", data[off:off+16])
        off += 16
        pkts.append(data[off:off+caplen])
        off += caplen
    return linktype, pkts

def l2_strip(linktype, p):
    if linktype == 1:            # EN10MB
        if p[12:14] == b"\x81\x00": return p[18:], struct.unpack(">H", p[16:18])[0]
        return p[14:], struct.unpack(">H", p[12:14])[0]
    if linktype == 101: return p, 0x0800                       # RAW
    if linktype == 113: return p[16:], struct.unpack(">H", p[14:16])[0]   # LINUX_SLL
    if linktype == 276: return p[20:], struct.unpack(">H", p[0:2])[0]     # LINUX_SLL2
    return p, 0x0800

def udp_of(linktype, p):
    payload, eth = l2_strip(linktype, p)
    if eth != 0x0800 or len(payload) < 20 or payload[9] != 17: return None
    ihl = (payload[0] & 0xF) * 4
    sip = ".".join(str(b) for b in payload[12:16])
    dip = ".".join(str(b) for b in payload[16:20])
    u = payload[ihl:]
    if len(u) < 8: return None
    sport, dport, _ = struct.unpack(">HHH", u[:6])
    return sip, dip, sport, dport, u[8:]

def bytes_to_bits(b):           # MSB-first, matches dmr_bytes_to_bits
    return [(byte >> (7 - i)) & 1 for byte in b for i in range(8)]

def cccc_frames(pl):            # 21-byte payload -> 3 x 49 bits
    return [bytes_to_bits(pl[i*7:i*7+6]) + [1 if pl[i*7+6] & 0x80 else 0] for i in range(3)]

def ipsc_frames(a19):           # 19-byte block -> 3 x 49 bits at 0/50/100
    bits = bytes_to_bits(a19)
    return [bits[0:49], bits[50:99], bits[100:149]]

VOICE_HEAD, VOICE_TERM = 0x01, 0x02

def collect(linktype, pkts):
    """cc = [49-bit frames]; ip = {src_ip: [49-bit frames]} (classify by content)."""
    cc, ip = [], {}
    for p in pkts:
        u = udp_of(linktype, p)
        if not u: continue
        sip, dip, sport, dport, pl = u
        if len(pl) == 33 and (pl[1] & 0x7f) == 94:                 # CC-CC RTP voice
            cc.extend(cccc_frames(pl[12:]))
        elif len(pl) >= 52 and pl[0] == 0x80 and pl[30] not in (VOICE_HEAD, VOICE_TERM):
            ip.setdefault(sip, []).extend(ipsc_frames(pl[33:52]))  # IPSC GROUP_VOICE
    return cc, ip

def nonsilence(frames):
    return [f for f in frames if any(f)]        # drop all-zero idle/silence

def try_permutation(A, B):
    """perm[j]=i means B[j]==A[i] for every pair, or None."""
    cand = [set(range(49)) for _ in range(49)]
    for a, b in zip(A, B):
        for j in range(49):
            cand[j] &= {i for i in range(49) if a[i] == b[j]}
    perm = []
    for j in range(49):
        if len(cand[j]) != 1: return None
        perm.append(next(iter(cand[j])))
    return perm

def try_xor(A, B):
    mask = [A[0][i] ^ B[0][i] for i in range(49)]
    for a, b in zip(A, B):
        if [a[i] ^ b[i] for i in range(49)] != mask: return None
    return mask

def evaluate(A, B):
    """Try every relative offset; return (offset, perm, xor) for the first that
    yields a consistent transform over a healthy overlap."""
    best = None
    for off in range(-len(B) + 8, len(A) - 8):
        a = A[max(0, off):]
        b = B[max(0, -off):]
        n = min(len(a), len(b))
        if n < 8: continue
        a, b = a[:n], b[:n]
        perm = try_permutation(a, b)
        xor  = try_xor(a, b)
        if perm or xor:
            return off, n, perm, xor
    return best

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: ambe_convention_diff.py capture.pcap [ipsc_source_ip]")
    lt, pkts = read_pcap(sys.argv[1])
    cc, ipbysrc = collect(lt, pkts)
    print(f"linktype={lt} packets={len(pkts)} CC-CC frames={len(cc)}")
    print("IPSC frames by source:", {k: len(v) for k, v in ipbysrc.items()} or "none")
    if not cc:
        sys.exit("no CC-CC (Form B) frames — is the c-Bridge sending CC-CC voice to cc2obp?")
    if not ipbysrc:
        sys.exit("no IPSC (Form A) frames — is a repeater sending IPSC voice here?")

    if len(sys.argv) >= 3 and sys.argv[2] in ipbysrc:
        src = sys.argv[2]
    else:
        src = max(ipbysrc, key=lambda k: len(ipbysrc[k]))
    print(f"using IPSC source {src} as Form A ({len(ipbysrc[src])} frames)")

    A = nonsilence(ipbysrc[src])    # Form A = known-good dmr_utils3 convention
    B = nonsilence(cc)              # Form B = c-Bridge CC-CC convention
    print(f"non-silence frames: Form A={len(A)}  Form B={len(B)}")
    if len(A) < 8 or len(B) < 8:
        sys.exit("too few non-silence frames on one side to align — capture a longer/steadier keyup")

    res = evaluate(A, B)
    print("\n== RESULT ==")
    if not res:
        print("no fixed permutation or XOR at any alignment offset.")
        print("=> not a bit-order/XOR difference; likely a C1-scramble/FEC-domain")
        print("   difference. Next: test with the demodulate (C1 descramble) variants.")
        return
    off, n, perm, xor = res
    print(f"aligned at frame offset {off} over {n} frame pairs")
    if xor:
        print("pure XOR mask (B = A xor mask):", "".join(map(str, xor)))
    if perm:
        if perm == list(range(49)):
            print("bit permutation: IDENTITY — Form A and Form B are the SAME 49 bits;")
            print("  the garble is NOT a 49-bit convention diff. Look upstream (packing/timeslot).")
        else:
            print("bit permutation B[j] = A[perm[j]]:")
            print(" ", perm)
            print("  -> apply the inverse of this permutation in cccc_ambe pack21/unpack21.")

if __name__ == "__main__":
    main()
