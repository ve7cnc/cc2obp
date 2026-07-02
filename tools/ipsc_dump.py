#!/usr/bin/env python3
"""ipsc_dump.py — decode IPSC GROUP_VOICE frames from a pcap and show the call
STRUCTURE (burst sequence, headers, embedded-LC markers), so we can diff a
known-good IPSC call against the one the c-Bridge synthesizes for a reverse
(OBP->CC->IPSC) call.  ipsc2hbp is a peer on the same IPSC system, so the
c-Bridge's injected frames are visible on its bind port (udp 50013).

Field offsets are ipsc2hbpc's (ipsc_const.h): opcode[0]=0x80 GROUP_VOICE,
src[6:9], dst[9:12], call_info[17], rtp_ts[22:26], burst_type[30]
(0x01 HEAD / 0x02 TERM / 0x0A TS1-voice / 0x8A TS2-voice), sub-header[31:33]
(0x14/0x40 pos0-sync, 0x22/0x16 burstE, 0x19/0x06 other), AMBE[33:52].

Usage: ipsc_dump.py capture.pcap [src_ip]     (src_ip: only that IPSC source)
"""
import struct, sys
from collections import defaultdict

def read_pcap(path):
    data = open(path, "rb").read()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        end = ">" if magic == b"\xa1\xb2\xc3\xd4" else "<"; nano = False
    elif magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        end = ">" if magic == b"\xa1\xb2\x3c\x4d" else "<"; nano = True
    else: sys.exit("not a classic pcap")
    lt = struct.unpack(end + "I", data[20:24])[0]
    off, pkts = 24, []
    while off + 16 <= len(data):
        s, f, caplen, _ = struct.unpack(end + "IIII", data[off:off+16]); off += 16
        pkts.append((s + f/(1e9 if nano else 1e6), data[off:off+caplen])); off += caplen
    return lt, pkts

def l2(lt, p):
    if lt == 1:
        return (p[18:], struct.unpack(">H", p[16:18])[0]) if p[12:14]==b"\x81\x00" else (p[14:], struct.unpack(">H", p[12:14])[0])
    if lt == 101: return p, 0x0800
    if lt == 113: return p[16:], struct.unpack(">H", p[14:16])[0]
    if lt == 276: return p[20:], struct.unpack(">H", p[0:2])[0]
    return p, 0x0800

def udp(lt, p):
    pl, eth = l2(lt, p)
    if eth != 0x0800 or len(pl) < 20 or pl[9] != 17: return None
    ihl = (pl[0] & 0xF)*4
    sip = ".".join(str(b) for b in pl[12:16])
    u = pl[ihl:]
    if len(u) < 8: return None
    return sip, u[8:]

def b24(d, o): return (d[o]<<16)|(d[o+1]<<8)|d[o+2]
BT = {0x01:"HEAD", 0x02:"TERM", 0x0A:"V-ts1", 0x8A:"V-ts2"}
def sub(d):
    if len(d) < 33: return "?"
    a, b = d[31], d[32]
    return {(0x14,0x40):"pos0/sync", (0x22,0x16):"burstE", (0x19,0x06):"voice"}.get((a,b), f"{a:02x}/{b:02x}")

def main():
    if len(sys.argv) < 2: sys.exit("usage: ipsc_dump.py capture.pcap [src_ip]")
    only = sys.argv[2] if len(sys.argv) >= 3 else None
    lt, pkts = read_pcap(sys.argv[1])
    bysrc = defaultdict(list)
    for t, raw in pkts:
        u = udp(lt, raw)
        if not u: continue
        sip, d = u
        if len(d) < 31 or d[0] != 0x80: continue          # GROUP_VOICE only
        if only and sip != only: continue
        bysrc[sip].append((t, d))

    if not bysrc: sys.exit("no IPSC GROUP_VOICE frames found (check port 50013 / src_ip)")
    print("IPSC GROUP_VOICE sources:", {k: len(v) for k, v in bysrc.items()})
    for sip, frames in bysrc.items():
        print(f"\n================ source {sip}  ({len(frames)} frames) ================")
        seq = []
        first_head = first_voice = None
        for t, d in frames:
            bt = d[30] if len(d) > 30 else -1
            name = BT.get(bt, f"0x{bt:02x}")
            seq.append(name if bt in (0x01,0x02) else sub(d))
            if bt in (0x01,0x02) and first_head is None: first_head = d
            if bt in (0x0A,0x8A) and first_voice is None: first_voice = d
        # compact burst-sequence
        print("burst sequence:")
        line = " ".join(seq)
        print("  " + (line if len(line) < 220 else line[:220] + " …"))
        if frames:
            d0 = frames[0][1]
            print(f"first frame: len={len(d0)} src_rid={b24(d0,6)} dst={b24(d0,9)} call_info=0x{d0[17]:02x} burst=0x{d0[30]:02x}")
        def hexrow(label, d):
            if d is None: print(f"  {label}: (none)"); return
            print(f"  {label}: hdr[0:34]={d[:34].hex()}")
            if len(d) >= 52: print(f"           ambe[33:52]={d[33:52].hex()}")
        print("structural samples:")
        hexrow("VOICE_HEAD ", first_head)
        hexrow("first voice", first_voice)

if __name__ == "__main__":
    main()
