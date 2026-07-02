#!/usr/bin/env python3
"""cc2obp_send_check.py — validate the CC-CC stream cc2obp SENDS to the c-Bridge
(reverse direction, OBP->CC).  No second path needed, so no loop: capture ONE
OBP-origin (UHF-radio) keyup on the cc2obp host and diff its outbound CC-CC
against the known-good cadence a real c-Bridge uses (per dmr/voice.log and the
c-Bridge author's own spec: RTP seq +1 and timestamp +480 every packet, marker
only on the first packet of a talkspurt, 21-byte payloads, one B-on then one
B-off).

Reverse symptom being chased: the c-Bridge shows correct metadata and the
repeater keys, but the subscriber decodes NOTHING (not even in promiscuous
monitor) => the OTA superframe the c-Bridge synthesizes is malformed at the
sync/LC level, which points at a STRUCTURAL defect in what cc2obp feeds it, not
at the AMBE bits (an AMBE-only bug would give a decodable call with bad audio).

Capture (cc2obp host, one keyup):
  sudo tcpdump -i any -w /tmp/rev.pcap 'tcp port 42421 or udp port 42422'
Run:
  cc2obp_send_check.py /tmp/rev.pcap [cbridge_ip]

No dependencies. Handles pcap linktypes EN10MB, RAW, and Linux SLL/SLL2.
"""
import struct, sys
from collections import defaultdict

# ---- pcap / L2 / L3 (shared shape with ambe_convention_diff.py) ----
def read_pcap(path):
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1"):
        end = ">" if magic == b"\xa1\xb2\xc3\xd4" else "<"; nano = False
    elif magic in (b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1"):
        end = ">" if magic == b"\xa1\xb2\x3c\x4d" else "<"; nano = True
    else:
        sys.exit("not a classic pcap (capture with tcpdump -w, not pcapng)")
    linktype = struct.unpack(end + "I", data[20:24])[0]
    off, pkts = 24, []
    while off + 16 <= len(data):
        ts_s, ts_f, caplen, _ = struct.unpack(end + "IIII", data[off:off+16]); off += 16
        t = ts_s + ts_f / (1e9 if nano else 1e6)
        pkts.append((t, data[off:off+caplen])); off += caplen
    return linktype, pkts

def l2_strip(linktype, p):
    if linktype == 1:
        if p[12:14] == b"\x81\x00": return p[18:], struct.unpack(">H", p[16:18])[0]
        return p[14:], struct.unpack(">H", p[12:14])[0]
    if linktype == 101: return p, 0x0800
    if linktype == 113: return p[16:], struct.unpack(">H", p[14:16])[0]
    if linktype == 276: return p[20:], struct.unpack(">H", p[0:2])[0]
    return p, 0x0800

def l4(linktype, p):
    """-> (proto, sip, dip, sport, dport, payload) or None. proto: 6=TCP 17=UDP."""
    payload, eth = l2_strip(linktype, p)
    if eth != 0x0800 or len(payload) < 20: return None
    proto = payload[9]
    if proto not in (6, 17): return None
    ihl = (payload[0] & 0xF) * 4
    sip = ".".join(str(b) for b in payload[12:16])
    dip = ".".join(str(b) for b in payload[16:20])
    seg = payload[ihl:]
    if proto == 17:
        if len(seg) < 8: return None
        sport, dport = struct.unpack(">HH", seg[:4]); data = seg[8:]
    else:  # TCP
        if len(seg) < 20: return None
        sport, dport = struct.unpack(">HH", seg[:4]); doff = (seg[12] >> 4) * 4; data = seg[doff:]
    return proto, sip, dip, sport, dport, data

PT_VOICE_MASK = 0x7f
PT_VOICE = 94  # cc2obp CCCC_RTP_PT_VOICE; confirm if your build differs

def main():
    if len(sys.argv) < 2:
        sys.exit("usage: cc2obp_send_check.py capture.pcap [cbridge_ip]")
    lt, pkts = read_pcap(sys.argv[1])
    cbridge = sys.argv[2] if len(sys.argv) >= 3 else None

    # group by ordered flow key (sip -> dip); collect control text + voice
    ctrl = defaultdict(list)   # key -> [(t, text)]
    voice = defaultdict(list)  # key -> [(t, seq, ts, marker, paylen)]
    for t, raw in pkts:
        r = l4(lt, raw)
        if not r: continue
        proto, sip, dip, sport, dport, data = r
        key = (sip, dip)
        if proto == 6 and (sport == 42421 or dport == 42421) and data:
            try: txt = data.decode("latin-1")
            except Exception: txt = ""
            for line in txt.replace("\r", "\n").split("\n"):
                line = line.strip()
                if "Bee=" in line or "LOSS=" in line:
                    ctrl[key].append((t, line))
        elif proto == 17 and (sport == 42422 or dport == 42422) and len(data) >= 12:
            if (data[1] & PT_VOICE_MASK) != PT_VOICE: continue   # skip keepalives
            seq = struct.unpack(">H", data[2:4])[0]
            ts  = struct.unpack(">I", data[4:8])[0]
            marker = (data[1] & 0x80) != 0
            voice[key].append((t, seq, ts, marker, len(data) - 12))

    # pick the outbound (cc2obp -> c-Bridge) flow: the one with a B-on ("Bee="),
    # or matching cbridge_ip as destination, else the flow with the most voice.
    def is_out(key):
        if cbridge: return key[1] == cbridge
        return any("Bee=" in ln for _, ln in ctrl.get(key, []))
    out_keys = [k for k in set(list(ctrl) + list(voice)) if is_out(k)]
    if not out_keys:
        out_keys = sorted(voice, key=lambda k: -len(voice[k]))[:1]
    if not out_keys:
        sys.exit("no CC-CC voice/control found — check ports (42421/42422) and that cc2obp sent a call")

    for key in out_keys:
        print(f"\n===== cc2obp OUTBOUND CC-CC  {key[0]} -> {key[1]} =====")
        cs = sorted(ctrl.get(key, []))
        vs = sorted(voice.get(key, []))
        bons  = [ln for _, ln in cs if "Bee=" in ln]
        boffs = [ln for _, ln in cs if "LOSS=" in ln]
        print(f"B-on ({len(bons)}):  " + (bons[0] if bons else "*** MISSING ***"))
        print(f"B-off ({len(boffs)}): " + (boffs[0] if boffs else "*** MISSING ***"))
        print(f"voice packets: {len(vs)}")
        if not vs:
            print("*** no voice packets in this flow ***"); continue

        # invariants a real c-Bridge peer holds (voice.log confirms):
        problems = []
        markers = [i for i, v in enumerate(vs) if v[3]]
        if markers != [0]:
            problems.append(f"marker bit set on packets {markers}, expected only [0]")
        seq0, ts0 = vs[0][1], vs[0][2]
        seq_bad, ts_bad, len_bad, gaps = [], [], [], []
        prev_t = None
        for i, (t, seq, ts, mk, pl) in enumerate(vs):
            if seq != (seq0 + i) & 0xFFFF: seq_bad.append((i, seq, (seq0 + i) & 0xFFFF))
            if ts  != (ts0 + 480 * i) & 0xFFFFFFFF: ts_bad.append((i, ts, (ts0 + 480 * i) & 0xFFFFFFFF))
            if pl != 21: len_bad.append((i, pl))
            if prev_t is not None:
                dt = (t - prev_t) * 1000.0
                if dt < 30 or dt > 120: gaps.append((i, round(dt, 1)))
            prev_t = t
        if seq_bad: problems.append(f"seq not strictly +1 at {seq_bad[:8]}{' …' if len(seq_bad)>8 else ''}")
        if ts_bad:  problems.append(f"timestamp not strictly +480 at {ts_bad[:8]}{' …' if len(ts_bad)>8 else ''}")
        if len_bad: problems.append(f"payload not 21 bytes at {len_bad[:8]}")
        if gaps:    problems.append(f"inter-packet gap outside 30–120 ms at {gaps[:8]}{' …' if len(gaps)>8 else ''}")
        if len(bons) != 1:  problems.append(f"expected exactly 1 B-on, saw {len(bons)}")
        if len(boffs) != 1: problems.append(f"expected exactly 1 B-off, saw {len(boffs)}")

        print(f"seq: first={seq0} last={vs[-1][1]}   ts: first={ts0} last={vs[-1][2]} (step should be 480)")
        print("first 12 (idx seq ts marker len):")
        for i, (t, seq, ts, mk, pl) in enumerate(vs[:12]):
            print(f"   {i:3d}  seq={seq:5d} ts={ts:7d} M={int(mk)} len={pl}")
        print("\n-- VERDICT --")
        if not problems:
            print("cadence MATCHES a real c-Bridge peer (seq+1, ts+480, marker on first,")
            print("21-byte payloads, one B-on/B-off). The reverse break is NOT here —")
            print("look at B-on field VALUES or the c-Bridge's own reconstruction next.")
        else:
            for p in problems: print("  ✗ " + p)
            print("\nAny of these can make the c-Bridge synthesize a malformed IPSC")
            print("superframe -> subscriber decodes nothing. Fix so the outbound stream")
            print("matches the invariants above (prime suspect: seq/ts derived from")
            print("wall-clock slot index in translate.c ~268-274 instead of a +1 counter).")

if __name__ == "__main__":
    main()
