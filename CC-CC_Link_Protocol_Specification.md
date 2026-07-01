# CC-CC Link Protocol Specification

**Control Center to Control Center (CC-CC) link protocol**
Version 1.0 — 2026-06-30
Status: Group-voice profile. Derived from interoperability analysis against a
production c-Bridge (code revision 10252).

---

## 1. Introduction and Scope

CC-CC is the protocol used to link two c-Bridge "Control Centers." A link joins one
**Bridge Group** on each Control Center into a single point-to-point conduit
identified by a **Link ID (LID)**, carrying one talkgroup's traffic and one
concurrent call.

This document specifies the protocol sufficiently to implement an interoperable
endpoint.

**In scope:** link establishment, group voice transport, call signaling, keepalive,
link-test diagnostics, and teardown.

**Out of scope:** private (unit) calls, data calls, and the c-Bridge's internal
bridge/routing configuration. These are noted where the wire format reserves space
for them (§13).

## 2. Terminology and Conventions

| Term | Meaning |
|---|---|
| Control Center | A c-Bridge instance terminating one end of a link. |
| Bridge Group | A named routing group on a Control Center; one per link end. |
| Link ID (LID) | Numeric identifier of a CC-CC conduit. The routing key (§5). |
| Bridge | A Control Center's local named binding of an IPSC LID to a CC-CC LID (§5). |
| Outbound | The link end that initiates the connection. |
| Inbound | The link end that listens for the connection. |
| Sync source | A per-connection 32-bit value used as the RTP SSRC (§4.1). |

The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted
as in RFC 2119.

Multi-byte integers are big-endian. Control-channel messages are ASCII text; fields
are separated by a single newline (`0x0A`), including a trailing newline after the
final field. Byte values are shown in hexadecimal.

## 3. Architecture and Transport

A link is asymmetric to establish and symmetric in operation. The Outbound end opens
the connection; once established, voice flows in both directions. A link carries one
LID and one concurrent call; additional concurrent calls require additional links.

| Port | Transport | Purpose | Section |
|---|---|---|---|
| 42421 | TCP | Control channel: handshake, call signaling | §4, §7 |
| 42422 | UDP | Voice (RTP) and keepalive | §6, §8 |
| 42420 | UDP | Link-test diagnostic packets | §9 |

Port 42420 also carries an unrelated TCP web-management interface; it is not part of
this protocol.

The Outbound end MUST be configured with the remote Control Center's address and the
LID. The Inbound end MUST be configured with the remote site name and the LID.

### 3.1 Concurrent Links

A Control Center MAY maintain any number of links simultaneously, including multiple
links to the same remote Control Center. Each link requires its own TCP control
connection (§4); this is a consequence of §4.1 — the sync source that identifies a
link's voice traffic on the shared UDP port is established once per control
connection, so one TCP connection cannot carry more than one link. All links to a
given remote UDP port share that port for voice, keepalive, and diagnostic traffic,
and are demultiplexed by sync source (SSRC).

## 4. Control Channel — Connection Establishment

The Outbound end opens a TCP connection to the Inbound end on port 42421 and
immediately sends the Question. The Inbound end replies with the Answer. On success
the link is established and remains so until torn down (§10).

### 4.1 Question (Outbound → Inbound)

Eight newline-delimited fields:

| # | Field | Encoding / Notes |
|---|---|---|
| 0 | Sync source | 32-bit value as a lowercase hex string. Random per connection. Becomes the RTP SSRC for this connection in both directions. MUST be unique among the recipient's active connections. |
| 1 | Link ID | Decimal LID, followed by a space. |
| 2 | Channel name | Sending bridge-group label. |
| 3 | Site name | Sending Control Center name. |
| 4 | Connection type | Literal `Server Inbound`. |
| 5 | MAC address | 12 hex characters. |
| 6 | Code revision | Decimal build identifier. |
| 7 | OS version | Free-text. |

### 4.2 Answer (Inbound → Outbound)

Seven newline-delimited fields:

| # | Field | Encoding / Notes |
|---|---|---|
| 0 | Codec | `AMBE`. Negotiated (§4.3). |
| 1 | Audio per frame (ms) | `60`. Negotiated (§4.3). |
| 2 | Time | `<seconds> <microseconds>` Unix time, for clock-offset reference. |
| 3 | Version | Build identifier and compile date. |
| 4 | Site name | Replying Control Center name. |
| 5 | RTP TOS | `0`. Unused. |
| 6 | OS version | Free-text. |

### 4.3 Validation

Only Codec (Answer field 0) and Audio per frame (field 1) are validated. If either
disagrees with the Outbound end's configuration, the Outbound end MUST close the TCP
connection. All other fields are informational and MUST NOT cause rejection.

## 5. Identity and Routing Model

Two independent LID number spaces exist:

- **IPSC LIDs** — assigned by a Control Center to each timeslot of each attached IPSC
  system: for system *n*, slot 1 = `2n−1`, slot 2 = `2n`.
- **CC-CC LIDs** — assigned to inbound/outbound links. Unrelated to IPSC LIDs of the
  same numeric value.

The two spaces are connected by a **bridge**: a named binding on each Control Center
that makes an IPSC LID and a CC-CC LID members of the same group. Each bridge member
specifies that Control Center's own local talkgroup (TGID).

Consequences for an implementation:

- The **CC-CC LID is the routing key** carried in call signaling (§7).
- **TGID is local.** It is not carried end-to-end; each end maps the conduit to its
  own configured TGID. A TGID value that appears in signaling (§7) reflects the
  *originating* side and MUST NOT be used for delivery routing.
- The **source radio ID is carried end-to-end** so the receiving end can reconstruct
  the caller identity.

## 6. Voice Transport (UDP 42422)

Voice is carried as RTP. Each packet is a 12-byte RTP header followed by a 21-byte
payload.

### 6.1 RTP Header

| Bytes | Field | Value |
|---|---|---|
| 0 | V/P/X/CC | `0x80` (version 2). |
| 1 | M / Payload type | Payload type 94 (`0x5E`). The marker bit is set on the first packet of a call: `0xDE` first packet, `0x5E` thereafter. |
| 2–3 | Sequence | Starts at 0 per call; increments by 1 per packet. |
| 4–7 | Timestamp | Starts at 0 per call; increments by 480 per packet (8 kHz × 60 ms). |
| 8–11 | SSRC | The connection sync source (§4.1). |

Sequence and timestamp reset to 0 at the start of each call. The receiver
demultiplexes packets to a link by SSRC.

### 6.2 Payload

The 21-byte payload is three 7-byte units, each carrying one 49-bit AMBE voice frame
representing 20 ms of audio (60 ms per packet).

Within each 7-byte unit the 49-bit frame is packed most-significant-bit first: bits
0–47 occupy bytes 0–5, bit 48 occupies the most-significant bit of byte 6, and the
remaining 7 bits of byte 6 are zero padding.

## 7. Call Signaling (Control Channel)

Call boundaries are signaled as single text lines on the TCP control channel. No
call metadata is carried in the voice stream; signaling occurs only at call start
and end.

### 7.1 Call start (B-on)

```
B01<LID><user> <radio> <peer> <rssi> radioid=<radio> peerid=<peer> Bee=B01<srcLID><TGID><type>
```

| Token | Encoding / Notes |
|---|---|
| `B01<LID><user>` | Marker. `B01`, then LID (2 digits), then user number (3 digits). |
| `<radio>` | Source radio (subscriber) ID. |
| `<peer>` | Source peer (repeater) ID. |
| `<rssi>` | Initial RSSI; `0.0` at call start. |
| `radioid=`, `peerid=` | Source radio and peer IDs, repeated as key-value fields. |
| `Bee=B01<srcLID><TGID><type>` | Originating descriptor: `B01`, source IPSC LID (2 digits), TGID (variable length), and call type — `G` for group. |

### 7.2 Call end (B-off)

```
B<LID>00000  LOSS=<lost>/<total> RSSI=<rssi>
```

| Token | Encoding / Notes |
|---|---|
| `B<LID>00000` | Marker. `B`, LID (2 digits), then zero padding. |
| `LOSS=<lost>/<total>` | Voice packets lost and total for the call, as counted by the originating end. |
| `RSSI=<rssi>` | Raw end-of-call RSSI. |

## 8. Link Keepalive (UDP 42422)

Each end sends a keepalive approximately every 10 seconds. It maintains link
liveness only and does not feed the diagnostics of §9.

A keepalive is a 16-byte RTP-format packet:

| Bytes | Field | Value |
|---|---|---|
| 0 | V/P/X/CC | `0x80`. |
| 1 | Payload type | 127 (`0x7F`). |
| 2–3 | Sequence | `0x0000`. |
| 4–7 | Timestamp | `0x00000000`. |
| 8–11 | SSRC | The connection sync source. |
| 12–15 | Payload | `0x00000064` (constant; see §13). |

An endpoint SHOULD originate its own keepalive on the interval above and SHOULD
reflect a received keepalive to the sender. Loss of received keepalives indicates a
dead link.

## 9. Link-Test Diagnostics (UDP 42420)

Each end measures the round-trip time and loss rate of its link by sending **trial
packets** to the remote end's UDP port 42420. Every 2 minutes a burst of
audio-sized packets (approximately 5 seconds of audio) is sent; the sender derives
round-trip time and loss from the packets that return.

An endpoint **MUST reflect** received trial packets back to their sender unchanged.
An endpoint that does not reflect them causes the remote end to report 100% loss and
a maximum round-trip time, independent of whether voice (§6) is flowing.

An endpoint need not originate trial packets unless it intends to measure the remote
end itself. Reflection alone satisfies the remote end's measurement.

## 10. Link Teardown

There is no explicit teardown message. A link is torn down by closing the TCP control
connection (§4); the close presents as a normal TCP FIN. A link is also considered
dead when received keepalives (§8) cease. No final packet is sent on any channel.

A link configured but administratively bounced is re-established by the Outbound end
reopening the connection (§4) with a new sync source.

## 11. Timing Requirements

CC-CC voice is RTP and its timing MUST be honored.

- **Origination.** An endpoint that *generates* a voice stream MUST pace packets at
  60 ms and increment the RTP timestamp by 480 per packet, with the pacing held to
  the timestamp clock. Cumulative drift corrupts the decoded audio.
- **Relay.** An endpoint that *forwards* existing voice MUST transmit packets as they
  arrive and MUST NOT re-pace or insert a jitter buffer. Inter-packet timing is
  preserved by the originator; de-jittering is the responsibility of the final
  receiver.

## 12. Security Considerations

The protocol provides no authentication, integrity, or confidentiality. A link is
trusted on the basis of source address and static configuration alone. Deployments
MUST rely on network controls (firewalling to the configured peers, or a private
transport) to restrict access to the link ports.

## 13. Assumptions, Undefined Behavior, and Out-of-Scope

| Item | Status |
|---|---|
| Private (unit) calls | Out of scope. The Bee `<type>` field (§7.1) carries `G` for group; other values are not specified here. |
| Data calls | Out of scope. |
| Source IPSC LID > 99 | Undefined. The Bee `<srcLID>` field (§7.1) is two digits; encoding for IPSC LIDs of 100 or greater is unknown. |
| Keepalive payload `0x00000064` | Constant in all observed traffic; its meaning is unknown. Implementations should reproduce it verbatim. |
| Connection type values | Only `Server Inbound` (§4.1 field 4) is known. |
| Codec values | Only `AMBE` is known. |
| Concurrent links | Verified with two simultaneous links to one remote (§3.1). Behavior at larger scale is assumed, not characterized here. |
| First voice packet | A receiver MAY miss the first (sequence 0) voice packet of a call if it arrives before the B-on (§7.1) is processed. A missed frame is a loss; it MUST NOT be synthesized. |

## Appendix A — Annotated Call Lifecycle

A single group call over an established link, Outbound (initiator) to Inbound.

```
1. Connection
   Outbound → Inbound   TCP 42421   Question (§4.1)
   Inbound  → Outbound  TCP 42421   Answer   (§4.2), codec/ms agree → link up

2. Maintenance (continuous)
   both ends            UDP 42422   keepalive every ~10 s (§8), reflected
   both ends            UDP 42420   trial burst every 2 min (§9), reflected

3. Call
   Outbound → Inbound   TCP 42421   B-on   (§7.1)
   Outbound → Inbound   UDP 42422   RTP voice, PT 94, seq/ts from 0,
                                     marker set on first packet, +480/packet (§6)
   Outbound → Inbound   TCP 42421   B-off  (§7.2)

4. Teardown
   either end           TCP 42421   close connection (§10)
```
