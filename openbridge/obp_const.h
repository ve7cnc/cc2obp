/* obp_const.h — OpenBridge DMRD wire layout and HMAC framing.
 * Confirmed against hblink3's `class OPENBRIDGE` (hblink.py: send_system /
 * datagram_received), not just the informal protocol description: OpenBridge's
 * DMRD body is 53 bytes (no trailing BER/RSSI — that is a Homebrew/HBP-only
 * extension present in ipsc2hbpc's hbp_const.h DMRD_LEN=55, and does NOT apply
 * here), followed by a 20-byte HMAC-SHA1 digest computed over those 53 bytes. */
#ifndef OBP_CONST_H
#define OBP_CONST_H

/* DMRD body layout (bytes 0..52) */
#define OBP_DMRD_BODY_LEN   53
#define OBP_HMAC_LEN        20
#define OBP_DMRD_PKT_LEN    (OBP_DMRD_BODY_LEN + OBP_HMAC_LEN)   /* 73 */

#define OBP_SEQ_OFF         4    /* 1 byte */
#define OBP_SRC_OFF         5    /* 3 bytes: rf_src */
#define OBP_DST_OFF         8    /* 3 bytes: dst_id (TGID) */
#define OBP_NETID_OFF       11   /* 4 bytes: peer/network_id, overwritten on send (§12) */
#define OBP_FLAGS_OFF       15   /* 1 byte */
#define OBP_STREAM_OFF      16   /* 4 bytes: stream_id */
#define OBP_PAYLOAD_OFF     20   /* 33 bytes: DMR burst payload */
#define OBP_PAYLOAD_LEN     33

/* Flags byte (offset 15) — identical bit meanings to ipsc2hbpc's hbp_const.h
 * HBPF_* (both descend from the same Homebrew DMRD convention); redefined here
 * under an OBP_ prefix since OpenBridge's frame length/trailer differ. */
#define OBPF_SLOT2          0x80   /* bit 7: 1 = timeslot 2. cc2obp only ever sends/expects slot 1 (§1). */
#define OBPF_CALL_UNIT      0x40   /* bit 6: private (unit) call — out of scope (§1), dropped */
#define OBPF_FRAMETYPE_MASK 0x30
#define OBPF_FRAMETYPE_VOICE      0x00
#define OBPF_FRAMETYPE_VOICESYNC  0x10
#define OBPF_FRAMETYPE_DATASYNC   0x20
#define OBPF_DTYPE_MASK     0x0F
#define OBPF_SLT_VHEAD      0x01
#define OBPF_SLT_VTERM      0x02
/* vcsbk detection per hblink3: (bits & 0x23) == 0x23 */
#define OBPF_VCSBK_MASK     0x23

#endif /* OBP_CONST_H */
