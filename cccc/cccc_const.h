/* cccc_const.h — CC-CC wire constants: ports, RTP/keepalive layout, call-
 * signaling text formats.  Ported directly from
 * CC-CC_Link_Protocol_Specification.md; see that document for authoritative
 * detail on every field referenced here. */
#ifndef CCCC_CONST_H
#define CCCC_CONST_H

/* Ports (§3) */
#define CCCC_CONTROL_PORT   42421   /* TCP: handshake, call signaling (§4, §7) */
#define CCCC_VOICE_PORT     42422   /* UDP: voice (RTP) and keepalive (§6, §8), shared by every link */
#define CCCC_TRIAL_PORT     42420   /* UDP: link-test diagnostic reflector (§9), stateless */

/* Voice RTP (UDP 42422) — §6.1 */
#define CCCC_RTP_HDR_LEN     12
#define CCCC_RTP_PAYLOAD_LEN 21     /* 3 x 7-byte AMBE units (§6.2) */
#define CCCC_RTP_PKT_LEN     (CCCC_RTP_HDR_LEN + CCCC_RTP_PAYLOAD_LEN)  /* 33 */
#define CCCC_RTP_VPXCC       0x80   /* byte 0: version 2, no padding/ext/CSRC */
#define CCCC_RTP_PT_VOICE    94     /* 0x5E */
#define CCCC_RTP_MARKER_BIT  0x80   /* set in byte 1 on the first packet of a call */
#define CCCC_RTP_TS_STEP     480    /* 8 kHz * 60 ms per packet (§6.1, §11) */
#define CCCC_SLOT_MS         0.060  /* 60 ms/frame (§11) */

/* Keepalive (UDP 42422) — §8: 16-byte RTP-format packet */
#define CCCC_KEEPALIVE_LEN   16
#define CCCC_RTP_PT_KEEPALIVE 127   /* 0x7F */
#define CCCC_KEEPALIVE_PAYLOAD 0x00000064u  /* constant; meaning unknown (§13) */
#define CCCC_KEEPALIVE_INTERVAL_S 10.0      /* approx. §8 */
#define CCCC_LINK_TIMEOUT_S       35.0      /* no keepalive received within this -> link dead */

/* Call signaling (TCP 42421) — §7.  Call type is always 'G' (group); private
 * calls are out of scope (§1). */
#define CCCC_CALL_TYPE_GROUP 'G'

/* Handshake (TCP 42421) — §4 */
#define CCCC_QUESTION_NFIELDS 8
#define CCCC_ANSWER_NFIELDS   7
#define CCCC_CONNTYPE_SERVER_INBOUND "Server Inbound"   /* §4.1 field 4, literal */
#define CCCC_CODEC_AMBE       "AMBE"                    /* §4.2 field 0 */
#define CCCC_MS_PER_FRAME     60                        /* §4.2 field 1 */

/* Link-test trial reflector (UDP 42420) — §9: fully stateless, reflect verbatim. */

#endif /* CCCC_CONST_H */
