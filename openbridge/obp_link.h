/* obp_link.h — one UDP socket per enabled [[openbridge]] peer (§6.1, §12).
 * Stateless protocol (no login/handshake); owns only the socket, HMAC
 * framing, and slot-1/HMAC validation on receive. */
#ifndef OBP_LINK_H
#define OBP_LINK_H

#include <stdint.h>
#include "../config.h"
#include "../eventloop.h"

typedef struct obp_mux obp_mux;
struct translator;

obp_mux *obp_mux_new(Config *cfg, struct translator *tr, ev_loop *loop);
int  obp_mux_start(obp_mux *mx);   /* binds a UDP socket per enabled peer (§5) */
void obp_mux_stop(obp_mux *mx);
void obp_mux_free(obp_mux *mx);

/* Call after config_reload_toggles() mutates *cfg in place (SIGHUP, §6.3):
 * binds newly-enabled peers, closes newly-disabled peers' sockets. */
void obp_mux_reconcile(obp_mux *mx);

int obp_peer_is_enabled(const obp_mux *mx, int peer_idx);

/* Send a DMRD frame to peer_idx.  body must be exactly OBP_DMRD_BODY_LEN (53)
 * bytes; bytes OBP_NETID_OFF..+4 are overwritten with that peer's own
 * network_id before HMAC signing and transmission (§12).  No-op (logged at
 * DEBUG) if the peer is disabled/has no socket. */
/* rssi: RSSI byte (-dBm, 0 = none) for the BER/RSSI trailer, sent only if the
 * peer has rssi_trailer set (ignored otherwise). */
void obp_send_dmrd(obp_mux *mx, int peer_idx, uint8_t body[53], int rssi);

#endif /* OBP_LINK_H */
