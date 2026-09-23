/* obp_link.c — see obp_link.h.  Wire format confirmed against hblink3's
 * `class OPENBRIDGE` (hblink.py: send_system/datagram_received), not just
 * the informal description: 53-byte DMRD body + 20-byte HMAC-SHA1 (§12). */
#include "obp_link.h"
#include "obp_const.h"
#include "../translate.h"
#include "../net.h"
#include "../crypto.h"
#include "../log.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

#define LOGN "obp.link"

struct obp_mux {
    Config     *cfg;
    struct translator *tr;
    ev_loop    *loop;
    int         fd[CFG_MAX_OPENBRIDGE];
    int         active[CFG_MAX_OPENBRIDGE];  /* mirrors cfg->openbridge[i].enabled at last (re)bind */
    struct { obp_mux *mx; int idx; } cbctx[CFG_MAX_OPENBRIDGE];
};

/* Constant-time-ish digest compare (defense in depth; not a hard requirement
 * of the plan, but cheap and matches good practice for an HMAC check). */
static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
    return diff == 0;
}

static void on_obp_readable(ev_loop *loop, int fd, void *ud)
{
    (void)loop;
    struct { obp_mux *mx; int idx; } *ctx = ud;
    obp_mux *mx = ctx->mx;
    int idx = ctx->idx;
    const ObpPeerConfig *o = &mx->cfg->openbridge[idx];

    uint8_t buf[128];
    char src_ip[INET6_ADDRSTRLEN]; int src_port;
    int n = udp_recvfrom(fd, buf, sizeof buf, src_ip, &src_port);
    if (n < 4 || memcmp(buf, "DMRD", 4) != 0) return;
    log_wire("obp.wire", "UDP RECV %s:%d %d %s", src_ip, src_port, n, log_hex(buf, n));

    int body_len;
    if (n == OBP_DMRD_PKT_LEN) body_len = OBP_DMRD_BODY_LEN;
    else if (n == OBP_DMRD_EXT_PKT_LEN) body_len = OBP_DMRD_EXT_BODY_LEN;   /* + BER/RSSI */
    else {
        LOGD(LOGN, "peer '%s': unexpected length %d (want %d or %d) from %s:%d — dropped",
             o->name, n, OBP_DMRD_PKT_LEN, OBP_DMRD_EXT_PKT_LEN, src_ip, src_port);
        return;
    }
    if (strcmp(src_ip, o->peer_ip) != 0 || src_port != o->peer_port) {
        LOGW(LOGN, "peer '%s': packet from unexpected source %s:%d (expected %s:%d) — dropped",
             o->name, src_ip, src_port, o->peer_ip, o->peer_port);
        return;
    }

    uint8_t expect[OBP_HMAC_LEN];
    hmac_sha1((const uint8_t *)o->passphrase, (size_t)o->passphrase_len,
              buf, (size_t)body_len, expect);
    if (!ct_eq(expect, buf + body_len, OBP_HMAC_LEN)) {
        LOGW(LOGN, "peer '%s': HMAC verification failed — dropped", o->name);
        return;
    }

    /* §1: cc2obp is always slot 1 (an OpenBridge convention); no BOTH_SLOTS
     * support (out of scope). Group/unit/CSBK classification is translate.c's
     * job (§10.1), not this transport-layer gate. */
    uint8_t flags = buf[OBP_FLAGS_OFF];
    if (flags & OBPF_SLOT2) {
        LOGW(LOGN, "peer '%s': packet not on slot 1 — dropped (§1)", o->name);
        return;
    }

    int rssi = (body_len == OBP_DMRD_EXT_BODY_LEN) ? buf[OBP_RSSI_OFF] : 0;
    translator_obp_dmrd_received(mx->tr, idx, buf, rssi);
}

static int bind_peer(obp_mux *mx, int idx)
{
    ObpPeerConfig *o = &mx->cfg->openbridge[idx];
    mx->fd[idx] = udp_bind("0.0.0.0", o->bind_port);
    if (mx->fd[idx] < 0) {
        LOGE(LOGN, "failed to bind udp/%d for openbridge peer '%s'", o->bind_port, o->name);
        return -1;
    }
    mx->cbctx[idx].mx = mx;
    mx->cbctx[idx].idx = idx;
    ev_add_fd(mx->loop, mx->fd[idx], on_obp_readable, &mx->cbctx[idx]);
    mx->active[idx] = 1;
    LOGI(LOGN, "openbridge peer '%s' socket up: local udp/%d -> remote %s:%d (network_id=%u)",
         o->name, o->bind_port, o->peer_ip, o->peer_port, o->network_id);
    return 0;
}

static void unbind_peer(obp_mux *mx, int idx)
{
    if (mx->fd[idx] >= 0) {
        ev_del_fd(mx->loop, mx->fd[idx]);
        close(mx->fd[idx]);
        mx->fd[idx] = -1;
    }
    mx->active[idx] = 0;
    LOGI(LOGN, "openbridge peer '%s' socket down", mx->cfg->openbridge[idx].name);
}

int obp_peer_is_enabled(const obp_mux *mx, int peer_idx)
{
    if (peer_idx < 0 || peer_idx >= mx->cfg->n_openbridge) return 0;
    return mx->active[peer_idx];
}

void obp_send_dmrd(obp_mux *mx, int peer_idx, uint8_t body[53], int rssi)
{
    if (peer_idx < 0 || peer_idx >= mx->cfg->n_openbridge || mx->fd[peer_idx] < 0) {
        LOGD(LOGN, "obp_send_dmrd: peer idx=%d not enabled/bound — dropped", peer_idx);
        return;
    }
    ObpPeerConfig *o = &mx->cfg->openbridge[peer_idx];

    /* §12: bytes 11-14 (peer/network ID field) are normally overwritten with
     * OUR OWN network_id for this peer before signing — not anything from the
     * originating side. This field is not validated by the reference
     * implementation (auth = HMAC + source socket), so preserve_source_peer
     * leaves whatever the caller placed there (the CC-origin source-peer, set
     * by send_dmrd) intact for end-to-end provenance. Default: overwrite. */
    if (!o->preserve_source_peer) {
        body[OBP_NETID_OFF + 0] = (uint8_t)(o->network_id >> 24);
        body[OBP_NETID_OFF + 1] = (uint8_t)(o->network_id >> 16);
        body[OBP_NETID_OFF + 2] = (uint8_t)(o->network_id >> 8);
        body[OBP_NETID_OFF + 3] = (uint8_t)(o->network_id);
    }

    uint8_t pkt[OBP_DMRD_EXT_PKT_LEN];
    int body_len = OBP_DMRD_BODY_LEN;
    memcpy(pkt, body, OBP_DMRD_BODY_LEN);
    if (o->rssi_trailer) {                 /* BER/RSSI trailer extension (obp_const.h) */
        pkt[OBP_DMRD_BODY_LEN] = 0;                        /* BER: not reported over CC-CC */
        pkt[OBP_RSSI_OFF] = (uint8_t)(rssi > 0 && rssi < 256 ? rssi : 0);
        body_len = OBP_DMRD_EXT_BODY_LEN;
    }
    hmac_sha1((const uint8_t *)o->passphrase, (size_t)o->passphrase_len,
              pkt, (size_t)body_len, pkt + body_len);
    int n = body_len + OBP_HMAC_LEN;
    log_wire("obp.wire", "UDP SEND %s:%d %d %s", o->peer_ip, o->peer_port, n, log_hex(pkt, n));
    udp_sendto(mx->fd[peer_idx], pkt, n, o->peer_ip, o->peer_port);
}

obp_mux *obp_mux_new(Config *cfg, struct translator *tr, ev_loop *loop)
{
    obp_mux *mx = calloc(1, sizeof *mx);
    mx->cfg = cfg; mx->tr = tr; mx->loop = loop;
    for (int i = 0; i < CFG_MAX_OPENBRIDGE; i++) mx->fd[i] = -1;
    return mx;
}

int obp_mux_start(obp_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_openbridge; i++)
        if (mx->cfg->openbridge[i].enabled)
            bind_peer(mx, i);   /* non-fatal per-peer failure: other peers/links are independent */
    return 0;
}

void obp_mux_reconcile(obp_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_openbridge; i++) {
        int enabled = mx->cfg->openbridge[i].enabled;
        if (enabled && !mx->active[i]) bind_peer(mx, i);
        else if (!enabled && mx->active[i]) unbind_peer(mx, i);
    }
}

void obp_mux_stop(obp_mux *mx)
{
    for (int i = 0; i < mx->cfg->n_openbridge; i++)
        if (mx->active[i]) unbind_peer(mx, i);
}

void obp_mux_free(obp_mux *mx)
{
    if (!mx) return;
    free(mx);
}
