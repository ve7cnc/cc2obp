/* test_obp_scenarios.c — §15 orphaned-call and seq/ts-gap scenarios, driven
 * from the OpenBridge (UDP) side, now feasible same-host thanks to the
 * bind_port/peer_port split (config.h): this test's fake OpenBridge peer
 * binds its own local port (= the configured peer_port) distinct from
 * cc2obp's own bind_port, so there is no port conflict.
 *
 * Like test_translate.c, this is a system test against the compiled cc2obp
 * binary (fork/exec + real loopback sockets), not a unit test — translate.c
 * exposes no test-only accessors, so the wire protocol is the only
 * observable surface. This test plays BOTH synthetic endpoints: an
 * OpenBridge peer (raw UDP + HMAC-SHA1, using the real dmr/ primitives to
 * build valid DMRD payloads exactly as translate.c does) and a CC-CC
 * inbound-role remote (raw TCP, per the formal spec's handshake).
 *
 * Not covered here: LC-checksum-failure handling — cc2obp intentionally
 * implements no such guard (see translate.c's file header); the plan's
 * original §15 item for it no longer applies. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

#include "../dmr/dmr.h"
#include "../crypto.h"
#include "../openbridge/obp_const.h"

#define FAKE_PEER_PORT   63001   /* this test's own OpenBridge socket (== peer_port in config) */
#define CC2OBP_BIND_PORT 63002   /* cc2obp's own OpenBridge socket (== bind_port in config) */
#define VOICE_TEST_PORT  43001   /* this test's CC-CC voice receiver (== cc_remote_voice_port) */
#define PASSPHRASE       "test-passphrase"
#define TGID             9
#define CC_LID           60

static int fails = 0, checks = 0;
static void check(const char *what, int cond)
{
    checks++;
    if (!cond) { fails++; fprintf(stderr, "FAIL: %s\n", what); }
    else fprintf(stderr, "ok:   %s\n", what);
}

static void sleep_ms(int ms)
{
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/* ---------------- generic socket helpers ---------------- */

static int udp_bind_local(int port)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

static void udp_send_to(int fd, int port, const void *buf, size_t len)
{
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    ssize_t wr = sendto(fd, buf, len, 0, (struct sockaddr *)&a, sizeof a);
    (void)wr;
}

static int udp_recv_timeout(int fd, void *buf, size_t cap, int timeout_ms)
{
    fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return -1;
    return (int)recv(fd, buf, cap, 0);
}

static int tcp_connect_retry(int port)
{
    for (int i = 0; i < 40; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return -1;
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (connect(fd, (struct sockaddr *)&a, sizeof a) == 0) return fd;
        close(fd);
        sleep_ms(50);
    }
    return -1;
}

/* Small line-buffered TCP reader: returns 1 with *line filled on a complete
 * line, 0 on timeout, -1 on EOF/error. */
typedef struct { int fd; char buf[2048]; int len; } tcp_reader;

static int tcp_read_line(tcp_reader *r, char *line, size_t cap, int timeout_ms)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) { deadline.tv_sec++; deadline.tv_nsec -= 1000000000L; }

    for (;;) {
        for (int i = 0; i < r->len; i++) {
            if (r->buf[i] == '\n') {
                int n = i; if (n > 0 && r->buf[n-1] == '\r') n--;
                if ((size_t)n >= cap) n = (int)cap - 1;
                memcpy(line, r->buf, (size_t)n); line[n] = 0;
                memmove(r->buf, r->buf + i + 1, (size_t)(r->len - i - 1));
                r->len -= i + 1;
                return 1;
            }
        }
        struct timespec now; clock_gettime(CLOCK_MONOTONIC, &now);
        double remain = (double)(deadline.tv_sec - now.tv_sec) + (double)(deadline.tv_nsec - now.tv_nsec) / 1e9;
        if (remain <= 0) return 0;

        fd_set rfds; FD_ZERO(&rfds); FD_SET(r->fd, &rfds);
        struct timeval tv = { (long)remain, (long)((remain - (long)remain) * 1e6) };
        int sr = select(r->fd + 1, &rfds, NULL, NULL, &tv);
        if (sr <= 0) return 0;
        ssize_t n = read(r->fd, r->buf + r->len, sizeof r->buf - (size_t)r->len);
        if (n <= 0) return -1;
        r->len += (int)n;
    }
}

/* ---------------- CC-CC handshake ---------------- */

static void send_question(int fd, uint32_t sync_source, int lid)
{
    char q[512];
    int n = snprintf(q, sizeof q, "%x\n%d \ntest-channel\ntest-site\nServer Inbound\nDEADBEEF0002\n9999\nLinux test\n",
                     sync_source, lid);
    ssize_t wr = write(fd, q, (size_t)n);
    (void)wr;
}

/* ---------------- OpenBridge DMRD frame construction (mirrors translate.c) ---------------- */

static void wr24(uint8_t *p, uint32_t v) { p[0]=(uint8_t)(v>>16); p[1]=(uint8_t)(v>>8); p[2]=(uint8_t)v; }

static void build_head_term_payload(const uint8_t lc[9], int is_term, uint8_t out33[33])
{
    dmr_bit full_lc[196]; dmr_bptc_encode_lc(lc, is_term, full_lc);
    dmr_bit fb[264]; int at = 0;
    const dmr_bit *slot_type = is_term ? DMR_SLOT_TYPE_VTERM : DMR_SLOT_TYPE_VHEAD;
    memcpy(fb+at, full_lc, 98); at += 98;
    memcpy(fb+at, slot_type, 10); at += 10;
    memcpy(fb+at, DMR_BS_DATA_SYNC, 48); at += 48;
    memcpy(fb+at, slot_type + 10, 10); at += 10;
    memcpy(fb+at, full_lc + 98, 98); at += 98;
    dmr_bits_to_bytes(fb, 264, out33);
}

static void build_voice_burst_payload(const uint8_t emb[4][4], int pos, uint8_t out33[33])
{
    dmr_bit ambe49[3][49];
    for (int u = 0; u < 3; u++) for (int b = 0; b < 49; b++) ambe49[u][b] = (dmr_bit)((u + b) % 2);
    dmr_bit a1_72[72], a2_72[72], a3_72[72];
    dmr_ambe_49_to_72(ambe49[0], a1_72);
    dmr_ambe_49_to_72(ambe49[1], a2_72);
    dmr_ambe_49_to_72(ambe49[2], a3_72);

    dmr_bit embed[48];
    if (pos == 0) {
        memcpy(embed, DMR_BS_VOICE_SYNC, 48);
    } else {
        int eidx = pos - 1;
        memcpy(embed, DMR_EMB[eidx], 8);
        if (pos <= 4) dmr_bytes_to_bits(emb[pos - 1], 4, embed + 8);
        else memset(embed + 8, 0, 32);
        memcpy(embed + 40, DMR_EMB[eidx] + 8, 8);
    }

    dmr_bit fb[264]; int at = 0;
    memcpy(fb+at, a1_72, 72); at += 72;
    memcpy(fb+at, a2_72, 36); at += 36;
    memcpy(fb+at, embed, 48); at += 48;
    memcpy(fb+at, a2_72 + 36, 36); at += 36;
    memcpy(fb+at, a3_72, 72); at += 72;
    dmr_bits_to_bytes(fb, 264, out33);
}

/* >= 0: send the 75-byte form with a BER/RSSI trailer carrying this RSSI byte
 * (the hblink3 RSSI_TRAILER extension); < 0: standard 73-byte OpenBridge. */
static int g_rssi_trailer = -1;

static void send_dmrd(int fd, uint8_t seq, uint32_t rf_src, uint32_t dst_id, uint8_t flags,
                      const uint8_t stream[4], const uint8_t payload33[33], uint32_t sender_network_id)
{
    uint8_t body[OBP_DMRD_BODY_LEN];
    memcpy(body, "DMRD", 4);
    body[OBP_SEQ_OFF] = seq;
    wr24(body + OBP_SRC_OFF, rf_src);
    wr24(body + OBP_DST_OFF, dst_id);
    body[OBP_NETID_OFF+0] = (uint8_t)(sender_network_id>>24); body[OBP_NETID_OFF+1] = (uint8_t)(sender_network_id>>16);
    body[OBP_NETID_OFF+2] = (uint8_t)(sender_network_id>>8);  body[OBP_NETID_OFF+3] = (uint8_t)(sender_network_id);
    body[OBP_FLAGS_OFF] = flags;
    memcpy(body + OBP_STREAM_OFF, stream, 4);
    memcpy(body + OBP_PAYLOAD_OFF, payload33, 33);

    uint8_t pkt[OBP_DMRD_EXT_PKT_LEN];
    size_t body_len = OBP_DMRD_BODY_LEN;
    memcpy(pkt, body, OBP_DMRD_BODY_LEN);
    if (g_rssi_trailer >= 0) {
        pkt[OBP_DMRD_BODY_LEN] = 0;                          /* BER */
        pkt[OBP_RSSI_OFF] = (uint8_t)g_rssi_trailer;
        body_len = OBP_DMRD_EXT_BODY_LEN;
    }
    hmac_sha1((const uint8_t *)PASSPHRASE, strlen(PASSPHRASE), pkt, body_len, pkt + body_len);
    udp_send_to(fd, CC2OBP_BIND_PORT, pkt, body_len + OBP_HMAC_LEN);
}

static void send_voice_head(int fd, uint32_t rf_src, const uint8_t stream[4], uint8_t emb_out[4][4])
{
    uint8_t lc[9];
    lc[0]=DMR_LC_OPT[0]; lc[1]=DMR_LC_OPT[1]; lc[2]=DMR_LC_OPT[2];
    wr24(lc+3, TGID);
    wr24(lc+6, rf_src);
    dmr_encode_emblc(lc, emb_out);
    uint8_t payload33[33];
    build_head_term_payload(lc, 0, payload33);
    send_dmrd(fd, 0, rf_src, TGID, OBPF_FRAMETYPE_DATASYNC | OBPF_SLT_VHEAD, stream, payload33, 7654321);
}

static void send_voice_term(int fd, uint32_t rf_src, const uint8_t stream[4])
{
    uint8_t lc[9];
    lc[0]=DMR_LC_OPT[0]; lc[1]=DMR_LC_OPT[1]; lc[2]=DMR_LC_OPT[2];
    wr24(lc+3, TGID);
    wr24(lc+6, rf_src);
    uint8_t payload33[33];
    build_head_term_payload(lc, 1, payload33);
    send_dmrd(fd, 0, rf_src, TGID, OBPF_FRAMETYPE_DATASYNC | OBPF_SLT_VTERM, stream, payload33, 7654321);
}

static void send_voice_burst(int fd, uint32_t rf_src, const uint8_t stream[4], const uint8_t emb[4][4], int pos)
{
    uint8_t payload33[33];
    build_voice_burst_payload(emb, pos, payload33);
    uint8_t flags = (pos == 0) ? OBPF_FRAMETYPE_VOICESYNC : (uint8_t)(OBPF_FRAMETYPE_VOICE | pos);
    send_dmrd(fd, (uint8_t)pos, rf_src, TGID, flags, stream, payload33, 7654321);
}

/* ---------------- test scenarios ---------------- */

/* Read OpenBridge packets cc2obp sends the fake peer until one has the given
 * flags byte; returns its length (0 on timeout) with the packet in buf. */
static int recv_obp_flags(int fd, uint8_t flags, uint8_t *buf, size_t cap)
{
    for (int i = 0; i < 50; i++) {
        int n = udp_recv_timeout(fd, buf, cap, 2000);
        if (n <= 0) return 0;
        if (n > OBP_FLAGS_OFF && buf[OBP_FLAGS_OFF] == flags) return n;
    }
    return 0;
}

static int extract_radio_field(const char *bon_line, uint32_t *radio)
{
    char marker[64];
    return sscanf(bon_line, "%63s %u", marker, radio) == 2;
}

int main(void)
{
    const char *cfg_path = "/tmp/cc2obp_test_obp_scenarios.toml";
    FILE *f = fopen(cfg_path, "w");
    if (!f) { perror("fopen"); return 2; }
    fprintf(f,
        "[global]\nlog_level = \"DEBUG\"\n\n"
        "[[openbridge]]\n"
        "name = \"fakepeer\"\nenabled = true\n"
        "peer_ip = \"127.0.0.1\"\npeer_port = %d\nbind_port = %d\n"
        "network_id = 3129999\npassphrase = \"%s\"\nrssi_trailer = true\n\n"
        "[[link]]\n"
        "name = \"link-a\"\nenabled = true\ncross_connect_active = true\n"
        "tgid = %d\nopenbridge_system = \"fakepeer\"\ncc_role = \"inbound\"\n"
        "cc_lid = %d\ncc_remote_ip = \"127.0.0.1\"\ncc_remote_voice_port = %d\n",
        FAKE_PEER_PORT, CC2OBP_BIND_PORT, PASSPHRASE, TGID, CC_LID, VOICE_TEST_PORT);
    fclose(f);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        execl("./cc2obp", "cc2obp", "-c", cfg_path, "--log-level", "DEBUG", (char *)NULL);
        perror("execl"); _exit(127);
    }

    int peer_fd = udp_bind_local(FAKE_PEER_PORT);
    check("fake OpenBridge peer bound to its own port", peer_fd >= 0);
    int voice_fd = udp_bind_local(VOICE_TEST_PORT);
    check("fake CC-CC voice receiver bound", voice_fd >= 0);

    int cc_fd = tcp_connect_retry(42421);
    check("connected to cc2obp CC-CC control channel", cc_fd >= 0);
    tcp_reader rd = { .fd = cc_fd, .len = 0 };

    if (cc_fd >= 0) {
        send_question(cc_fd, 0x11112222, CC_LID);
        char line[512];
        /* Answer is CCCC_ANSWER_NFIELDS (7) newline-terminated fields sent as
         * one block — drain all 7, don't just read one "line". */
        int have_answer = 1;
        char codec[64] = "", ms[64] = "";
        for (int i = 0; i < 7; i++) {
            if (tcp_read_line(&rd, line, sizeof line, 2000) != 1) { have_answer = 0; break; }
            if (i == 0) snprintf(codec, sizeof codec, "%.63s", line);
            if (i == 1) snprintf(ms, sizeof ms, "%.63s", line);
        }
        check("received Answer, link up", have_answer);
        check("Answer codec/ms are AMBE/60", have_answer && !strcmp(codec, "AMBE") && !strcmp(ms, "60"));

        /* ---------------- Scenario A: orphaned call (§15) ---------------- */
        uint8_t stream1[4] = {0x01,0x01,0x01,0x01};
        uint8_t stream2[4] = {0x02,0x02,0x02,0x02};
        uint8_t emb1[4][4], emb2[4][4];

        send_voice_head(peer_fd, 1001, stream1, emb1);
        int got1 = tcp_read_line(&rd, line, sizeof line, 2000);
        check("B-on received for first (orphaned) call", got1 == 1 && strstr(line, "Bee="));
        uint32_t radio1 = 0;
        if (got1 == 1) { extract_radio_field(line, &radio1); }
        check("first B-on carries radio=1001", radio1 == 1001);

        /* No VOICE_TERM for stream1 — send a second VOICE_HEAD with a
         * different stream: cc2obp must synthesize a B-off for the orphaned
         * call, then start a fresh one. */
        send_voice_head(peer_fd, 1002, stream2, emb2);

        int got_boff = tcp_read_line(&rd, line, sizeof line, 2000);
        check("orphaned call produced a synthesized B-off", got_boff == 1 && strstr(line, "LOSS="));

        int got_bon2 = tcp_read_line(&rd, line, sizeof line, 2000);
        check("second B-on received for the new call", got_bon2 == 1 && strstr(line, "Bee="));
        uint32_t radio2 = 0;
        if (got_bon2 == 1) { extract_radio_field(line, &radio2); }
        check("second B-on carries radio=1002 (not orphaned radio 1001)", radio2 == 1002);

        send_voice_term(peer_fd, 1002, stream2);
        int got_boff2 = tcp_read_line(&rd, line, sizeof line, 2000);
        check("clean VOICE_TERM produced a B-off", got_boff2 == 1 && strstr(line, "LOSS="));
        check("B-off without an RSSI trailer reports RSSI=0", got_boff2 == 1 && strstr(line, "RSSI=0"));

        /* ---------------- Scenario B: seq/ts gap consistency (§10.4/§15) ---------------- */
        uint8_t stream3[4] = {0x03,0x03,0x03,0x03};
        uint8_t emb3[4][4];
        send_voice_head(peer_fd, 1003, stream3, emb3);
        int got_bon3 = tcp_read_line(&rd, line, sizeof line, 2000);
        check("B-on received for seq/ts-gap call", got_bon3 == 1 && strstr(line, "Bee="));

        send_voice_burst(peer_fd, 1003, stream3, emb3, 0);
        uint8_t pkt0[64];
        int n0 = udp_recv_timeout(voice_fd, pkt0, sizeof pkt0, 2000);
        check("first RTP voice packet received", n0 == 33);

        /* Simulate a dropped OpenBridge burst by waiting ~2 slot periods
         * (60ms each) before the next one, rather than sending immediately. */
        sleep_ms(130);
        send_voice_burst(peer_fd, 1003, stream3, emb3, 2);
        uint8_t pkt1[64];
        int n1 = udp_recv_timeout(voice_fd, pkt1, sizeof pkt1, 2000);
        check("second RTP voice packet received", n1 == 33);

        if (n0 == 33 && n1 == 33) {
            uint16_t seq0 = (uint16_t)((pkt0[2] << 8) | pkt0[3]);
            uint16_t seq1 = (uint16_t)((pkt1[2] << 8) | pkt1[3]);
            uint32_t ts0 = ((uint32_t)pkt0[4]<<24)|((uint32_t)pkt0[5]<<16)|((uint32_t)pkt0[6]<<8)|pkt0[7];
            uint32_t ts1 = ((uint32_t)pkt1[4]<<24)|((uint32_t)pkt1[5]<<16)|((uint32_t)pkt1[6]<<8)|pkt1[7];
            uint16_t dseq = (uint16_t)(seq1 - seq0);
            uint32_t dts  = ts1 - ts0;
            fprintf(stderr, "  seq0=%u seq1=%u (d=%u)  ts0=%u ts1=%u (d=%u)\n", seq0, seq1, dseq, ts0, ts1, dts);
            check("timestamp gap == sequence gap * 480 (real, consistent loss signal, §10.4)",
                  dts == (uint32_t)dseq * 480u);
            check("a real gap was actually exercised (dseq >= 2, not a compacted/adjacent send)", dseq >= 2);
        }

        send_voice_term(peer_fd, 1003, stream3);
        tcp_read_line(&rd, line, sizeof line, 2000);   /* drain final B-off */

        /* ---------------- Scenario C: BER/RSSI trailer -> B-off RSSI ---------------- */
        uint8_t stream4[4] = {0x04,0x04,0x04,0x04};
        uint8_t emb4[4][4];
        uint8_t pktv[64];
        g_rssi_trailer = 0;                                  /* header: no reading yet */
        send_voice_head(peer_fd, 1004, stream4, emb4);
        int got_bon4 = tcp_read_line(&rd, line, sizeof line, 2000);
        check("75-byte (RSSI trailer) VOICE_HEAD accepted", got_bon4 == 1 && strstr(line, "Bee="));
        g_rssi_trailer = 99;
        send_voice_burst(peer_fd, 1004, stream4, emb4, 0);
        check("75-byte voice burst relayed", udp_recv_timeout(voice_fd, pktv, sizeof pktv, 2000) == 33);
        g_rssi_trailer = 101;
        send_voice_burst(peer_fd, 1004, stream4, emb4, 1);
        udp_recv_timeout(voice_fd, pktv, sizeof pktv, 2000);
        send_voice_term(peer_fd, 1004, stream4);
        int got_boff4 = tcp_read_line(&rd, line, sizeof line, 2000);
        /* average of 99 and 101 = -100 dBm -> 8.8 fixed point 100 * 256 = 25600 */
        check("B-off carries the call's average RSSI (RSSI=25600)", got_boff4 == 1 && strstr(line, "RSSI=25600"));
        g_rssi_trailer = -1;

        /* ---------------- Scenario D: c-Bridge B-off RSSI -> VOICE_TERM trailer ---------------- */
        /* A cc-origin call: B-on, then B-off with RSSI=27615 (8.8 fixed point: -107.87 dBm).
         * With rssi_trailer set, cc2obp sends the 75-byte form, the terminator carrying 108. */
        char ctl[256];
        uint8_t obp[128];
        snprintf(ctl, sizeof ctl, "B01%02dtest 1005 302700 0.0 radioid=1005 peerid=302700 Bee=B0102%dG\n",
                 CC_LID, TGID);
        check("B-on written", write(cc_fd, ctl, strlen(ctl)) == (ssize_t)strlen(ctl));
        int nh = recv_obp_flags(peer_fd, OBPF_FRAMETYPE_DATASYNC | OBPF_SLT_VHEAD, obp, sizeof obp);
        check("cc-origin VOICE_HEAD sent in 75-byte form, RSSI 0", nh == OBP_DMRD_EXT_PKT_LEN && obp[OBP_RSSI_OFF] == 0);
        snprintf(ctl, sizeof ctl, "B%02d00000  LOSS=0/1 RSSI=27615\n", CC_LID);
        check("B-off written", write(cc_fd, ctl, strlen(ctl)) == (ssize_t)strlen(ctl));
        int nt = recv_obp_flags(peer_fd, OBPF_FRAMETYPE_DATASYNC | OBPF_SLT_VTERM, obp, sizeof obp);
        check("VOICE_TERM carries the B-off RSSI (108 = -108 dBm)", nt == OBP_DMRD_EXT_PKT_LEN && obp[OBP_RSSI_OFF] == 108);

        close(cc_fd);
    }
    if (peer_fd >= 0) close(peer_fd);
    if (voice_fd >= 0) close(voice_fd);

    kill(pid, SIGTERM);
    int status; waitpid(pid, &status, 0);
    unlink(cfg_path);

    printf("obp_scenarios self-test: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
