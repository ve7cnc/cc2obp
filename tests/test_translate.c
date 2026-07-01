/* test_translate.c — §15 SSRC collision test, run as a real system test
 * against the compiled cc2obp binary (fork/exec + loopback sockets), not a
 * unit test against translate.c's internals: translate.c's call/link state
 * is intentionally file-local (no test-only accessors), so the only way to
 * observe its behavior is the real wire protocol, exactly as a real c-Bridge
 * would see it.  This mirrors how §15 itself describes validation (drive a
 * call from either side, observe at the other) using external harnesses.
 *
 * Scope note: the other §15 scenarios (orphaned call, seq/ts timestamp gap,
 * LC checksum path, multi-link/multi-peer, enabled/cross_connect_active
 * toggles) all require driving traffic from the OpenBridge (UDP) side, which
 * this file does not yet do (§6.1's bind_port/peer_port split now makes a
 * same-host fake OpenBridge peer possible — see config.h — but that harness
 * hasn't been written here yet). Validate those scenarios manually per §15
 * with cccc_probe.py/hblink3 in the meantime, or add a fake-peer harness to
 * this file using a bind_port distinct from the fake peer's own port.
 *
 * This test only needs the CC-CC (TCP) side: cc2obp is the sole TCP
 * listener (inbound-role links), so this test's two fake clients only ever
 * *connect out* to it — no bind-conflict is possible on that path. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>

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

static int connect_loopback(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(fd, (struct sockaddr *)&a, sizeof a) < 0) { close(fd); return -1; }
    return fd;
}

/* Retry connect for up to ~2s while the child process finishes binding. */
static int connect_loopback_retry(int port)
{
    for (int i = 0; i < 40; i++) {
        int fd = connect_loopback(port);
        if (fd >= 0) return fd;
        sleep_ms(50);
    }
    return -1;
}

static void send_question(int fd, uint32_t sync_source, int lid)
{
    char q[512];
    int n = snprintf(q, sizeof q, "%x\n%d \ntest-channel\ntest-site\nServer Inbound\nDEADBEEF0001\n9999\nLinux test\n",
                     sync_source, lid);
    ssize_t wr = write(fd, q, (size_t)n);
    (void)wr;
}

/* Read with an overall deadline; returns bytes read (0 = EOF, -1 = timeout/error). */
static int read_with_timeout(int fd, char *buf, size_t cap, int timeout_ms)
{
    fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    int r = select(fd + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return -1;
    return (int)read(fd, buf, cap);
}

int main(void)
{
    const char *cfg_path = "/tmp/cc2obp_test_ssrc_collision.toml";
    FILE *f = fopen(cfg_path, "w");
    if (!f) { perror("fopen"); return 2; }
    fprintf(f,
        "[global]\n"
        "log_level = \"DEBUG\"\n"
        "\n"
        "[[openbridge]]\n"
        "name = \"dummy\"\n"
        "enabled = true\n"
        "peer_ip = \"127.0.0.1\"\n"
        "peer_port = 62999\n"
        "bind_port = 62998\n"
        "network_id = 3120099\n"
        "passphrase = \"x\"\n"
        "\n"
        "[[link]]\n"
        "name = \"link-a\"\n"
        "enabled = true\n"
        "cross_connect_active = true\n"
        "tgid = 9\n"
        "openbridge_system = \"dummy\"\n"
        "cc_role = \"inbound\"\n"
        "cc_lid = 60\n"
        "cc_remote_ip = \"127.0.0.1\"\n"
        "cc_remote_voice_port = 42422\n"
        "\n"
        "[[link]]\n"
        "name = \"link-b\"\n"
        "enabled = true\n"
        "cross_connect_active = true\n"
        "tgid = 10\n"
        "openbridge_system = \"dummy\"\n"
        "cc_role = \"inbound\"\n"
        "cc_lid = 61\n"
        "cc_remote_ip = \"127.0.0.1\"\n"
        "cc_remote_voice_port = 42422\n");
    fclose(f);

    pid_t pid = fork();
    if (pid < 0) { perror("fork"); return 2; }
    if (pid == 0) {
        execl("./cc2obp", "cc2obp", "-c", cfg_path, "--log-level", "DEBUG", (char *)NULL);
        perror("execl");
        _exit(127);
    }

    /* Client A: link-a, sync_source S -> expect a valid Answer (link up). */
    int fda = connect_loopback_retry(42421);
    check("client A connected to cc2obp TCP 42421", fda >= 0);
    if (fda >= 0) {
        uint32_t ssrc = 0xdeadbeef;
        send_question(fda, ssrc, 60);
        char buf[512];
        int n = read_with_timeout(fda, buf, sizeof buf, 2000);
        check("client A received an Answer (link up)", n > 0);
        if (n > 0) {
            buf[n < (int)sizeof buf ? n : (int)sizeof buf - 1] = 0;
            check("client A's Answer starts with AMBE codec", strncmp(buf, "AMBE\n", 5) == 0);
        }

        /* Client B: link-b, SAME sync_source -> §7.1 collision policy: no
         * Answer, connection closed immediately. */
        int fdb = connect_loopback_retry(42421);
        check("client B connected to cc2obp TCP 42421", fdb >= 0);
        if (fdb >= 0) {
            send_question(fdb, ssrc, 61);
            char bufb[512];
            int nb = read_with_timeout(fdb, bufb, sizeof bufb, 2000);
            check("client B got no Answer / connection closed on SSRC collision (§7.1)", nb <= 0);
            close(fdb);
        }

        /* Client A's link must be unaffected by B's rejected collision. */
        char probe[16];
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fda, &rfds);
        struct timeval tv = { 0, 200000 };
        int r = select(fda + 1, &rfds, NULL, NULL, &tv);
        int still_open = 1;
        if (r > 0) {
            int n2 = (int)recv(fda, probe, sizeof probe, MSG_DONTWAIT);
            if (n2 == 0) still_open = 0;   /* peer closed -- collision wrongly tore down A */
        }
        check("client A's link still open after B's collision was refused", still_open);

        close(fda);
    }

    kill(pid, SIGTERM);
    int status; waitpid(pid, &status, 0);
    unlink(cfg_path);

    printf("translate self-test: %d checks, %d failures\n", checks, fails);
    return fails ? 1 : 0;
}
