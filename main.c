/* main.c — cc2obp entry point: args, config load, wires cccc_mux <-> obp_mux
 * <-> translator together, runs the event loop.  SIGHUP reload (§6.3) is
 * deferred out of the signal handler (config_reload_toggles/logging are not
 * async-signal-safe) via a flag checked on the periodic tick. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include "config.h"
#include "log.h"
#include "eventloop.h"
#include "cccc/cccc_link.h"
#include "openbridge/obp_link.h"
#include "translate.h"

#define TICK_INTERVAL_S 1.0

static ev_loop  *g_loop = NULL;
static cccc_mux *g_cc   = NULL;
static obp_mux  *g_ob   = NULL;
static const char *g_cfg_path = NULL;
static Config    g_cfg;

static volatile sig_atomic_t g_reload_requested = 0;
static volatile sig_atomic_t g_shutdown_requested = 0;

static void on_sighup(int signum)  { (void)signum; g_reload_requested = 1; }
static void on_sigterm(int signum) { (void)signum; g_shutdown_requested = 1; }

static void do_reload(void)
{
    char err[8192];
    LOGI("cc2obp", "SIGHUP received — reloading enabled/cross_connect_active toggles from %s (§6.3)", g_cfg_path);
    if (config_reload_toggles(g_cfg_path, &g_cfg, err, sizeof err) != 0) {
        LOGE("cc2obp", "reload failed, keeping running config: %s", err);
        return;
    }
    config_warn_soft_issues(&g_cfg);
    cccc_mux_reconcile(g_cc);
    obp_mux_reconcile(g_ob);
    LOGI("cc2obp", "reload complete");
}

static void tick_cb(ev_loop *loop, void *ud)
{
    translator *tr = ud;
    translator_tick(tr);
    if (g_reload_requested) { g_reload_requested = 0; do_reload(); }
    if (g_shutdown_requested) { ev_stop(loop); return; }
    ev_timer_after(loop, TICK_INTERVAL_S, tick_cb, tr);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-c config.toml] [--log-level LEVEL] [--wire]\n"
        "  -c, --config PATH    Path to TOML config (default: /etc/cc2obp/cc2obp.toml)\n"
        "  --log-level LEVEL    Override config log level (DEBUG|INFO|WARNING|ERROR)\n"
        "  --wire                Log raw CC-CC/OpenBridge hex only; silence everything else\n",
        prog);
}

int main(int argc, char **argv)
{
    const char *cfg_path = "/etc/cc2obp/cc2obp.toml";
    const char *log_level_override = NULL;
    int wire = 0;

    for (int i = 1; i < argc; i++) {
        if ((!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config")) && i + 1 < argc) {
            cfg_path = argv[++i];
        } else if (!strcmp(argv[i], "--log-level") && i + 1 < argc) {
            log_level_override = argv[++i];
        } else if (!strcmp(argv[i], "--wire")) {
            wire = 1;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]); return 0;
        } else {
            usage(argv[0]); return 2;
        }
    }
    g_cfg_path = cfg_path;

    char err[8192];
    if (config_load(cfg_path, &g_cfg, err, sizeof err) != 0) {
        fprintf(stderr, "Configuration error:\n%s\n", err);
        return 1;
    }

    int level = g_cfg.log_level;
    if (log_level_override) {
        int l = log_level_from_str(log_level_override);
        if (l >= 0) level = l;
    }
    log_init(level, wire);
    config_warn_soft_issues(&g_cfg);

    LOGI("cc2obp", "cc2obp starting — %d openbridge peer(s), %d link(s), config=%s",
         g_cfg.n_openbridge, g_cfg.n_link, cfg_path);

    g_loop = ev_new();
    translator *tr = translator_new(&g_cfg, g_loop);
    g_ob = obp_mux_new(&g_cfg, tr, g_loop);
    g_cc = cccc_mux_new(&g_cfg, tr, g_loop);
    translator_set_protocols(tr, g_cc, g_ob);

    struct sigaction sa_term; memset(&sa_term, 0, sizeof sa_term);
    sa_term.sa_handler = on_sigterm;
    sigaction(SIGTERM, &sa_term, NULL);
    sigaction(SIGINT, &sa_term, NULL);

    struct sigaction sa_hup; memset(&sa_hup, 0, sizeof sa_hup);
    sa_hup.sa_handler = on_sighup;
    sigaction(SIGHUP, &sa_hup, NULL);

    if (obp_mux_start(g_ob) != 0) {
        LOGE("cc2obp", "failed to start OpenBridge peers");
        return 1;
    }
    if (cccc_mux_start(g_cc) != 0) {
        fprintf(stderr, "Failed to bind CC-CC sockets\n");
        return 1;
    }

    ev_timer_after(g_loop, TICK_INTERVAL_S, tick_cb, tr);

    LOGI("cc2obp", "cc2obp running");
    ev_run(g_loop);

    LOGI("cc2obp", "shutting down");
    cccc_mux_stop(g_cc);
    obp_mux_stop(g_ob);
    cccc_mux_free(g_cc);
    obp_mux_free(g_ob);
    translator_free(tr);
    ev_free(g_loop);
    LOGI("cc2obp", "cc2obp stopped");
    return 0;
}
