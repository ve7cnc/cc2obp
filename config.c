/* config.c — load and validate the TOML config (§6).  Style/helpers ported
 * from ipsc2hbpc's config.c (errbag accumulator + typed get_* helpers);
 * extended here to walk [[openbridge]]/[[link]] array-of-tables via
 * toml_array_len + a constructed "name#index" section string. */
#include "config.h"
#include "toml.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

/* error accumulator */
typedef struct { char buf[8192]; int n; } errbag;
static void adderr(errbag *e, const char *fmt, ...) {
    char line[256];
    va_list ap; va_start(ap, fmt);
    vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    e->n += snprintf(e->buf + e->n, sizeof e->buf - (size_t)e->n, "  %s\n", line);
}

static void str_to_upper(char *s) { for (; *s; s++) *s = (char)toupper((unsigned char)*s); }

static char *trimcpy(char *dst, size_t cap, const char *src) {
    while (*src && isspace((unsigned char)*src)) src++;
    size_t len = strlen(src);
    while (len > 0 && isspace((unsigned char)src[len-1])) len--;
    if (len >= cap) len = cap - 1;
    memcpy(dst, src, len);
    dst[len] = 0;
    return dst;
}

static int get_str(const toml *t, errbag *e, const char *sec, const char *key,
                   int required, const char *deflt, char *out, size_t cap) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) {
        if (required) adderr(e, "[%s] %s: required", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0] = 0;
        return 0;
    }
    if (v->type != TOML_STRING) {
        adderr(e, "[%s] %s: must be a string", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0] = 0;
        return 0;
    }
    trimcpy(out, cap, v->s);
    return 1;
}

static int get_choice(const toml *t, errbag *e, const char *sec, const char *key,
                      int required, const char *deflt,
                      const char *const *choices, int nch, char *out, size_t cap) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) {
        if (required) adderr(e, "[%s] %s: required", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0] = 0;
        return 0;
    }
    if (v->type != TOML_STRING) { adderr(e, "[%s] %s: must be a string", sec, key);
        if (deflt) snprintf(out, cap, "%s", deflt); else out[0]=0; return 0; }
    char tmp[64]; trimcpy(tmp, sizeof tmp, v->s); str_to_upper(tmp);
    for (int i = 0; i < nch; i++)
        if (!strcmp(tmp, choices[i])) { snprintf(out, cap, "%s", choices[i]); return 1; }
    adderr(e, "[%s] %s: invalid value '%s'", sec, key, v->s);
    if (deflt) snprintf(out, cap, "%s", deflt); else out[0]=0;
    return 0;
}

static long long get_int(const toml *t, errbag *e, const char *sec, const char *key,
                         int required, long long deflt, int has_min, long long mn,
                         int has_max, long long mx) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) { if (required) adderr(e, "[%s] %s: required", sec, key); return deflt; }
    if (v->type != TOML_INT) { adderr(e, "[%s] %s: must be an integer", sec, key); return deflt; }
    if (has_min && v->i < mn) adderr(e, "[%s] %s: must be >= %lld, got %lld", sec, key, mn, v->i);
    if (has_max && v->i > mx) adderr(e, "[%s] %s: must be <= %lld, got %lld", sec, key, mx, v->i);
    return v->i;
}

static int get_bool(const toml *t, errbag *e, const char *sec, const char *key,
                    int required, int deflt) {
    const toml_value *v = toml_get(t, sec, key);
    if (!v) { if (required) adderr(e, "[%s] %s: required", sec, key); return deflt; }
    if (v->type != TOML_BOOL) { adderr(e, "[%s] %s: must be true or false", sec, key); return deflt; }
    return v->b;
}

static int is_valid_ipv4(const char *s) {
    struct in_addr a;
    return inet_pton(AF_INET, s, &a) == 1;
}

/* ---------------- [[openbridge]] (§6.1) ---------------- */

static void load_openbridge(const toml *t, errbag *e, Config *cfg)
{
    int n = toml_array_len(t, "openbridge");
    if (n > CFG_MAX_OPENBRIDGE) {
        adderr(e, "[[openbridge]]: %d entries exceeds maximum of %d", n, CFG_MAX_OPENBRIDGE);
        n = CFG_MAX_OPENBRIDGE;
    }
    for (int i = 0; i < n; i++) {
        char sec[80]; snprintf(sec, sizeof sec, "openbridge#%d", i);
        ObpPeerConfig *o = &cfg->openbridge[cfg->n_openbridge++];
        memset(o, 0, sizeof *o);

        get_str(t, e, sec, "name", 1, "", o->name, sizeof o->name);
        o->enabled = get_bool(t, e, sec, "enabled", 0, 1);
        get_str(t, e, sec, "peer_ip", 1, "", o->peer_ip, sizeof o->peer_ip);
        if (o->peer_ip[0] && !is_valid_ipv4(o->peer_ip))
            adderr(e, "[%s] peer_ip: not a valid IPv4 address: %s", sec, o->peer_ip);
        o->peer_port = (int)get_int(t, e, sec, "peer_port", 1, 0, 1, 1, 1, 65535);
        o->bind_port = (int)get_int(t, e, sec, "bind_port", 1, 0, 1, 1, 1, 65535);
        o->network_id = (uint32_t)get_int(t, e, sec, "network_id", 1, 0, 1, 0, 0, 0);
        { char pp[256]; get_str(t, e, sec, "passphrase", 1, "", pp, sizeof pp);
          o->passphrase_len = (int)strlen(pp);
          memcpy(o->passphrase, pp, (size_t)o->passphrase_len); }
    }

    /* name uniqueness */
    for (int i = 0; i < cfg->n_openbridge; i++)
        for (int j = i + 1; j < cfg->n_openbridge; j++)
            if (cfg->openbridge[i].name[0] && !strcmp(cfg->openbridge[i].name, cfg->openbridge[j].name))
                adderr(e, "[[openbridge]]: duplicate name '%s' (entries %d and %d)",
                       cfg->openbridge[i].name, i, j);

    /* bind_port is OUR OWN local port per peer (obp_link.c binds it; §12's
     * hblink3 precedent has both PORT and TARGET_PORT — this mirrors that).
     * Two enabled peers sharing a bind_port would both try to bind the same
     * local port and fail at runtime — catch that here with a clear message
     * instead of a bare EADDRINUSE from bind(). Nothing stops bind_port from
     * equaling peer_port if the operator wants the common symmetric-port
     * convention; that's just two fields with the same value. */
    for (int i = 0; i < cfg->n_openbridge; i++) {
        if (!cfg->openbridge[i].enabled) continue;
        for (int j = i + 1; j < cfg->n_openbridge; j++) {
            if (!cfg->openbridge[j].enabled) continue;
            if (cfg->openbridge[i].bind_port == cfg->openbridge[j].bind_port)
                adderr(e, "[[openbridge]]: '%s' and '%s' both use bind_port %d — two enabled peers "
                       "cannot bind the same local port",
                       cfg->openbridge[i].name, cfg->openbridge[j].name, cfg->openbridge[i].bind_port);
        }
    }
}

/* ---------------- [[link]] (§6.2, §6.4) ---------------- */

static int find_openbridge(const Config *cfg, const char *name)
{
    for (int i = 0; i < cfg->n_openbridge; i++)
        if (!strcmp(cfg->openbridge[i].name, name)) return i;
    return -1;
}

static void load_links(const toml *t, errbag *e, Config *cfg)
{
    int n = toml_array_len(t, "link");
    if (n > CFG_MAX_LINKS) {
        adderr(e, "[[link]]: %d entries exceeds maximum of %d", n, CFG_MAX_LINKS);
        n = CFG_MAX_LINKS;
    }
    for (int i = 0; i < n; i++) {
        char sec[80]; snprintf(sec, sizeof sec, "link#%d", i);
        LinkConfig *l = &cfg->link[cfg->n_link++];
        memset(l, 0, sizeof *l);

        get_str(t, e, sec, "name", 1, "", l->name, sizeof l->name);
        l->enabled = get_bool(t, e, sec, "enabled", 0, 1);
        l->cross_connect_active = get_bool(t, e, sec, "cross_connect_active", 0, 1);
        l->tgid = (int)get_int(t, e, sec, "tgid", 1, 0, 1, 0, 0, 0);

        get_str(t, e, sec, "openbridge_system", 1, "", l->openbridge_system, sizeof l->openbridge_system);
        l->openbridge_idx = find_openbridge(cfg, l->openbridge_system);
        if (l->openbridge_system[0] && l->openbridge_idx < 0)
            adderr(e, "[%s] openbridge_system: no [[openbridge]] named '%s'", sec, l->openbridge_system);

        { static const char *ROLES[] = {"OUTBOUND", "INBOUND"};
          char role[16];
          get_choice(t, e, sec, "cc_role", 1, "OUTBOUND", ROLES, 2, role, sizeof role);
          l->cc_role = !strcmp(role, "INBOUND") ? CC_ROLE_INBOUND : CC_ROLE_OUTBOUND;
        }

        /* No upper bound enforced: §16 notes LID > 99 encoding in Bee= is
         * undefined upstream, not that this program must reject it — that is
         * operator guidance ("should stay <= 99"), not one of §6.4's hard
         * validation rules. */
        l->cc_lid = (int)get_int(t, e, sec, "cc_lid", 1, 0, 1, 0, 0, 0);

        /* cc_remote_ip required for BOTH roles (§6.2, §6.4) */
        get_str(t, e, sec, "cc_remote_ip", 1, "", l->cc_remote_ip, sizeof l->cc_remote_ip);
        if (l->cc_remote_ip[0] && !is_valid_ipv4(l->cc_remote_ip))
            adderr(e, "[%s] cc_remote_ip: not a valid IPv4 address: %s", sec, l->cc_remote_ip);

        /* cc_remote_port: meaningful and required ONLY for outbound (§6.4).
         * For inbound, never read it from TOML — always -1 in the runtime
         * struct regardless of what (if anything) is present in the file. */
        if (l->cc_role == CC_ROLE_OUTBOUND)
            l->cc_remote_port = (int)get_int(t, e, sec, "cc_remote_port", 1, 0, 1, 1, 1, 65535);
        else
            l->cc_remote_port = -1;

        l->cc_remote_voice_port = (int)get_int(t, e, sec, "cc_remote_voice_port", 1, 0, 1, 1, 1, 65535);

        if (l->cc_role == CC_ROLE_OUTBOUND)
            get_str(t, e, sec, "cc_channel_name", 1, "", l->cc_channel_name, sizeof l->cc_channel_name);
        else
            get_str(t, e, sec, "cc_channel_name", 0, "", l->cc_channel_name, sizeof l->cc_channel_name);
    }

    /* §6.4 validation */

    /* link.name unique */
    for (int i = 0; i < cfg->n_link; i++)
        for (int j = i + 1; j < cfg->n_link; j++)
            if (cfg->link[i].name[0] && !strcmp(cfg->link[i].name, cfg->link[j].name))
                adderr(e, "[[link]]: duplicate name '%s' (entries %d and %d)", cfg->link[i].name, i, j);

    /* (openbridge_system, tgid) unique */
    for (int i = 0; i < cfg->n_link; i++)
        for (int j = i + 1; j < cfg->n_link; j++)
            if (cfg->link[i].openbridge_idx >= 0 && cfg->link[i].openbridge_idx == cfg->link[j].openbridge_idx &&
                cfg->link[i].tgid == cfg->link[j].tgid)
                adderr(e, "[[link]]: duplicate (openbridge_system, tgid) = ('%s', %d) — links '%s' and '%s'",
                       cfg->link[i].openbridge_system, cfg->link[i].tgid, cfg->link[i].name, cfg->link[j].name);

    /* (cc_remote_ip, cc_lid) unique among INBOUND entries only */
    for (int i = 0; i < cfg->n_link; i++) {
        if (cfg->link[i].cc_role != CC_ROLE_INBOUND) continue;
        for (int j = i + 1; j < cfg->n_link; j++) {
            if (cfg->link[j].cc_role != CC_ROLE_INBOUND) continue;
            if (!strcmp(cfg->link[i].cc_remote_ip, cfg->link[j].cc_remote_ip) &&
                cfg->link[i].cc_lid == cfg->link[j].cc_lid)
                adderr(e, "[[link]]: duplicate inbound (cc_remote_ip, cc_lid) = ('%s', %d) — links '%s' and '%s'",
                       cfg->link[i].cc_remote_ip, cfg->link[i].cc_lid, cfg->link[i].name, cfg->link[j].name);
        }
    }
}

/* Soft check (§6.4): duplicate (cc_remote_ip, cc_remote_port, cc_lid) among
 * OUTBOUND entries is a likely operator typo, not a correctness violation —
 * each outbound entry gets its own dedicated connection regardless.  Logged,
 * not refused; called from main.c after log_init (config_load runs first). */
void config_warn_soft_issues(const Config *cfg)
{
    for (int i = 0; i < cfg->n_link; i++) {
        if (cfg->link[i].cc_role != CC_ROLE_OUTBOUND) continue;
        for (int j = i + 1; j < cfg->n_link; j++) {
            if (cfg->link[j].cc_role != CC_ROLE_OUTBOUND) continue;
            if (!strcmp(cfg->link[i].cc_remote_ip, cfg->link[j].cc_remote_ip) &&
                cfg->link[i].cc_remote_port == cfg->link[j].cc_remote_port &&
                cfg->link[i].cc_lid == cfg->link[j].cc_lid)
                LOGW("config", "links '%s' and '%s' share (cc_remote_ip, cc_remote_port, cc_lid) = "
                     "('%s', %d, %d) — likely operator typo (not an error: each has its own connection)",
                     cfg->link[i].name, cfg->link[j].name,
                     cfg->link[i].cc_remote_ip, cfg->link[i].cc_remote_port, cfg->link[i].cc_lid);
        }
    }
}

int config_load(const char *path, Config *cfg, char *err, size_t errlen)
{
    char perr[256];
    toml *t = toml_parse_file(path, perr, sizeof perr);
    if (!t) { snprintf(err, errlen, "%s", perr); return -1; }

    errbag e; e.buf[0] = 0; e.n = 0;
    memset(cfg, 0, sizeof *cfg);

    /* [global] */
    { static const char *LV[] = {"DEBUG","INFO","WARNING","ERROR"};
      char lvl[16];
      get_choice(t, &e, "global", "log_level", 0, "INFO", LV, 4, lvl, sizeof lvl);
      cfg->log_level = log_level_from_str(lvl);
      if (cfg->log_level < 0) cfg->log_level = LOG_INFO;
    }
    get_str(t, &e, "global", "cc_site_name",     0, "cc2obp",  cfg->cc_site_name,     sizeof cfg->cc_site_name);
    get_str(t, &e, "global", "cc_mac_address",   0, "000000000000", cfg->cc_mac_address, sizeof cfg->cc_mac_address);
    get_str(t, &e, "global", "cc_code_revision", 0, "10252",   cfg->cc_code_revision, sizeof cfg->cc_code_revision);
    get_str(t, &e, "global", "cc_version",       0, "cc2obp",  cfg->cc_version,       sizeof cfg->cc_version);
    get_str(t, &e, "global", "cc_os_version",    0, "Linux",   cfg->cc_os_version,    sizeof cfg->cc_os_version);
    cfg->cc_keepalive_interval = (double)get_int(t, &e, "global", "cc_keepalive_interval", 0, 10, 1, 1, 1, 300);
    cfg->cc_link_timeout       = (double)get_int(t, &e, "global", "cc_link_timeout",       0, 35, 1, 1, 1, 3600);

    load_openbridge(t, &e, cfg);
    load_links(t, &e, cfg);

    toml_free(t);

    if (e.n > 0) {
        snprintf(err, errlen, "Configuration errors:\n%s", e.buf);
        return -1;
    }
    return 0;
}

int config_reload_toggles(const char *path, Config *cfg, char *err, size_t errlen)
{
    Config fresh;
    if (config_load(path, &fresh, err, errlen) != 0)
        return -1;

    for (int i = 0; i < cfg->n_openbridge; i++) {
        int found = 0;
        for (int j = 0; j < fresh.n_openbridge; j++) {
            if (strcmp(cfg->openbridge[i].name, fresh.openbridge[j].name) != 0) continue;
            found = 1;
            if (cfg->openbridge[i].enabled != fresh.openbridge[j].enabled) {
                LOGI("config", "reload: openbridge '%s' enabled %d -> %d",
                     cfg->openbridge[i].name, cfg->openbridge[i].enabled, fresh.openbridge[j].enabled);
                cfg->openbridge[i].enabled = fresh.openbridge[j].enabled;
            }
            /* Any other field difference is out of scope for a toggle-only
             * reload (§6.3) — warn and ignore. */
            if (cfg->openbridge[i].peer_port != fresh.openbridge[j].peer_port ||
                strcmp(cfg->openbridge[i].peer_ip, fresh.openbridge[j].peer_ip) != 0 ||
                cfg->openbridge[i].network_id != fresh.openbridge[j].network_id)
                LOGW("config", "reload: [[openbridge]] '%s' has non-toggle field changes — ignored "
                     "(full reconfiguration requires a restart, §1)", cfg->openbridge[i].name);
            break;
        }
        if (!found)
            LOGW("config", "reload: [[openbridge]] '%s' no longer present in file — ignored "
                 "(removal requires a restart)", cfg->openbridge[i].name);
    }

    for (int i = 0; i < cfg->n_link; i++) {
        int found = 0;
        for (int j = 0; j < fresh.n_link; j++) {
            if (strcmp(cfg->link[i].name, fresh.link[j].name) != 0) continue;
            found = 1;
            if (cfg->link[i].enabled != fresh.link[j].enabled) {
                LOGI("config", "reload: link '%s' enabled %d -> %d",
                     cfg->link[i].name, cfg->link[i].enabled, fresh.link[j].enabled);
                cfg->link[i].enabled = fresh.link[j].enabled;
            }
            if (cfg->link[i].cross_connect_active != fresh.link[j].cross_connect_active) {
                LOGI("config", "reload: link '%s' cross_connect_active %d -> %d",
                     cfg->link[i].name, cfg->link[i].cross_connect_active, fresh.link[j].cross_connect_active);
                cfg->link[i].cross_connect_active = fresh.link[j].cross_connect_active;
            }
            if (cfg->link[i].tgid != fresh.link[j].tgid ||
                cfg->link[i].cc_lid != fresh.link[j].cc_lid ||
                strcmp(cfg->link[i].cc_remote_ip, fresh.link[j].cc_remote_ip) != 0 ||
                cfg->link[i].openbridge_idx != fresh.link[j].openbridge_idx)
                LOGW("config", "reload: [[link]] '%s' has non-toggle field changes — ignored "
                     "(full reconfiguration requires a restart, §1)", cfg->link[i].name);
            break;
        }
        if (!found)
            LOGW("config", "reload: [[link]] '%s' no longer present in file — ignored "
                 "(removal requires a restart)", cfg->link[i].name);
    }

    return 0;
}
