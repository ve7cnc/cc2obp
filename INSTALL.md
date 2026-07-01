# Installation

`cc2obp` is a single C binary with **no external dependencies** — it links
only against the C standard library. Tested on Debian/Ubuntu; adapt paths for
other distros.

## Requirements

- A C11 compiler (`gcc` or `clang`) and `make`
- git

That's it. There is no Python, no venv, no `pip`, and no third-party
libraries. The TOML parser, HMAC-SHA1, the event loop, and the DMR DSP/FEC
code are all included in the repository and compiled into the binary.

## 1 — Clone and build

```
git clone https://github.com/n0mjs710/cc2obp.git
cd cc2obp
make
```

This produces the `cc2obp` binary in the repo root.

## 2 — Run the self-tests (optional but recommended)

```
make test
```

This validates the DMR DSP/FEC core against golden vectors, the CC-CC AMBE
bit-packing, and two system tests that drive the compiled binary over real
loopback sockets (SSRC collision handling; orphaned-call and
sequence/timestamp-gap behavior).

## 3 — Install (as root)

```
sudo make install
```

This follows the usual system conventions:

| Item    | Destination                       |
|---------|------------------------------------|
| binary  | `/usr/local/bin/cc2obp`           |
| config  | `/etc/cc2obp/cc2obp.toml`         |
| sample  | `/etc/cc2obp/cc2obp.toml.sample`  |
| service | `/lib/systemd/system/cc2obp.service` |

The service runs as **root** (it binds CC-CC's fixed low-numbered ports —
TCP 42421, UDP 42422, UDP 42420 — which on most systems requires either root
or a capability grant). Install paths are overridable:

```
sudo make install PREFIX=/usr SYSCONFDIR=/etc UNITDIR=/etc/systemd/system
```

**Your live config is never clobbered.** `make install` writes
`/etc/cc2obp/cc2obp.toml` only if it does not already exist; on every run it
refreshes `cc2obp.toml.sample` next to it. Re-running `sudo make install`
after a `git pull` updates the binary and unit while leaving your config
untouched.

## 4 — Configure

Edit `/etc/cc2obp/cc2obp.toml`. See `CONFIGURING.md` for a full walkthrough,
including what you'll need to coordinate with the operator at each end of
every link before it will come up.

You can test against the config manually before enabling the service:

```
/usr/local/bin/cc2obp -c /etc/cc2obp/cc2obp.toml --log-level DEBUG
```

Hit Ctrl-C to stop. `--wire` restricts logging to raw CC-CC/OpenBridge hex
dumps if you need to inspect the wire traffic directly.

## 5 — Enable the service

```
sudo systemctl enable --now cc2obp
```

## 6 — Check the logs

```
journalctl -u cc2obp -f
```

## Reloading config toggles without a restart

`[[link]].enabled`, `[[link]].cross_connect_active`, and
`[[openbridge]].enabled` can be flipped in the config file and picked up
without dropping every other link:

```
sudo systemctl reload cc2obp
```

(equivalent to `sudo kill -HUP` the running process). Any other field-level
change in the file is logged at WARNING and ignored — those require a
restart. See `CONFIGURING.md` for what each toggle actually does.

## Updating

```
git pull
make
sudo make install          # updates binary + unit, preserves your config
sudo systemctl restart cc2obp
```

## Uninstalling

```
sudo make uninstall        # removes binary + unit; leaves /etc/cc2obp intact
```

## Development runs

When working in the cloned repo, run the freshly built binary against a
local config without installing:

```
make
./cc2obp -c cc2obp.toml --log-level DEBUG
```
