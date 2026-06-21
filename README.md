# Lowprint Trojan Server

Minimal TCP-only Trojan over TLS server for direct Shadowrocket import.

## Build

```sh
cargo build --release --bin proxy-server
```

## Run

```sh
proxy-server --config examples/server.toml check-config
proxy-server --config /etc/lowprint/server.toml
```

## Install

```sh
cargo build --release --bin proxy-server
sudo bash scripts/install-trojan.sh \
  --domain example.com \
  --email admin@example.com \
  --password 'change-me-long-random-password'
```

Print the Shadowrocket import link again at any time:

```sh
proxy-server --config /etc/lowprint/server.toml uri
```

The server logs operational events and byte counts only. It does not log requested target domains or target IP addresses.
