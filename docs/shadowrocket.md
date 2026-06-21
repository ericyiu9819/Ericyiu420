# Shadowrocket direct mode

Shadowrocket connects directly to this server over TCP/TLS using Trojan.

## Install on Debian/Ubuntu

```sh
cargo build --release --bin proxy-server
sudo bash scripts/install-trojan.sh \
  --domain example.com \
  --email admin@example.com \
  --password 'change-me-long-random-password'
```

The script requests an ACME certificate with `certbot --standalone`, writes `/etc/lowprint/server.toml`, installs a systemd service, and prints a `trojan://` URI.

## Import into Shadowrocket

Copy the printed URI into Shadowrocket:

```text
trojan://PASSWORD@example.com:443?sni=example.com#lowprint-example.com
```

## Operations

```sh
sudo systemctl status lowprint-trojan.service
sudo journalctl -u lowprint-trojan.service -f
sudo certbot renew --dry-run
proxy-server --config /etc/lowprint/server.toml uri
```

The server logs operational events and byte counts only. It does not log target domains or target IP addresses.
