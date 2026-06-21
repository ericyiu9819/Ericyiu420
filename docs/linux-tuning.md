# Debian/Ubuntu TCP tuning

These values are deployment starting points for the TCP-only Trojan server. Measure with your own VPS, route, and workload.

```sh
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
sudo sysctl -w net.core.default_qdisc=fq
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

For persistent settings, place the same keys in `/etc/sysctl.d/99-lowprint.conf`.

Use a real certificate for the configured domain. The installer uses `certbot --standalone` by default.
