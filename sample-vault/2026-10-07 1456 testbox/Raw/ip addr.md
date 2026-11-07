---
command: "ip -j addr show"
status: "ok"
tags:
  - "archaudit/raw"
---

# ip addr

`ip -j addr show` · ok · 0.01s

```text
[{"ifname": "lo", "operstate": "UNKNOWN", "address": "00:00:00:00:00:00", "addr_info": [{"local": "127.0.0.1", "prefixlen": 8}]}, {"ifname": "wlan0", "operstate": "UP", "address": "3c:a9:f4:12:34:56", "addr_info": [{"local": "192.168.1.42", "prefixlen": 24}, {"local": "fe80::1", "prefixlen": 64}]}]
```
