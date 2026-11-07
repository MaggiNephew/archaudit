---
command: "ip -j route show"
status: "ok"
tags:
  - "archaudit/raw"
---

# ip route

`ip -j route show` · ok · 0.01s

```text
[{"dst": "default", "gateway": "192.168.1.1", "dev": "wlan0", "protocol": "dhcp"}, {"dst": "192.168.1.0/24", "dev": "wlan0", "protocol": "kernel"}]
```
