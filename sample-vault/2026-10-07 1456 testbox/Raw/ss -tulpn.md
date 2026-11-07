---
command: "ss -H -tulpn"
status: "ok"
tags:
  - "archaudit/raw"
---

# ss -tulpn

`ss -H -tulpn` · ok · 0.01s

```text
tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 4096 [::]:22 [::]:* users:(("sshd",pid=1,fd=4))
tcp LISTEN 0 511 0.0.0.0:6379 0.0.0.0:* users:(("redis-server",pid=9,fd=6))
tcp LISTEN 0 128 127.0.0.1:631 0.0.0.0:*
udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*
```
