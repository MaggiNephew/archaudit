---
command: "lsblk -J -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,RO,RM"
status: "ok"
tags:
  - "archaudit/raw"
---

# lsblk

`lsblk -J -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MODEL,RO,RM` · ok · 0.01s

```text
{"blockdevices": [{"name": "nvme0n1", "type": "disk", "size": "953.9G", "fstype": null, "mountpoints": [null], "model": "Samsung SSD 980 PRO 1TB", "children": [{"name": "nvme0n1p1", "type": "part", "size": "1G", "fstype": "vfat", "mountpoints": ["/boot"]}, {"name": "nvme0n1p2", "type": "part", "size": "952.9G", "fstype": "ext4", "mountpoints": ["/"]}]}]}
```
