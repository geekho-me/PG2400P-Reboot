# TP-Link PG2400P Reboot Script

## Introduction

This script is used to automate the reboot of the TP-Link PG2400P G.hn2400 Powerline Kit.

See related [blogpost](https://geekho.me/posts/tp-link-pg2400p-reboot-script/).

## Usage

```bash
john@GeekHome:~$ python router_reboot.py --ip 192.168.1.101 --password MyStrongPassword
[+] Target router: http://192.168.1.101
[+] Preflight warm-up...
[+] Logging in...
[+] TOKEN obtained.
[+] Sending reboot command...
[+] Reboot command accepted (ERROR=000). The router should be rebooting now.
```

## Compatibility

Tested working on:

* TP-Link [PG200P Kit](https://www.tp-link.com/uk/home-networking/powerline/pg2400p-kit/) G.hn2400 Passthrough Powerline Kit
  * Firmware `1.1.0 Build 20250710 Rel.56841`
