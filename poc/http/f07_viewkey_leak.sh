#!/bin/sh
# Finding 7 -- private view key placed in a URL rendered into the page.
# No flags required. Substitute a THROWAWAY key; never use a real one.
HOST="${1:-http://127.0.0.1:8081}"
TXHASH="${2:-0000000000000000000000000000000000000000000000000000000000000000}"
ADDR="${3:-4xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}"
VIEWKEY="${4:-0000000000000000000000000000000000000000000000000000000000000001}"

echo "POST /myoutputs -- checking whether the response embeds the view key in a URL"
curl -sS -m 30 -X POST "$HOST/myoutputs" \
  --data-urlencode "tx_hash=$TXHASH" \
  --data-urlencode "xmr_address=$ADDR" \
  --data-urlencode "viewkey=$VIEWKEY" \
  | grep -o 'href="[^"]*myoutputs[^"]*"' | head -5

echo
echo "Expect the shortcut link from src/page.h:2110 / templates/my_outputs.html:81"
echo "to contain the view key -- it then leaks via Referer, history and access logs."
echo
echo "Rendered-in-full variants (need --enable-key-image-checker /"
echo "--enable-output-key-checker) print it directly as '<h4>Viewkey: ...</h4>':"
echo "  POST $HOST/checkrawkeyimgs    rawkeyimgsdata=<b64> viewkey=<key>"
echo "  POST $HOST/checkrawoutputkeys rawoutputkeysdata=<b64> viewkey=<key>"
