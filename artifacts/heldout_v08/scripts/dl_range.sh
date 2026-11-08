#!/bin/bash
# Resumable Google Drive download in verified 512 MB ranges (drive.usercontent.google.com, confirm=t).
# Optional 4th arg: byte offset of the file inside the Drive file (a tar member). Each range must come back as HTTP 206 application/octet-stream with the expected length before it is appended,
# so a quota/HTML page can never end up inside the dump. Backoff on failure. Usage: dl.sh name id total_bytes
name=$1; id=$2; total=$3; base=${4:-0}
dir=/root/darpa/$name; out=$dir/$name.dump; chunk=$dir/.chunk
mkdir -p $dir
CH=$((512*1024*1024)); fails=0; wait=60
URL="https://drive.usercontent.google.com/download?id=$id&export=download&confirm=t"
while :; do
  have=$(stat -c %s $out 2>/dev/null || echo 0)
  [ "$have" -ge "$total" ] && { echo "$(date +%T) $name complete ($have bytes)"; break; }
  free=$(df --output=avail -B1G / | tail -1 | tr -d ' ')
  [ "$free" -lt 27 ] && { echo "$(date +%T) $name: only ${free}G free, stopping"; exit 2; }
  end=$((have+CH-1)); [ $end -ge $total ] && end=$((total-1))
  want=$((end-have+1))
  meta=$(curl -sS -L -A "Mozilla/5.0" --max-time 1800 -r $((base+have))-$((base+end)) -o $chunk -w '%{http_code} %{content_type}' "$URL" 2>&1)
  got=$(stat -c %s $chunk 2>/dev/null || echo 0)
  if [ "${meta%% *}" = 206 ] && echo "$meta" | grep -q octet-stream && [ "$got" -eq "$want" ]; then
    cat $chunk >> $out && rm -f $chunk
    fails=0; wait=60
    echo "$(date +%T) $name $((end+1))/$total"
  else
    fails=$((fails+1))
    echo "$(date +%T) $name range $have-$end failed ($meta, got $got/$want), attempt $fails, sleeping ${wait}s"
    head -c 300 $chunk 2>/dev/null | tr -cd '[:print:]\n' | grep -i -m2 -E "quota|too many|error" ; rm -f $chunk
    [ $fails -ge 40 ] && { echo "$(date +%T) $name: giving up after $fails failures"; exit 1; }
    sleep $wait; wait=$((wait*2)); [ $wait -gt 1800 ] && wait=1800
  fi
done
