#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Apply OMAPFIX1 patch files to a packed capture store (store + .idx).
  capimg_apply.py <store> <patch> [<patch> ...]"""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refcheck as rc
BS = 4096
src = rc.CaptureSrc('-', sys.argv[1]); n0 = len(src.have); n = 0
for p in sys.argv[2:]:
    d = open(p, 'rb').read(); assert d[:8] == b'OMAPFIX1'
    off, cnt = struct.unpack_from('<QI', d, 8); pos = 20
    for _ in range(cnt):
        b = struct.unpack_from('<Q', d, pos)[0]; src.put(b, d[pos + 8:pos + 8 + BS]); pos += 8 + BS; n += 1
src.close()
print('applied %d blocks to %s (%d new in the index)' % (n, sys.argv[1], len(src.have) - n0))
