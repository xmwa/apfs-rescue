#!/usr/bin/env python3
"""Convert an old sparse capture (blocks at their natural offsets, index = one block number per
line) into a packed store.   capimg_pack.py <old_image> <new_store>"""
import os, sys
BS = 4096
old, new = sys.argv[1], sys.argv[2]
blocks = [int(x) for x in open(old + '.idx').read().split()]
fi = os.open(old, os.O_RDONLY); fo = os.open(new, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o644)
with open(new + '.idx', 'w') as ix:
    for pos, b in enumerate(blocks):
        os.pwrite(fo, os.pread(fi, BS, b * BS), pos * BS); ix.write('%d %d\n' % (b, pos))
os.fsync(fo)
print('packed %d blocks into %s (%.2f GB)' % (len(blocks), new, len(blocks) * BS / 1e9))
