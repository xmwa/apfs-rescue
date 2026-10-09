#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""band_vs_device.py <bundle> <part_offset> <raw partition device> <refs file>

Compares what the attached image returns for blocks inside given bands with what the band
files on the disk hold. The refs file has lines 'band_hex start_block_hex nblocks class'
(as written by the bands5 scratch script). Read-only on both sides. Reports, per band and
class: blocks identical, blocks where the device returned zeros while the band holds data,
blocks that differ otherwise."""
import os, sys, collections
BS = 4096
BAND = 8 * 1024 * 1024
BPB = BAND // BS
bundle, part_off, dev, refs = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
fd = os.open(dev, os.O_RDONLY)
stats = collections.defaultdict(collections.Counter)
bands = {}
with open(refs) as f:
    for line in f:
        b, start, n, cls = line.split(None, 3)
        cls = cls.strip(); start = int(start, 16); n = int(n)
        bi = int(b, 16)
        if b not in bands:
            try:
                bands[b] = open(os.path.join(bundle, 'bands', b), 'rb')
            except OSError as e:
                bands[b] = None; print('band %s: %s' % (b, e))
        bf = bands[b]
        for k in range(start, start + n):
            d = os.pread(fd, BS, k * BS)      # the device is the partition itself; part_off only matters for the band offset
            inb = part_off + k * BS - bi * BAND     # image offset of the block, inside its band
            w = b''
            if bf is not None:
                bf.seek(inb); w = bf.read(BS)
            if len(w) < BS:
                w = w + b'\0' * (BS - len(w)); stats[(b, cls)]['beyond band end'] += 1
            if d == w:
                stats[(b, cls)]['identical' if any(w) else 'identical (both zero)'] += 1
            elif not any(d):
                stats[(b, cls)]['device zeros, band has data'] += 1
            else:
                stats[(b, cls)]['differ'] += 1
for (b, cls), c in sorted(stats.items()):
    print('band %s %-12s %s' % (b, cls, dict(c)))
