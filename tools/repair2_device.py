#!/usr/bin/env python3
"""Helpers for writing the second repair to the real drive.

  repair2_device.py compare <device_or_image> <image> [known_ranges_file]
        (known_ranges_file: lines "first_block count"; only these blocks are compared, because
         a sparse image holds zero filler around blocks that were copied one at a time)
        Reads every part of <image> that holds data and compares it with the same blocks of
        <device_or_image>. Prints the number of differing blocks; exit 0 only if identical.
  repair2_device.py diff <image_a> <image_b> <patch> [<patch> ...]
        Checks that the blocks differing between two images are exactly the blocks of the
        given patch files, with the patch contents.
Read-only."""
import os, struct, sys
BS = 4096


def extents(fd, size):
    pos = 0
    while pos < size:
        try:
            d = os.lseek(fd, pos, os.SEEK_DATA)
        except OSError:
            return
        h = os.lseek(fd, d, os.SEEK_HOLE)
        yield d - d % BS, h
        pos = h


def known_extents(path):
    for l in open(path):
        t = l.split()
        if len(t) >= 2:
            yield int(t[0]) * BS, (int(t[0]) + int(t[1])) * BS


def compare(a_path, img_path, collect=None, limit=20, known=None):
    fa = os.open(a_path, os.O_RDONLY); fi = os.open(img_path, os.O_RDONLY)
    size = os.fstat(fi).st_size
    diff = 0; total = 0; shown = 0
    CH = 8 << 20
    for d, h in (known_extents(known) if known else extents(fi, size)):
        pos = d
        while pos < h:
            n = min(CH, h - pos); n -= n % BS
            if n <= 0: break
            x = os.pread(fi, n, pos); y = os.pread(fa, n, pos)
            if len(y) != n:
                raise SystemExit('short read from %s at %d' % (a_path, pos))
            total += n // BS
            if x != y:
                for k in range(0, n, BS):
                    if x[k:k + BS] != y[k:k + BS]:
                        diff += 1
                        b = (pos + k) // BS
                        if collect is not None: collect[b] = (y[k:k + BS], x[k:k + BS])
                        elif shown < limit:
                            print('  differs: block 0x%x' % b); shown += 1
            pos += n
    return diff, total


def read_patch(path):
    data = open(path, 'rb').read()
    assert data[:8] == b'OMAPFIX1'
    off, n = struct.unpack_from('<QI', data, 8)
    out = {}; pos = 20
    for _ in range(n):
        p = struct.unpack_from('<Q', data, pos)[0]; out[p] = data[pos + 8:pos + 8 + BS]; pos += 8 + BS
    return out


def main(a):
    if len(a) in (4, 5) and a[1] == 'compare':
        d, t = compare(a[2], a[3], known=a[4] if len(a) == 5 else None)
        print('compared %d blocks (%.1f GB): %d differ' % (t, t * BS / 1e9, d))
        return 0 if d == 0 else 1
    if len(a) >= 5 and a[1] == 'diff':
        col = {}
        d, t = compare(a[2], a[3], col)
        want = {}
        for p in a[4:]:
            want.update(read_patch(p))
        extra = [b for b in col if b not in want]
        missing = [b for b in want if b not in col and True]
        wrong = [b for b in col if b in want and col[b][1] != want[b]]
        # a patch block identical to the old content does not show up as a difference
        same = [b for b in missing if os.pread(os.open(a[2], os.O_RDONLY), BS, b * BS) == want[b]]
        missing = [b for b in missing if b not in same]
        print('images differ in %d blocks; patch files hold %d blocks; unexpected differences %d, patch blocks not applied %d, wrong content %d'
              % (d, len(want), len(extra), len(missing), len(wrong)))
        return 0 if not (extra or missing or wrong) else 1
    print(__doc__); return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
