#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Gate G3, the before/after comparison of a write rehearsal.

  g3_compare.py <before_image> <after_image> <before_refs_prefix> <after_refs_prefix> [--names ls_file ...]

W = every block whose content differs between the two images.
Hard checks:
  1. every index node that exists in the after-state with a version from before the rehearsal
     sits at the same block as before and that block is unchanged
  2. no block of W lies inside a file extent that exists unchanged in both states
     (data of files the rehearsal did not touch was not written over)
Reports which pre-existing files lost or changed extents during the rehearsal (should only be
system files that macOS rewrites on a mounted volume)."""
import os, sys, struct, collections
import numpy as np
BS = 4096


def data_extents(fd, size):
    pos = 0
    while pos < size:
        try:
            d = os.lseek(fd, pos, os.SEEK_DATA)
        except OSError:
            break
        h = os.lseek(fd, d, os.SEEK_HOLE)
        yield d, h
        pos = h


def changed_blocks(before, after):
    fa = os.open(after, os.O_RDONLY); fb = os.open(before, os.O_RDONLY)
    size = os.fstat(fa).st_size
    out = []
    CH = 16 << 20
    for d, h in data_extents(fa, size):
        d -= d % BS
        pos = d
        while pos < h:
            n = min(CH, h - pos)
            n -= n % BS
            if n == 0:
                break
            a = np.frombuffer(os.pread(fa, n, pos), dtype=np.uint8).reshape(-1, BS)
            b = np.frombuffer(os.pread(fb, n, pos), dtype=np.uint8).reshape(-1, BS)
            diff = np.nonzero((a != b).any(axis=1))[0]
            if len(diff):
                out.append(diff + pos // BS)
            pos += n
    # blocks present before but turned into holes afterwards do not occur (nothing punches holes)
    return np.concatenate(out) if out else np.zeros(0, dtype=np.int64), fa, fb


def load_nodes(prefix):
    d = {}
    for l in open(prefix + '.nodes'):
        t = l.split()
        d[(t[0], int(t[1], 16))] = (int(t[2], 16), int(t[3], 16), int(t[4], 16))     # (tag, oid) -> (xid, paddr, level)
    return d


def load_ext(prefix):
    s = set()
    for l in open(prefix + '.extents'):
        t = l.split()
        s.add((int(t[0], 16), int(t[1], 16), int(t[2], 16), int(t[3], 16)))
    return s


def main(a):
    names = {}
    if '--names' in a:
        i = a.index('--names')
        for p in a[i + 1:]:
            for l in open(p):
                t = l.split(None, 3)
                if len(t) >= 4 and t[0] == 'N':
                    names[int(t[2])] = t[3].strip()
        del a[i:]
    before, after, pb, pa = a[1:5]
    W, fa, fb = changed_blocks(before, after)
    W = np.unique(W)
    Wset = set(W.tolist())
    print('blocks whose content changed during the rehearsal: %d (%.2f GB)' % (len(W), len(W) * BS / 1e9))
    nb, na = load_nodes(pb), load_nodes(pa)
    xid0 = max(v[0] for v in nb.values())
    print('index nodes before %d, after %d; newest version before the rehearsal: xid %d' % (len(nb), len(na), xid0))
    moved = changed = unknown = kept = 0
    ex = []
    for k, (xid, paddr, lvl) in na.items():
        if xid > xid0:
            continue
        old = nb.get(k)
        if old is None:
            unknown += 1; ex.append(('not present before', k, xid, hex(paddr))); continue
        if old[0] != xid or old[1] != paddr:
            moved += 1; ex.append(('version or block differs', k, xid, hex(paddr), old)); continue
        if paddr in Wset:
            changed += 1; ex.append(('content changed', k, xid, hex(paddr))); continue
        kept += 1
    print('1. old index nodes still in use: %d unchanged; content changed: %d; at a different block: %d; unknown before: %d' % (kept, changed, moved, unknown))
    for e in ex[:10]:
        print('     ', e)
    # also: no changed block may belong to a node of the BEFORE state that is still the live version
    eb, ea = load_ext(pb), load_ext(pa)
    both = eb & ea
    hit = 0; hits = []
    Ws = np.sort(W)
    for fid, lg, p, n in both:
        i = int(np.searchsorted(Ws, p))
        if i < len(Ws) and Ws[i] < p + n:
            hit += 1
            if len(hits) < 10: hits.append((fid, hex(p), n, hex(int(Ws[i]))))
    print('2. file extents present before and after: %d; of these written into during the rehearsal: %d' % (len(both), hit))
    for h in hits:
        print('      file id %d extent %s+%d, changed block %s  %s' % (h[0], h[1], h[2], h[3], names.get(h[0], '')))
    gone = eb - ea
    new = ea - eb
    gid = collections.Counter(); gblk = collections.Counter()
    for fid, lg, p, n in gone:
        gid[fid] += 1; gblk[fid] += n
    print('pre-existing extents no longer referenced: %d in %d files (%d blocks, %.2f GB); new extents: %d (%d blocks)'
          % (len(gone), len(gid), sum(gblk.values()), sum(gblk.values()) * BS / 1e9, len(new), sum(x[3] for x in new)))
    top = sorted(gblk.items(), key=lambda x: -x[1])[:12]
    for fid, n in top:
        print('      file id %d: %d blocks  %s' % (fid, n, names.get(fid, '')))
    ids = sorted(gid)
    if ids:
        print('      file ids of those files: %d .. %d' % (ids[0], ids[-1]))
        open(pa + '.gone-file-ids', 'w').write('\n'.join(str(i) for i in ids) + '\n')
    ok = not (changed or moved or unknown or hit)
    print('RESULT:', 'PASS' if ok else 'FAIL')
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
