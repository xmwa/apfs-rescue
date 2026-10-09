#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["numpy"]
# ///
"""leftover_scan.py <capture spec> [--out file]

Reads every object-map mapping of the (unencrypted) volume that no live backup can see any
more (old versions the deleted backups' cleanup has not removed) and looks at the block each
one points at: does it still hold that object, has it been reused by another object, or is
it unreadable. Read-only. Also says, for each, whether the pending cleanup will still visit
it (object id at or after the reaper's position) or has passed it."""
import sys, struct, collections, time
import numpy as np
sys.path.insert(0, __import__('os').path.dirname(__import__('os').path.abspath(__file__)))
import refcheck as rc
BS = 4096
a = sys.argv[1:]
out = None
if '--out' in a:
    i = a.index('--out'); out = a[i + 1]; del a[i:i + 2]
spec = a[0]
if spec.startswith('capture:'):
    _, dev, img = spec.split(':', 2)
    src = rc.CaptureSrc(dev, img)
else:
    src = rc.Src([spec])
c = rc.Container(src)
croot, cn, cent, _ = rc.read_omap(c, c.omap_oid)
x, fl, size, vp = max(cent[c.fs_oids[0]])
vsb = src.block(vp)
vomap = struct.unpack_from('<Q', vsb, 128)[0]
om = src.block(vomap)
oroot, snap_tree = struct.unpack_from('<QQ', om, 48)
# live snapshot xids = object-map snapshot tree entries not marked deleted
live = []
def sl(b, ents):
    for koff, kl, voff, vl in ents:
        xid = struct.unpack_from('<Q', b, koff)[0]; flags = struct.unpack_from('<I', b, voff)[0]
        if not (flags & 1):
            live.append(xid)
rc.walk_phys_tree(src, snap_tree, sl, 'snapshot tree')
liv = np.array(sorted(live), dtype=np.int64)
# reaper position (if a cleanup is pending)
pos = None
try:
    rp = c.eph_obj(c.reaper_oid)
    cl, omsf, sprev, sstart, send, snext, koid, kxid = struct.unpack_from('<IIQQQQQQ', rp, 112)
    if cl:
        pos = koid
except Exception:
    pass
keys = []
def leaf(b, ents):
    for koff, kl, voff, vl in ents:
        oid, xx = struct.unpack_from('<QQ', b, koff)
        fl, sz, paddr = struct.unpack_from('<IIQ', b, voff)
        if not (fl & 1):
            keys.append((oid, xx, paddr))
rc.walk_phys_tree(src, oroot, leaf, 'object map')
K = np.array(keys, dtype=np.int64).reshape(-1, 3); del keys
K = K[np.lexsort((K[:, 1], K[:, 0]))]
nxt = np.full(len(K), 1 << 62, dtype=np.int64)
same = K[1:, 0] == K[:-1, 0]
nxt[:-1][same] = K[1:, 1][same]
j = np.searchsorted(liv, K[:, 1], side='left')
seen = (j < len(liv)) & (liv[np.minimum(j, len(liv) - 1)] < nxt)
unseen = ~seen & (nxt != (1 << 62))
idx = np.flatnonzero(unseen)
print('mappings %d, live backups %d, left-over old versions %d, reaper position %s' % (len(K), len(liv), len(idx), ('0x%x' % pos) if pos is not None else 'none'))
res = collections.Counter()
lines = []
t = time.time()
for n, k in enumerate(sorted(idx, key=lambda k: int(K[k, 2]))):
    oid, xx, p = (int(v) for v in K[k])
    where = 'ahead' if (pos is not None and oid >= pos) else 'behind'
    try:
        b = src.block(p)
    except KeyError:
        res[(where, 'unreadable')] += 1; lines.append('0x%x %d 0x%x %s unreadable' % (oid, xx, p, where)); continue
    o, x2, typ, sub = struct.unpack_from('<QQII', b, 8)
    if not rc.valid(b):
        what = 'bad checksum'
    elif o == oid and x2 == xx:
        what = 'still holds the object'
    else:
        what = 'reused: oid 0x%x xid %d type 0x%x sub 0x%x' % (o, x2, typ, sub)
    res[(where, what.split(':')[0])] += 1
    lines.append('0x%x %d 0x%x %s %s' % (oid, xx, p, where, what))
    if time.time() - t > 30:
        t = time.time(); print('   ... %d of %d read' % (n + 1, len(idx))); sys.stdout.flush()
for (where, what), n in sorted(res.items()):
    print('%-7s %-24s %d' % (where, what, n))
if out:
    with open(out, 'w') as f:
        f.write('\n'.join(lines) + '\n')
