#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
import os, struct, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refcheck as rc
src = rc.CaptureSrc(sys.argv[2] if len(sys.argv) > 2 else '-', sys.argv[1])
c = rc.Container(src); sm = rc.Spaceman(c)
croot, cnodes, centries, cprob = rc.read_omap(c, c.omap_oid)
apsb_paddr = max(e for e in centries[c.fs_oids[0]] if e[0] <= c.xid)[3]
apsb = src.block(apsb_paddr); vol_omap = struct.unpack_from('<Q', apsb, 128)[0]
om = src.block(vol_omap); root = struct.unpack_from('<Q', om, 48)[0]
node = {}; ent = collections.defaultdict(list); bytarget = collections.defaultdict(list)
stack = [(root, None)]
while stack:
    p, parent = stack.pop(); b = src.block(p); flags, level, ents = rc.parse_btnode(b)
    node[p] = (level, struct.unpack_from('<Q', b, 16)[0], parent, len(ents))
    for koff, kl, voff, vl in ents:
        if level > 0: stack.append((struct.unpack_from('<Q', b, voff)[0], p))
        else:
            oid, xid = struct.unpack_from('<QQ', b, koff); fl, size, paddr = struct.unpack_from('<IIQ', b, voff)
            ent[oid].append((xid, fl, size, paddr, p))
            if not (fl & 1): bytarget[paddr].append((oid, xid, fl, p))
queued = {}
for xid, p, n in sm.queues['main']['entries']:
    for k in range(p, p + n): queued[k] = xid
both = sorted(p for p in node if p in bytarget)
print('object-map nodes: %d; mappings: %d; blocks that are a node AND a mapping target: %d' % (len(node), sum(len(v) for v in ent.values()), len(both)))
dup = [p for p, v in bytarget.items() if len(v) > 1]
print('blocks that are the target of more than one live mapping: %d %s' % (len(dup), [(hex(p), [(hex(o), x) for o, x, f, l in bytarget[p]]) for p in dup[:5]]))
for p in both:
    lvl, nxid, parent, n = node[p]
    print('block 0x%x: object-map node level %d, written in xid %d, %d entries, parent 0x%x; in release queue: %s' % (p, lvl, nxid, n, parent or 0, queued.get(p)))
    for oid, xid, fl, leaf in bytarget[p]:
        vers = sorted(ent[oid])
        print('    also the target of mapping oid 0x%x xid %d (flags %d), stored in leaf 0x%x; all versions of that oid: %s' % (oid, xid, fl, leaf, [(v[0], v[1], hex(v[3])) for v in vers][:8]))
        tb = src.block(p); print('    the block itself: o_oid 0x%x o_xid %d type 0x%x subtype 0x%x' % (struct.unpack_from('<Q', tb, 8)[0], struct.unpack_from('<Q', tb, 16)[0], struct.unpack_from('<I', tb, 24)[0], struct.unpack_from('<I', tb, 28)[0]))
snaps = []
def snap_leaf(b, ents):
    for koff, kl, voff, vl in ents:
        k = struct.unpack_from('<Q', b, koff)[0]
        if (k >> 60) == 1: snaps.append(k & 0x0FFFFFFFFFFFFFFF)
vol = dict(snapmeta=struct.unpack_from('<Q', apsb, 152)[0])
rc.walk_phys_tree(src, vol['snapmeta'], snap_leaf, 'snap')
snaps.sort(); print('snapshot xids: %d, from %d to %d; volume xid %d' % (len(snaps), snaps[0], snaps[-1], struct.unpack_from('<Q', apsb, 16)[0]))
import bisect
for p in both:
    for oid, xid, fl, leaf in bytarget[p]:
        vers = sorted(v[0] for v in ent[oid]); i = vers.index(xid)
        nxt = vers[i + 1] if i + 1 < len(vers) else None
        # a version (oid, xid) is visible to snapshots with xid <= S < next version's xid, and to the live tree if it is the newest
        vis = [s for s in snaps if s >= xid and (nxt is None or s < nxt)]
        print('    oid 0x%x xid %d: next version %s; snapshots that would use this version: %d %s; used by the live tree: %s' % (oid, xid, nxt, len(vis), vis[:4], nxt is None))
src.close()
