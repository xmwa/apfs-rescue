#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Read-only. For every file-data block that is referenced but not stored (list from refcheck_extra.py):
does it lie inside the file's contents, or in space reserved beyond the end of the file?
  e3_beyond.py <capture spec> <bundle> <part_offset> <hdd_extents> <bands listing> <maps listing> <notstored file>"""
import os, struct, sys, collections, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refcheck as rc
from e3_analyze import listing
BS = 4096; BAND = 8388608; BPB = BAND // BS


def main(a):
    spec, bundle, part_off, hdd_ext, lb, lm, nsf = a[1], a[2], int(a[3]), a[4], a[5], a[6], a[7]
    poff = part_off // BS
    bands = listing(lb); maps = listing(lm)
    miss = sorted({(int(l.split()[0], 16), int(l.split()[1])) for l in open(nsf)})
    need = set()
    for s, n in miss:
        need.update(range((s + poff) // BPB, (s + n - 1 + poff) // BPB + 1))
    ino2band = {bands[b][0]: b for b in need if b in bands}
    ext = collections.defaultdict(list)
    with open(hdd_ext) as f:
        for line in f:
            fid = int(line.split(' ', 1)[0], 16)
            if fid in ino2band:
                u = line.split(); ext[ino2band[fid]].append((int(u[1], 16) // BS, int(u[3], 16)))
    mapbits = {}
    for b in sorted(need):
        if b in maps:
            mapbits[b] = open(os.path.join(bundle, 'mapped', '%x' % b), 'rb').read()

    def situation(p):
        b, o = divmod(p + poff, BPB)
        if b not in bands:
            return 'no piece file'
        host = any(lo <= o < lo + ln for lo, ln in ext[b]) and o * BS < bands[b][1]
        m = mapbits.get(b, b'')
        mapped = True if m == b'' else bool((m[o >> 3] >> (o & 7)) & 1)
        if host and mapped:
            return None
        return ('marked present' if mapped else 'not marked') + (', stored' if host else ', nothing stored')

    _, dev, img = spec.split(':', 2)
    src = rc.CaptureSrc(dev, img); c = rc.Container(src)
    croot, cnodes, centries, cprob = rc.read_omap(c, c.omap_oid)
    xid, fl, size, vp = max(e for e in centries[c.fs_oids[0]] if e[0] <= c.xid)
    apsb = src.block(vp)
    omap_oid, root_oid, ext_oid, snapmeta = struct.unpack_from('<QQQQ', apsb, 128)
    otree = struct.unpack_from('<Q', src.block(omap_oid), 48)[0]
    snaps = []

    def snap_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            k = struct.unpack_from('<Q', b, koff)[0]
            if (k >> 60) == 1:
                e, sb = struct.unpack_from('<QQ', b, voff); snaps.append((k & 0x0FFFFFFFFFFFFFFF, e))
    rc.walk_phys_tree(src, snapmeta, snap_leaf, 'snapmeta'); snaps.sort()
    mset = collections.defaultdict(set)
    for s, n in miss:
        mset[s].add(n)
    found = []
    for sx, e in snaps + [(c.xid, ext_oid)]:
        def ext_leaf(b, ents, sx=sx):
            for koff, kl, voff, vl in ents:
                k = struct.unpack_from('<Q', b, koff)[0]
                if (k >> 60) == 2:
                    st = k & 0x0FFFFFFFFFFFFFFF
                    if st in mset:
                        lk, owner, refc = struct.unpack_from('<QQi', b, voff)
                        if (lk & 0x0FFFFFFFFFFFFFFF) in mset[st]:
                            found.append((st, lk & 0x0FFFFFFFFFFFFFFF, sx, owner, refc, lk >> 60))
        rc.walk_phys_tree(src, e, ext_leaf, 'ext')
    print('not fully stored extent records: %d (of %d listed ranges)' % (len(found), len(miss)))
    ocache = {}

    def omap_get(oid, at):
        key = (oid, at)
        if key in ocache:
            return ocache[key]
        p = otree; res = None
        while True:
            b = src.block(p); flags, level, ents = rc.parse_btnode(b)
            lo, hi = 0, len(ents)
            while lo < hi:
                mid = (lo + hi) // 2
                if struct.unpack_from('<QQ', b, ents[mid][0]) <= (oid, at):
                    lo = mid + 1
                else:
                    hi = mid
            if lo == 0:
                break
            koff, kl, voff, vl = ents[lo - 1]
            if level > 0:
                p = struct.unpack_from('<Q', b, voff)[0]
            else:
                if struct.unpack_from('<Q', b, koff)[0] == oid:
                    f, sz, paddr = struct.unpack_from('<IIQ', b, voff)
                    res = None if f & 1 else paddr
                break
        ocache[key] = res
        return res

    def fs_scan(at, oid, typ):
        """all records with (oid, typ) in the file index as of xid 'at': [(key bytes, value bytes)]"""
        out = []
        stack = [omap_get(root_oid, at)]
        while stack:
            p = stack.pop()
            if p is None:
                continue
            b = src.block(p)
            if not rc.valid(b):
                out.append(None); continue
            flags, level, ents = rc.parse_btnode(b)
            ks = []
            for koff, kl, voff, vl in ents:
                k = struct.unpack_from('<Q', b, koff)[0]; ks.append((k & 0x0FFFFFFFFFFFFFFF, k >> 60))
            if level > 0:
                for i, (koff, kl, voff, vl) in enumerate(ents):
                    if ks[i] <= (oid, typ) and (i + 1 == len(ents) or ks[i + 1] >= (oid, typ)) or (i == 0 and ks[0] > (oid, typ)):
                        stack.append(omap_get(struct.unpack_from('<Q', b, voff)[0], at))
                    elif ks[i] == (oid, typ):
                        stack.append(omap_get(struct.unpack_from('<Q', b, voff)[0], at))
            else:
                for i, (koff, kl, voff, vl) in enumerate(ents):
                    if ks[i] == (oid, typ):
                        out.append((b[koff:koff + kl], b[voff:voff + vl]))
        return out

    def inode_info(at, oid):
        r = [x for x in fs_scan(at, oid, 3) if x]
        if not r:
            return None
        v = r[0][1]
        parent, private = struct.unpack_from('<QQ', v, 0)
        name = None; size = None; alloc = None
        if len(v) > 96:
            nx, used = struct.unpack_from('<HH', v, 92); pos = 96 + 4 * nx
            for i in range(nx):
                xt, xf, xs = struct.unpack_from('<BBH', v, 96 + 4 * i); d = v[pos:pos + xs]
                if xt == 4:
                    name = d.split(b'\0')[0].decode('utf8', 'replace')
                elif xt == 8 and xs >= 16:
                    size, alloc = struct.unpack_from('<QQ', d, 0)
                pos += (xs + 7) & ~7
        return parent, private, name, size, alloc

    tot = collections.Counter(); files_inside = collections.defaultdict(lambda: [0, None]); t0 = time.time()
    noinode = collections.Counter(); fx_cache = {}
    byowner = collections.defaultdict(list)
    for st, n, sx, owner, refc, kind in found:
        byowner[(owner, sx)].append((st, n))
    done = 0
    for (owner, sx), rs in sorted(byowner.items()):
        ino = inode_info(sx, owner)
        fx = []
        for k, v in [x for x in fs_scan(sx, owner, 8) if x]:
            logical = struct.unpack_from('<Q', k, 8)[0]
            lf, phys = struct.unpack_from('<QQ', v, 0)
            fx.append((phys, (lf & 0x00FFFFFFFFFFFFFF) // BS, logical))
        fx.sort()
        size = ino[3] if ino and ino[3] is not None else None
        for st, n in rs:
            for p in range(st, st + n):
                sit = situation(p)
                if sit is None:
                    continue
                where = 'not part of the file as of that backup'
                for phys, ln, logical in fx:
                    if phys <= p < phys + ln:
                        off = logical + (p - phys) * BS
                        if size is None:
                            where = 'in the file, size unknown (no inode under this id)'
                        elif off >= size:
                            where = 'reserved space beyond the end of the file'
                        else:
                            where = 'INSIDE the file contents'
                            f = files_inside[(owner, sx)]; f[0] += 1; f[1] = (ino[2], size, off) if f[1] is None else f[1]
                        break
                tot[(where, sit)] += 1
                if size is None:
                    noinode[owner] += 1
        done += 1
        if time.time() - t0 > 60:
            t0 = time.time(); print('   ... %d of %d owners' % (done, len(byowner))); sys.stdout.flush()
    print('missing blocks (counted once per extent record):')
    for (where, sit), v in sorted(tot.items(), key=lambda kv: -kv[1]):
        print('   %9d  %-52s %s' % (v, where, sit))
    print('files with missing blocks INSIDE their contents: %d' % len(files_inside))
    for (owner, sx), (cnt, info) in sorted(files_inside.items(), key=lambda kv: -kv[1][0])[:40]:
        print('   id %d as of xid %d: %d blocks; %s size %d first at offset %d' % (owner, sx, cnt, info[0], info[1], info[2]))
    print('owners without an inode under their id: %s' % ', '.join('%d: %d blocks' % kv for kv in noinode.most_common(10)))
    src.close()


if __name__ == '__main__':
    main(sys.argv)
