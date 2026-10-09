#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Read-only analysis of the 'referenced but not stored' file-data blocks that refcheck_extra.py (E3)
reports for an image in a sparse bundle: where they lie, which backups and files they belong to.
  e3_analyze.py <capture spec> <bundle> <part_offset> <hdd_extents> <bands listing> <maps listing> <notstored file>"""
import os, struct, sys, collections, bisect, re, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refcheck as rc
BS = 4096; BAND = 8388608; BPB = BAND // BS


def listing(path):
    out = {}; cur = None
    for line in open(path, errors='replace'):
        m = re.match(r'\s+file id=(\d+)\s+size=(\d+)\s+(\S+)', line)
        if m:
            try:
                cur = int(m.group(3), 16)
            except ValueError:
                cur = None; continue
            out[cur] = [int(m.group(1)), int(m.group(2)), '', '']
            continue
        m = re.match(r'\s+created (\S+ \S+)\s+modified (\S+ \S+)', line)
        if m and cur is not None:
            out[cur][2], out[cur][3] = m.group(1), m.group(2)
    return out


def main(a):
    spec, bundle, part_off, hdd_ext, lb, lm, nsf = a[1], a[2], int(a[3]), a[4], a[5], a[6], a[7]
    poff = part_off // BS
    bands = listing(lb); maps = listing(lm)
    print('bands listed %d, maps listed %d' % (len(bands), len(maps)))
    miss = []
    for line in open(nsf):
        t = line.split(); miss.append((int(t[0], 16), int(t[1])))
    miss.sort()
    need = set()
    for s, n in miss:
        for b in range((s + poff) // BPB, (s + n - 1 + poff) // BPB + 1):
            need.add(b)
    print('not fully stored ranges: %d covering %d blocks, touching %d pieces' % (len(miss), sum(n for s, n in miss), len(need)))
    ino2band = {bands[b][0]: b for b in need if b in bands}
    ext = collections.defaultdict(list)
    with open(hdd_ext) as f:
        for line in f:
            t = line.split(' ', 1)
            fid = int(t[0], 16)
            if fid in ino2band:
                u = line.split(); ext[ino2band[fid]].append((int(u[1], 16) // BS, int(u[3], 16)))
    cat = collections.Counter(); per_band = collections.defaultdict(collections.Counter)
    mapbits = {}
    for b in sorted(need):
        if b in maps:
            try:
                mapbits[b] = open(os.path.join(bundle, 'mapped', '%x' % b), 'rb').read()
            except OSError:
                mapbits[b] = None
    for s, n in miss:
        for p in range(s, s + n):
            ib = p + poff; b, o = divmod(ib, BPB)
            if b not in bands:
                k = 'piece file does not exist'
            else:
                host = any(lo <= o < lo + ln for lo, ln in ext[b])
                beyond = o * BS >= bands[b][1]
                m = mapbits.get(b, b'')
                mapped = True if m == b'' else (m is not None and len(m) == 256 and bool((m[o >> 3] >> (o & 7)) & 1))
                if host and mapped and not beyond:
                    continue
                k = ('marked present' if mapped else 'not marked present') + ', ' + ('beyond the end of the piece file' if beyond else ('real block on the HDD' if host else 'no block on the HDD (hole)'))
            cat[k] += 1; per_band[b][k] += 1
    print('missing blocks by situation:')
    for k, v in cat.most_common():
        print('   %9d  %s' % (v, k))
    # the pieces involved: when were they last changed
    by_month = collections.Counter(); by_month_blocks = collections.Counter()
    for b, c in per_band.items():
        mt = bands[b][3][:7] if b in bands else 'no file'
        by_month[mt] += 1; by_month_blocks[mt] += sum(c.values())
    print('pieces involved by month of last change (pieces, missing blocks):')
    for k in sorted(by_month):
        print('   %s  %6d  %9d' % (k, by_month[k], by_month_blocks[k]))
    allm = collections.Counter(v[3][:7] for v in bands.values())
    print('all pieces by month of last change:', ', '.join('%s: %d' % kv for kv in sorted(allm.items())))
    short = [b for b in per_band if b in bands and bands[b][1] < BAND]
    print('involved pieces that are shorter than a full piece: %d of %d short pieces in the bundle' % (len(short), sum(1 for v in bands.values() if v[1] < BAND)))

    # which backups and files own these extents
    _, dev, img = spec.split(':', 2)
    src = rc.CaptureSrc(dev, img); c = rc.Container(src)
    croot, cnodes, centries, cprob = rc.read_omap(c, c.omap_oid)
    xid, fl, size, vp = max(e for e in centries[c.fs_oids[0]] if e[0] <= c.xid)
    apsb = src.block(vp)
    omap_oid, root_oid, ext_oid, snapmeta = struct.unpack_from('<QQQQ', apsb, 128)
    om = src.block(omap_oid); otree = struct.unpack_from('<Q', om, 48)[0]
    snaps = []

    def snap_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            k = struct.unpack_from('<Q', b, koff)[0]
            if (k >> 60) == 1:
                e, sb = struct.unpack_from('<QQ', b, voff)
                ct = struct.unpack_from('<Q', b, voff + 24)[0]
                nl = struct.unpack_from('<H', b, voff + 48)[0]
                snaps.append((k & 0x0FFFFFFFFFFFFFFF, e, sb, time.strftime('%Y-%m-%d', time.localtime(ct / 1e9)), b[voff + 50:voff + 50 + nl - 1].decode('utf8', 'replace')))
    rc.walk_phys_tree(src, snapmeta, snap_leaf, 'snapmeta')
    snaps.sort()
    mset = {s: n for s, n in miss}
    found = {}
    for sx, e, sb, day, name in snaps + [(1 << 62, ext_oid, vp, 'current', 'current state')]:
        def ext_leaf(b, ents, sx=sx):
            for koff, kl, voff, vl in ents:
                k = struct.unpack_from('<Q', b, koff)[0]
                if (k >> 60) == 2:
                    st = k & 0x0FFFFFFFFFFFFFFF
                    if st in mset:
                        lk, owner, refc = struct.unpack_from('<QQi', b, voff)
                        if (lk & 0x0FFFFFFFFFFFFFFF) == mset[st]:
                            found[st] = (sx, owner, refc, lk >> 60)
        rc.walk_phys_tree(src, e, ext_leaf, 'ext')
    lackof = {}
    for line in open(nsf):
        t = line.split(); lackof[int(t[0], 16)] = int(t[-1])
    print('ranges matched to an extent record: %d of %d' % (len(found), len(miss)))
    label = {sx: '%s %s' % (day, name) for sx, e, sb, day, name in snaps}; label[1 << 62] = 'current state (after the last backup)'
    bys = collections.Counter(); bysb = collections.Counter(); owners = collections.defaultdict(lambda: [0, 0, 0, 0])
    for st, (sx, owner, refc, kind) in found.items():
        bys[sx] += 1; bysb[sx] += lackof[st]
        o = owners[owner]; o[0] += 1; o[1] += lackof[st]; o[2] += mset[st]; o[3] = max(o[3], sx)
    print('first backup that holds the extent (ranges, missing blocks):')
    for sx in sorted(bys):
        print('   %-48s %6d %9d' % (label[sx][:48], bys[sx], bysb[sx]))
    print('distinct owning files: %d' % len(owners))

    # names of the biggest owners, looked up in the file index as of the backup that holds them
    def omap_get(oid, at):
        p = otree
        while True:
            b = src.block(p); flags, level, ents = rc.parse_btnode(b)
            best = None
            for koff, kl, voff, vl in ents:
                ko, kx = struct.unpack_from('<QQ', b, koff)
                if (ko, kx) <= (oid, at):
                    best = (ko, kx, voff)
                else:
                    break
            if best is None:
                return None
            if level > 0:
                p = struct.unpack_from('<Q', b, best[2])[0]
            else:
                if best[0] != oid:
                    return None
                f, sz, paddr = struct.unpack_from('<IIQ', b, best[2])
                return None if f & 1 else paddr

    def fs_get(root, at, oid, typ):
        """records of (oid, typ) in the file index as of xid 'at' (first matching leaf only)"""
        p = omap_get(root, at)
        while p is not None:
            b = src.block(p)
            if not rc.valid(b):
                return None
            flags, level, ents = rc.parse_btnode(b)
            if level > 0:
                best = None
                for koff, kl, voff, vl in ents:
                    k = struct.unpack_from('<Q', b, koff)[0]
                    if ((k & 0x0FFFFFFFFFFFFFFF), k >> 60) <= (oid, typ):
                        best = voff
                    else:
                        break
                if best is None:
                    best = ents[0][2]
                p = omap_get(struct.unpack_from('<Q', b, best)[0], at)
            else:
                for koff, kl, voff, vl in ents:
                    k = struct.unpack_from('<Q', b, koff)[0]
                    if (k & 0x0FFFFFFFFFFFFFFF) == oid and (k >> 60) == typ:
                        return b[voff:voff + vl]
                return None
        return None

    def inode(root, at, oid):
        v = fs_get(root, at, oid, 3)
        if v is None or len(v) < 92:
            return None
        parent, private = struct.unpack_from('<QQ', v, 0)
        mtime = struct.unpack_from('<Q', v, 24)[0]
        name = None; size = None; alloc = None; sparse = None
        if len(v) > 96:
            nx, used = struct.unpack_from('<HH', v, 92)
            pos = 96 + 4 * nx
            for i in range(nx):
                xt, xf, xs = struct.unpack_from('<BBH', v, 96 + 4 * i)
                d = v[pos:pos + xs]
                if xt == 4:
                    name = d.split(b'\0')[0].decode('utf8', 'replace')
                elif xt == 8 and xs >= 16:
                    size, alloc = struct.unpack_from('<QQ', d, 0)
                elif xt == 13 and xs >= 8:
                    sparse = struct.unpack_from('<Q', d, 0)[0]
                pos += (xs + 7) & ~7
        return parent, name, size, alloc, mtime, sparse

    def path(root, at, oid):
        parts = []; first = None
        for _ in range(40):
            r = inode(root, at, oid)
            if r is None:
                parts.append('?'); break
            if first is None:
                first = r
            parts.append(r[1] or '?')
            if r[0] in (1, 2) or r[0] == oid:
                break
            oid = r[0]
        return '/'.join(reversed(parts)), first

    top = sorted(owners.items(), key=lambda kv: -kv[1][1])
    print('largest owners (missing blocks / blocks in those extents / ranges; file size, allocated; path as of the backup):')
    exts = collections.Counter(); tot_named = 0
    for owner, (nr, lack, tot, sx) in top[:int(os.environ.get('E3_TOP', '40'))]:
        at = c.xid if sx == 1 << 62 else sx
        try:
            pth, ino = path(root_oid, at, owner)
        except Exception as ex:
            pth, ino = 'lookup failed: %r' % ex, None
        print('   %8d / %8d / %4d   %s   %s   [%s]' % (lack, tot, nr, ('size %d alloc %d%s' % (ino[2] or 0, ino[3] or 0, (' sparse bytes %d' % ino[5]) if ino[5] else '')) if ino else 'no inode found', pth[-150:], label[sx][:10]))
    src.close()


if __name__ == '__main__':
    main(sys.argv)
