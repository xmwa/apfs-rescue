#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Extra read-only checks of an unencrypted APFS container inside a sparse bundle. They cover what
neither refcheck.py (ownership) nor 'fsck_apfs -n -S' (current state only) looks at.

  refcheck_extra.py <capture spec> <bundle> <part_offset> <hdd_extents_file> [--sample N] [--reloc-map f] [--out f]

<capture spec>     capture:<device or ->:<packed store>   (as for refcheck.py)
<hdd_extents_file>  hdd-refs-<tag>.extents of the HDD itself, taken while nothing wrote to the HDD since

E1  nothing is pending that a writable mount would act on (reaper, reverts, object-map flags) and the
    object map's own snapshot list matches the volume's snapshot list (else old versions get cleaned)
E2  exact accounting: every allocated block is referenced, or in a known reserved area, or queued
E3  every referenced block is really stored: its band file exists, is long enough, is marked present
    in the band's map and has real blocks behind it on the HDD (no hole)
E4  every backup has a readable entry point (superblock, file-index root), and a random sample of all
    index nodes of all backups (plus every node the fix moved) is intact and is what the object map says
"""
import os, struct, sys, time, random, collections
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import refcheck as rc

BS = 4096
BAND = 8388608
BPB = BAND // BS


def main(a):
    out_path = None
    nsample = 60000
    reloc_map = None
    if '--out' in a:
        i = a.index('--out'); out_path = a[i + 1]; del a[i:i + 2]
    if '--sample' in a:
        i = a.index('--sample'); nsample = int(a[i + 1]); del a[i:i + 2]
    if '--reloc-map' in a:
        i = a.index('--reloc-map'); reloc_map = a[i + 1]; del a[i:i + 2]
    lst = None
    if '--listing' in a:          # offline listings of bands/ and mapped/ made with apfs-ls from the HDD's index copy
        i = a.index('--listing'); lst = (a[i + 1], a[i + 2]); del a[i:i + 3]
    skip_e3 = '--skip-e3' in a
    if skip_e3:
        a.remove('--skip-e3')
    spec, bundle, part_off, hdd_ext = a[1], a[2], int(a[3]), a[4]
    assert part_off % BS == 0
    lines = []
    hard = collections.OrderedDict()
    soft = collections.OrderedDict()
    t0 = time.time()

    def say(s=''):
        print(s); lines.append(s); sys.stdout.flush()

    _, dev, img = spec.split(':', 2)
    src = rc.CaptureSrc(dev, img)
    c = rc.Container(src)
    say('container save point xid %d, %d blocks' % (c.xid, c.block_count))
    sm = rc.Spaceman(c)
    bm = sm.load_bitmap()

    # ---------------- volume -----------------------------------------------------------------
    croot, cnodes, centries, cprob = rc.read_omap(c, c.omap_oid)
    R = [(p, 1, 6) for p in cnodes] + [(c.omap_oid, 1, 8)]
    fs = c.fs_oids[0]
    xid, fl, size, vpaddr = max(e for e in centries[fs] if e[0] <= c.xid)
    apsb = src.block(vpaddr)
    assert apsb[32:36] == b'APSB' and rc.valid(apsb)
    R.append((vpaddr, 1, 7))
    vol = dict(paddr=vpaddr, xid=struct.unpack_from('<Q', apsb, 16)[0], alloc_count=struct.unpack_from('<Q', apsb, 88)[0])
    vol['omap_oid'], vol['root_tree_oid'], vol['extentref_oid'], vol['snapmeta_oid'] = struct.unpack_from('<QQQQ', apsb, 128)
    revert_xid, revert_sb = struct.unpack_from('<QQ', apsb, 160)
    num_snaps = struct.unpack_from('<Q', apsb, 216)[0]
    fs_flags = struct.unpack_from('<Q', apsb, 264)[0]

    # ---------------- E1: pending work --------------------------------------------------------
    say(''); say('E1 pending work and snapshot lists')
    cleanup = None
    try:
        rp = c.eph_obj(c.reaper_oid)
    except KeyError:
        rp = None; say('   reaper: its block is not in the local store (offline run), skipped')
    if rp is not None:
        nxt, done, head, tail, rflags, rlcount, rtype, rsize, rfs, roid, rxid, nrle, sbs = struct.unpack_from('<QQQQIIIIQQQII', rp, 32)
        busy = head != 0 or tail != 0 or (rflags & 2) != 0 or roid != 0
        say('   reaper: next id %d, completed id %d, list count %d, flags 0x%x, object in work: type 0x%x oid 0x%x xid %d, entry flags 0x%x'
            % (nxt, done, rlcount, rflags, rtype, roid, rxid, nrle))
        if busy and (rtype & 0xffff) == 0xb and (nrle & 0x10) and rfs == fs and sbs >= 56:
            cl, omsf, sprev, sstart, send, snext, koid, kxid = struct.unpack_from('<IIQQQQQQ', rp, 112)
            if cl == 0 and sstart == 0 and send == 0 and (rflags & 2) == 0:
                say('   -> the reaper holds a finished object-map cleanup (last one between xids %d and %d); nothing is pending.' % (sprev, snext))
                hard['E1 reaper has other work pending'] = 0
            else:
                cleanup = (sprev, sstart, send, snext, koid)
                say('   -> a cleanup after deleting the backup(s) at xid %d..%d is in progress (neighbours %d and %d); it has reached object id 0x%x. A writable mount will continue it.'
                    % (sstart, send, sprev, snext, koid))
                soft['E1 cleanup of a deleted backup pending'] = 1
                hard['E1 reaper has other work pending'] = 0
        else:
            hard['E1 reaper has other work pending'] = int(busy)
    say('   volume: revert-to xid %d, revert-to superblock 0x%x, snapshots counted %d, flags 0x%x' % (revert_xid, revert_sb, num_snaps, fs_flags))
    hard['E1 volume revert pending'] = int(revert_xid != 0 or revert_sb != 0)
    for label, opaddr in (('container', c.omap_oid), ('volume', vol['omap_oid'])):
        om = src.block(opaddr)
        oflags, osnapcount = struct.unpack_from('<II', om, 32)
        otree, osnaptree, orecent, prmin, prmax = struct.unpack_from('<QQQQQ', om, 48)
        say('   %s object map: flags 0x%x, snapshot count %d, most recent snapshot xid %d, pending revert %d..%d' % (label, oflags, osnapcount, orecent, prmin, prmax))
        hard['E1 %s object map busy (flags or revert)' % label] = int((oflags & 0xE) != 0 or prmin != 0 or prmax != 0)
        if label == 'volume':
            vol_om = (osnapcount, osnaptree, orecent)
    q = sm.queues['tier2']
    hard['E1 second-tier queue in use'] = int(bool(q['entries']) or q['count'] != 0)
    hard['E1 chunk counts disagree with bitmap'] = sm.chunks_with_bad_count
    nbits = 0
    for i in range(0, len(bm), 1 << 24):
        nbits += int(np.unpackbits(bm[i:i + (1 << 24)], bitorder='little').sum())
    allocated = nbits
    hard['E1 free counts disagree'] = int(not (sm.free_count == sm.sum_chunk_free == sm.block_count - allocated))
    say('   space: free count %d, chunk sum %d, bitmap free %d' % (sm.free_count, sm.sum_chunk_free, sm.block_count - allocated))

    # object map's snapshot list
    om_snaps = {}

    def omsnap_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            x = struct.unpack_from('<Q', b, koff)[0]
            om_snaps[x] = struct.unpack_from('<I', b, voff)[0]
    if vol_om[1]:
        _, pr = rc.walk_phys_tree(src, vol_om[1], omsnap_leaf, 'object-map snapshot tree')
        hard['E1 object-map snapshot tree problems'] = len(pr)
    # the volume's snapshot list
    snaps = {}

    def snap_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            k = struct.unpack_from('<Q', b, koff)[0]
            if (k >> 60) == 1:
                ext_oid, sblock = struct.unpack_from('<QQ', b, voff)
                snaps[k & 0x0FFFFFFFFFFFFFFF] = (ext_oid, sblock)
    rc.walk_phys_tree(src, vol['snapmeta_oid'], snap_leaf, 'snapshot metadata tree')
    live_om = {x for x, f in om_snaps.items() if not (f & 1)}
    say('   snapshots: volume lists %d, object map lists %d (%d marked deleted), superblock says %d, object map header says %d'
        % (len(snaps), len(om_snaps), len(om_snaps) - len(live_om), num_snaps, vol_om[0]))
    miss = sorted(set(snaps) - live_om)
    extra = sorted(live_om - set(snaps))
    say('   snapshot xids the object map does not protect: %d %s; protected but no longer a snapshot: %d %s' % (len(miss), miss[:5], len(extra), extra[:5]))
    hard['E1 snapshots not protected in the object map'] = len(miss)
    soft['E1 object map protects xids that are no snapshot'] = len(extra)
    hard['E1 snapshot counts disagree'] = int(not (len(snaps) == num_snaps and len(om_snaps) == vol_om[0]))
    soft['E1 most recent snapshot xid differs'] = int(bool(snaps) and vol_om[2] != max(snaps))

    # ---------------- references (as refcheck.py, plus the mapping keys) ----------------------
    say(''); say('collecting references ...')
    PR, pprob = rc.plain_refs(c, src, vol, say)
    spm = [(x, 1, 9) for x in sm.cab_addrs + sm.cib_addrs + sm.bitmap_addrs]
    allr = np.array(R + PR + spm, dtype=np.int64).reshape(-1, 3)
    del PR
    starts, lens, cls = allr[:, 0], allr[:, 1], allr[:, 2]
    hard['tree structure problems'] = len(cprob) + len(pprob)

    # ---------------- E2: exact accounting ----------------------------------------------------
    say(''); say('E2 exact accounting of allocated blocks')
    n = int(sm.block_count) + 1
    d = np.zeros(n, dtype=np.int16)
    np.add.at(d, starts, 1); np.add.at(d, starts + lens, -1)
    known = [(0, 1), (c.desc_base, c.desc_blocks), (c.data_base, c.data_blocks), (sm.ip_base, sm.ip_block_count), (sm.ip_bm_base, sm.ip_bm_block_count)]
    known += [(p, k) for x, p, k in sm.queues['main']['entries']]
    for p, k in known:
        d[p] += 1; d[p + k] -= 1
    acc = np.cumsum(d, dtype=np.int16)[:sm.block_count] > 0
    del d
    abits = np.unpackbits(bm, bitorder='little')[:sm.block_count].view(bool)
    leaked = abits & ~acc
    nleak = int(leaked.sum())
    unalloc = int((acc & ~abits).sum())
    say('   allocated %d; allocated but neither referenced, reserved nor queued (lost space, harmless for writes): %d; accounted for but not allocated: %d' % (allocated, nleak, unalloc))
    if nleak:
        idx = np.flatnonzero(leaked)
        brk = np.flatnonzero(np.diff(idx) != 1)
        runs = len(brk) + 1
        say('   lost-space runs: %d, first at %s' % (runs, ', '.join('0x%x' % int(idx[k]) for k in ([0] + (brk[:5] + 1).tolist())[:6])))
    soft['E2 allocated blocks nobody refers to'] = nleak
    del leaked, acc
    hard['E2 referenced or reserved but not allocated'] = unalloc
    volref = cls != 6
    del abits
    dv = np.zeros(n, dtype=np.int16)
    np.add.at(dv, starts[volref & (cls != 9)], 1); np.add.at(dv, (starts + lens)[volref & (cls != 9)], -1)
    nvol = int((np.cumsum(dv, dtype=np.int16)[:sm.block_count] > 0).sum())
    del dv
    say('   blocks charged to the volume %d; blocks I find the volume using %d; difference %d' % (vol['alloc_count'], nvol, vol['alloc_count'] - nvol))
    soft['E2 volume charge differs from what it uses'] = abs(vol['alloc_count'] - nvol)

    # ---------------- E3: stored in the bundle and on the HDD ----------------------------------
    def e3():
        say(''); say('E3 every referenced block is really stored')
        poff = part_off // BS
        img_blocks = int(sm.block_count) + poff + BPB
        bands = {}
        bsize = {}
        maps = {}
        if lst:
            from e3_analyze import listing
            for k, v in listing(lst[0]).items():
                bands[k] = v[0]; bsize[k] = v[1]
            for k, v in listing(lst[1]).items():
                maps[k] = v[0]
        else:
            with os.scandir(os.path.join(bundle, 'bands')) as it:
                for e in it:
                    try:
                        bands[int(e.name, 16)] = e.inode()
                        bsize[int(e.name, 16)] = e.stat(follow_symlinks=False).st_size
                    except ValueError:
                        say('   unexpected name in bands: %s' % e.name)
            with os.scandir(os.path.join(bundle, 'mapped')) as it:
                for e in it:
                    try:
                        maps[int(e.name, 16)] = e.inode()
                    except ValueError:
                        say('   unexpected name in mapped: %s' % e.name)
        say('   band files %d (%d shorter than a full piece, %d longer), map files %d, map files without a band %d'
            % (len(bands), sum(1 for v in bsize.values() if v < BAND), sum(1 for v in bsize.values() if v > BAND), len(maps), len(set(maps) - set(bands))))
        hard['E3 band files longer than a piece'] = sum(1 for v in bsize.values() if v > BAND)
        ino2band = {v: k for k, v in bands.items()}
        ino2map = {v: k for k, v in maps.items()}
        assert len(ino2band) == len(bands)
        # the HDD's own extent table: which parts of each band file have real blocks, and where each map file's block is
        stored = np.zeros(img_blocks + 1, dtype=np.int8)       # +1/-1 marks, in image blocks
        map_at = {}
        nb_ext = 0
        with open(hdd_ext) as f:
            for line in f:
                t = line.split()
                fid = int(t[0], 16)
                bi = ino2band.get(fid)
                if bi is not None:
                    lo = int(t[1], 16); k = int(t[3], 16)
                    assert lo % BS == 0
                    s = bi * BPB + lo // BS
                    e_ = min(s + k, bi * BPB + bsize[bi] // BS)
                    if s < img_blocks and e_ > s:
                        stored[s] += 1; stored[min(e_, img_blocks)] -= 1; nb_ext += 1
                else:
                    mi = ino2map.get(fid)
                    if mi is not None and int(t[1], 16) == 0:
                        map_at[mi] = int(t[2], 16)
        have = np.cumsum(stored, dtype=np.int8)[:img_blocks] > 0
        del stored
        say('   band extents on the HDD: %d; image blocks with real blocks behind them: %d; map files located: %d' % (nb_ext, int(have.sum()), len(map_at)))
        # the maps, read in the order they lie on the HDD
        mapped = np.ones(img_blocks, dtype=bool)
        badmaps = 0
        tm = time.time()
        order = sorted(maps, key=lambda k: map_at.get(k, 0))
        for j, bi in enumerate(order):
            try:
                with open(os.path.join(bundle, 'mapped', '%x' % bi), 'rb') as f:
                    m = f.read()
            except OSError:
                badmaps += 1; continue
            if len(m) != BPB // 8:
                badmaps += 1; continue
            if bi * BPB < img_blocks:
                mapped[bi * BPB:(bi + 1) * BPB] = np.unpackbits(np.frombuffer(m, dtype=np.uint8), bitorder='little').astype(bool)[:max(0, min(BPB, img_blocks - bi * BPB))]
            if time.time() - tm > 30:
                tm = time.time(); print('   ... maps read: %d of %d' % (j + 1, len(maps))); sys.stdout.flush()
        say('   map files read: %d, unreadable or of unexpected size: %d' % (len(maps) - badmaps, badmaps))
        hard['E3 map files unreadable'] = badmaps
        present = have & mapped
        # bands without a file at all
        CLS = {1: 'file-index node', 2: 'extent-tree node', 3: 'snapshot-tree node', 4: 'file data', 5: 'volume object-map node',
               6: 'container object-map node', 7: 'volume superblock', 8: 'object-map header', 9: 'space-manager block'}
        a0 = starts + poff; a1 = a0 + lens

        def lacking(bits):
            cs = np.empty(len(bits) + 1, dtype=np.uint32); cs[0] = 0
            np.cumsum(bits, dtype=np.uint32, out=cs[1:])
            return lens - (cs[a1].astype(np.int64) - cs[a0].astype(np.int64))
        lack = lacking(present)
        nohost = lacking(have)
        nomap = lacking(mapped)
        for cl in sorted(CLS):
            sel = cls == cl
            if not sel.any():
                continue
            bad = np.flatnonzero(sel & (lack > 0))
            say('   %-26s ranges %9d, blocks %11d; not stored: %d ranges, %d blocks (no real block on the HDD: %d, not marked in the map: %d)%s'
                % (CLS[cl], int(sel.sum()), int(lens[sel].sum()), len(bad), int(lack[sel].sum()), int(nohost[sel].sum()), int(nomap[sel].sum()),
                   (' e.g. ' + ', '.join('0x%x+%d' % (int(starts[k]), int(lens[k])) for k in bad[:4])) if len(bad) else ''))
        hard['E3 index or table blocks not stored'] = int(lack[cls != 4].sum())
        hard['E3 file data blocks not stored'] = int(lack[cls == 4].sum())
        badr = np.flatnonzero(lack > 0)
        if out_path and len(badr):
            with open(out_path + '.notstored', 'w') as fo:
                for k in badr[:200000].tolist():
                    fo.write('0x%x %d %s missing %d\n' % (int(starts[k]), int(lens[k]), CLS[int(cls[k])], int(lack[k])))
        # the reverse: stored image blocks that the container calls free are fine (stale data), nothing to check
        del have, mapped, present

    if skip_e3:
        say(''); say('E3 skipped on request')
    else:
        e3()

    # ---------------- E4: entry points of every backup, and a sample of all index nodes -------
    def e4():
        say(''); say('E4 entry points of every backup and a sample of index nodes')
        # all mappings with their keys
        keys = []

        def omap_leaf(b, ents):
            for koff, kl, voff, vl in ents:
                oid, x = struct.unpack_from('<QQ', b, koff)
                fl, size, paddr = struct.unpack_from('<IIQ', b, voff)
                if not (fl & 1):
                    keys.append((oid, x, paddr))
        om = src.block(vol['omap_oid'])
        rc.walk_phys_tree(src, struct.unpack_from('<Q', om, 48)[0], omap_leaf, 'object map')
        K = np.array(keys, dtype=np.int64).reshape(-1, 3)
        del keys
        ordk = np.lexsort((K[:, 1], K[:, 0]))
        K = K[ordk]
        # versions that no backup can see any more
        liv = np.array(sorted(live_om), dtype=np.int64)
        nxt_x = np.full(len(K), 1 << 62, dtype=np.int64)
        same = K[1:, 0] == K[:-1, 0]
        nxt_x[:-1][same] = K[1:, 1][same]
        j = np.searchsorted(liv, K[:, 1], side='left')
        seen = (j < len(liv)) & (liv[np.minimum(j, len(liv) - 1)] < nxt_x)
        unseen = ~seen & (nxt_x != (1 << 62))
        nun = int(unseen.sum())
        if cleanup:
            pend = int((unseen & (K[:, 0] >= cleanup[4])).sum())
            say('   old versions no live backup can see: %d, of these %d still ahead of the pending cleanup and %d behind it (left over, harmless as long as their blocks are properly owned)' % (nun, pend, nun - pend))
        else:
            say('   old versions no live backup can see (left over, harmless as long as their blocks are properly owned): %d' % nun)
        soft['E4 left-over old versions'] = nun
        del nxt_x, same, j, seen, unseen
        say('   mappings: %d for %d object ids' % (len(K), len(np.unique(K[:, 0]))))

        def resolve(oid, at_xid):
            lo = int(np.searchsorted(K[:, 0], oid, side='left')); hi = int(np.searchsorted(K[:, 0], oid, side='right'))
            best = None
            for k in range(lo, hi):
                if K[k, 1] <= at_xid:
                    best = k
            return None if best is None else (int(K[best, 1]), int(K[best, 2]))

        def node_ok(paddr, oid, x):
            try:
                b = src.block(paddr)
            except KeyError:
                return 'not readable'
            if not rc.valid(b):
                return 'bad checksum'
            o, xx, typ = struct.unpack_from('<QQI', b, 8)
            if o != oid or xx != x:
                return 'holds oid 0x%x xid %d instead' % (o, xx)
            types[typ & 0xffff] += 1
            return None

        types = collections.Counter()
        bad_entry = 0
        for sx in sorted(snaps) + [None]:
            if sx is None:
                sb, label, at = apsb, 'current state', vol['xid']
            else:
                ext_oid, sblock = snaps[sx]
                label, at = 'backup at xid %d' % sx, sx
                try:
                    sb = src.block(sblock)
                except KeyError:
                    sb = b''
                if len(sb) != BS or sb[32:36] != b'APSB' or not rc.valid(sb):
                    bad_entry += 1; say('   %s: superblock @0x%x not valid' % (label, sblock)); continue
            root_oid = struct.unpack_from('<Q', sb, 136)[0]
            r = resolve(root_oid, at)
            if r is None:
                bad_entry += 1; say('   %s: file-index root 0x%x has no mapping' % (label, root_oid)); continue
            why = node_ok(r[1], root_oid, r[0])
            if why:
                bad_entry += 1; say('   %s: file-index root @0x%x %s' % (label, r[1], why)); continue
            b = src.block(r[1])
            flags, level, ents = rc.parse_btnode(b)
            # one level down: every child of the root must resolve at this backup's xid
            nochild = 0
            if level > 0:
                for koff, kl, voff, vl in ents:
                    if resolve(struct.unpack_from('<Q', b, voff)[0], at) is None:
                        nochild += 1
            if nochild:
                bad_entry += 1; say('   %s: %d children of the root have no mapping' % (label, nochild))
        say('   entry points checked: %d backups + current state; bad: %d' % (len(snaps), bad_entry))
        hard['E4 backups without a readable entry point'] = bad_entry

        picks = []
        if reloc_map:
            with open(reloc_map) as f:
                for line in f:
                    t = line.split()
                    if len(t) >= 7 and t[2] == 'target':
                        picks.append((int(t[4], 16), int(t[6]), int(t[1], 16)))
            say('   nodes moved by the fix (from %s): %d' % (os.path.basename(reloc_map), len(picks)))
            moved_bad = 0
            for oid, x, newp in picks:
                lo = int(np.searchsorted(K[:, 0], oid, side='left')); hi = int(np.searchsorted(K[:, 0], oid, side='right'))
                hit = [k for k in range(lo, hi) if K[k, 1] == x]
                if not hit or int(K[hit[0], 2]) != newp:
                    moved_bad += 1; continue
                if node_ok(newp, oid, x):
                    moved_bad += 1
            say('   moved nodes that are not intact at their new place: %d' % moved_bad)
            hard['E4 moved nodes not intact'] = moved_bad
        rnd = random.Random(20261008)
        idx = sorted(rnd.sample(range(len(K)), min(nsample, len(K))), key=lambda k: int(K[k, 2]))
        sbad = 0
        ts = time.time()
        for j, k in enumerate(idx):
            why = node_ok(int(K[k, 2]), int(K[k, 0]), int(K[k, 1]))
            if why:
                sbad += 1
                if sbad <= 20:
                    say('   sample: oid 0x%x xid %d @0x%x %s' % (int(K[k, 0]), int(K[k, 1]), int(K[k, 2]), why))
            if time.time() - ts > 60:
                ts = time.time(); print('   ... sample: %d of %d read' % (j + 1, len(idx))); sys.stdout.flush()
        say('   random sample of index nodes over all backups: %d of %d mappings read, bad: %d' % (len(idx), len(K), sbad))
        hard['E4 sampled index nodes bad'] = sbad
        say('   object types met: %s' % ', '.join('0x%x: %d' % kv for kv in sorted(types.items())))

    if fs_flags & 1:
        e4()
    else:
        say(''); say('E4 skipped: the volume is encrypted, its index nodes cannot be read without the key')
        soft['E4 skipped (encrypted volume)'] = 1

    src.close()
    say('')
    bad = [(k, v) for k, v in hard.items() if v]
    for k, v in hard.items():
        say('  %-52s %s' % (k, 'OK' if not v else 'FAIL (%d)' % v))
    for k, v in soft.items():
        say('  %-52s %s' % (k, 'none' if not v else 'note (%d)' % v))
    say('RESULT: %s   (%.0f s)' % ('PASS' if not bad else 'FAIL', time.time() - t0))
    if out_path:
        with open(out_path, 'w') as fo:
            fo.write('\n'.join(lines) + '\n')
    return 0 if not bad else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
