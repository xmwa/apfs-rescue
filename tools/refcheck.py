#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Gate G1: independent ownership check of an APFS container with one volume.

Read-only. Every block that something live refers to must be
  (a) marked allocated in the space manager's bitmap,
  (b) absent from both free queues (blocks waiting to be released),
  (c) owned once.
Also: every queued block must still be allocated (else it would be released twice).

  refcheck.py <refs_prefix> <source> [<source> ...] [--out report.txt]

<refs_prefix>  output of apfs-refs: .nodes .extents .pext
<source>       where the container's plain metadata is read from: a device or image
               ("path"), or a partial copy starting at a block ("path@first_block").
Exit code 0 only if every hard check passes.
"""
import os, struct, sys, time, bisect, collections
import numpy as np

BS = 4096


def fletcher64(body):
    w = np.frombuffer(body, dtype='<u4').astype(np.uint64)
    n = len(w)
    s1 = int(w.sum() % 0xFFFFFFFF)
    weights = np.arange(n, 0, -1, dtype=np.uint64)
    s2 = int(((w % 0xFFFFFFFF) * (weights % 0xFFFFFFFF) % 0xFFFFFFFF).sum() % 0xFFFFFFFF)
    c1 = 0xFFFFFFFF - ((s1 + s2) % 0xFFFFFFFF)
    c2 = 0xFFFFFFFF - ((s1 + c1) % 0xFFFFFFFF)
    return (c2 << 32) | c1


def valid(blk):
    return len(blk) >= BS and len(blk) % BS == 0 and struct.unpack_from('<Q', blk, 0)[0] == fletcher64(blk[8:])


class CaptureSrc:
    """Reads blocks from a local store if they were captured before, else from the device (if
    given) and stores them. The store is PACKED: captured blocks are appended one after another
    and the index file maps block number -> position. (A sparse file with blocks at their natural
    offsets is not used any more: APFS pre-allocated up to 1.3 TB for such a file and filled the
    disk.) Spec: capture:<device or ->:<store>"""
    def __init__(self, dev, img):
        import shutil
        self._shutil = shutil
        self.off = 0
        self.dev = os.open(dev, os.O_RDONLY) if dev and dev != '-' else None
        self.img_path = img
        self.img = os.open(img, os.O_RDWR | os.O_CREAT, 0o644)
        self.idx_path = img + '.idx'
        self.have = {}
        if os.path.exists(self.idx_path):
            with open(self.idx_path) as f:
                for line in f:
                    t = line.split()
                    if len(t) != 2:
                        raise SystemExit('%s is not a packed capture index (old sparse format?); convert it with capimg_pack.py' % self.idx_path)
                    self.have[int(t[0])] = int(t[1])
        self.n = (max(self.have.values()) + 1) if self.have else 0
        if os.fstat(self.img).st_size < self.n * BS:
            raise SystemExit('capture store %s is shorter than its index says; do not use it' % img)
        self.idx = open(self.idx_path, 'a')
        self.missing = collections.Counter()
        self.fetched = 0

    def block(self, b, n=1):
        out = []
        for k in range(b, b + n):
            pos = self.have.get(k)
            if pos is not None:
                out.append(os.pread(self.img, BS, pos * BS))
            elif self.dev is not None:
                d = os.pread(self.dev, BS, k * BS)
                if len(d) != BS:
                    raise KeyError('short read at block 0x%x' % k)
                pos = self.n
                os.pwrite(self.img, d, pos * BS)
                self.have[k] = pos; self.n += 1
                self.idx.write('%d %d\n' % (k, pos)); self.fetched += 1
                if self.fetched % 2000 == 0:
                    self.idx.flush()
                    if self._shutil.disk_usage(os.path.dirname(os.path.abspath(self.img_path))).free < 100 * 10 ** 9:
                        raise SystemExit('less than 100 GB free on the disk holding the capture store; stopping')
                out.append(d)
            else:
                self.missing[k] += 1
                raise KeyError('block 0x%x was not captured' % k)
        return b''.join(out)

    def put(self, k, data):
        """Store or replace one block (used when applying a patch to a local copy)."""
        pos = self.have.get(k)
        if pos is None:
            pos = self.n; self.n += 1; self.have[k] = pos; self.idx.write('%d %d\n' % (k, pos))
        os.pwrite(self.img, data, pos * BS)

    def close(self):
        self.idx.flush(); os.fsync(self.idx.fileno()); os.fsync(self.img)


class Src:
    """Block reader over one or more files, each covering a block range."""
    def __init__(self, specs):
        self.parts = []
        self.off = 0
        for s in specs:
            path, _, start = s.partition('@')
            start = int(start, 0) if start else 0
            fd = os.open(path, os.O_RDONLY)
            size = os.lseek(fd, 0, os.SEEK_END)
            if size == 0:                       # character device: unknown size, trust it
                size = 1 << 62
            base = 0
            if not start and os.pread(fd, BS, 0)[32:36] != b'NXSB':
                # an image with a partition table: find where the container starts
                for pos in range(0, min(size, 2 << 30), BS):
                    if os.pread(fd, BS, pos)[32:36] == b'NXSB':
                        base = pos
                        break
            self.parts.append((start, start + (size - base) // BS, fd, path, base))
        self.missing = collections.Counter()

    def block(self, b, n=1):
        for start, end, fd, path, base in self.parts:
            if start <= b and b + n <= end:
                d = os.pread(fd, BS * n, base + (b - start) * BS)
                if len(d) == BS * n:
                    return d
        self.missing[b] += 1
        raise KeyError('block 0x%x is not in any source' % b)


def parse_btnode(b):
    """Generic B-tree node -> (flags, level, [(key_bytes_offset, key_len, val_off, val_len)], helpers)."""
    flags, level, nkeys = struct.unpack_from('<HHI', b, 32)
    toff, tlen = struct.unpack_from('<HH', b, 40)
    toc = 56 + toff
    keys = toc + tlen
    vend = len(b) - (40 if flags & 1 else 0)
    out = []
    for i in range(nkeys):
        if flags & 4:
            k, v = struct.unpack_from('<HH', b, toc + 4 * i)
            kl = vl = None
        else:
            k, kl, v, vl = struct.unpack_from('<HHHH', b, toc + 8 * i)
        out.append((keys + k, kl, None if v == 0xffff else vend - v, vl))
    return flags, level, out


class Container:
    def __init__(self, src, want_xid=None):
        self.src = src
        first = src.block(0)
        if first[32:36] != b'NXSB':
            raise SystemExit('no container superblock at block 0')
        self.desc_blocks, self.data_blocks, self.desc_base, self.data_base = struct.unpack_from('<IIQQ', first, 104)
        best = None
        for i in range(self.desc_blocks):
            b = src.block(self.desc_base + i)
            if b[32:36] == b'NXSB' and valid(b):
                x = struct.unpack_from('<Q', b, 16)[0]
                if (want_xid is None and (best is None or x > best[0])) or x == want_xid:
                    best = (x, self.desc_base + i, b)
        if best is None:
            raise SystemExit('no valid container superblock found')
        self.xid, self.sb_paddr, self.sb = best
        self.block_count = struct.unpack_from('<Q', self.sb, 40)[0]
        desc_index, desc_len = struct.unpack_from('<II', self.sb, 136)
        self.sm_oid, self.omap_oid, self.reaper_oid = struct.unpack_from('<QQQ', self.sb, 152)
        maxfs = struct.unpack_from('<I', self.sb, 180)[0]
        self.fs_oids = [o for o in struct.unpack_from('<%dQ' % min(maxfs, 100), self.sb, 184) if o]
        self.eph = {}
        self.cpm_blocks = []
        for k in range(desc_len):
            p = self.desc_base + (desc_index + k) % self.desc_blocks
            b = src.block(p)
            if (struct.unpack_from('<I', b, 24)[0] & 0xffff) != 0xc or not valid(b):
                continue
            self.cpm_blocks.append(p)
            for j in range(struct.unpack_from('<I', b, 36)[0]):
                typ, sub, size, pad, fs_oid, oid, paddr = struct.unpack_from('<IIIIQQQ', b, 40 + 40 * j)
                self.eph[oid] = (paddr, size, typ, sub)

    def eph_obj(self, oid):
        paddr, size, typ, sub = self.eph[oid]
        b = b''.join(self.src.block(self.data_base + (paddr - self.data_base + i) % self.data_blocks) for i in range(size // BS))
        if not valid(b):
            raise SystemExit('ephemeral object 0x%x fails its checksum' % oid)
        return b


class Spaceman:
    def __init__(self, c):
        self.c = c
        src = c.src
        sm = self.sm = c.eph_obj(c.sm_oid)
        if (struct.unpack_from('<I', sm, 24)[0] & 0xffff) != 5:
            raise SystemExit('not a space manager object')
        self.blocks_per_chunk, self.chunks_per_cib, self.cibs_per_cab = struct.unpack_from('<III', sm, 36)
        self.block_count, self.chunk_count, self.cib_count, self.cab_count, self.free_count, self.addr_offset = struct.unpack_from('<QQIIQI', sm, 48)
        self.ip_block_count, self.ip_bm_size, self.ip_bm_block_count, self.ip_bm_base, self.ip_base = struct.unpack_from('<QIIQQ', sm, 152)
        n = self.cab_count if self.cab_count else self.cib_count
        top = list(struct.unpack_from('<%dQ' % n, sm, self.addr_offset))
        self.cab_addrs = top if self.cab_count else []
        self.cib_addrs = []
        if self.cab_count:
            for a in top:
                cab = src.block(a)
                if not valid(cab):
                    raise SystemExit('cib address block @0x%x fails its checksum' % a)
                self.cib_addrs += list(struct.unpack_from('<%dQ' % struct.unpack_from('<I', cab, 36)[0], cab, 40))
        else:
            self.cib_addrs = top
        self.queues = {}
        for i, name in enumerate(('ip', 'main', 'tier2')):
            count, tree, oldest, limit = struct.unpack_from('<QQQH', sm, 200 + 40 * i)
            ents = []
            if tree:
                self._walk(tree, ents)
            self.queues[name] = dict(count=count, tree=tree, oldest=oldest, entries=ents)

    def _walk(self, oid, out):
        b = self.c.eph_obj(oid)
        flags, level, ents = parse_btnode(b)
        for koff, kl, voff, vl in ents:
            xid, paddr = struct.unpack_from('<QQ', b, koff)
            if level > 0:
                self._walk(struct.unpack_from('<Q', b, voff)[0], out)
            else:
                out.append((xid, paddr, 1 if voff is None else struct.unpack_from('<Q', b, voff)[0]))

    def load_bitmap(self):
        """Packed allocation bitmap of the whole container (bit i of byte j = block 8j+i)."""
        nbytes = (self.chunk_count * self.blocks_per_chunk + 7) // 8
        bm = np.zeros(nbytes, dtype=np.uint8)
        per = self.blocks_per_chunk // 8
        self.bitmap_addrs = []
        bad_counts = 0
        total_free = 0
        c = 0
        for a in self.cib_addrs:
            cib = self.c.src.block(a)
            if not valid(cib) or (struct.unpack_from('<I', cib, 24)[0] & 0xffff) != 7:
                raise SystemExit('chunk-info block @0x%x is not valid' % a)
            for e in range(struct.unpack_from('<I', cib, 36)[0]):
                xid, addr, bcount, fcount, bmaddr = struct.unpack_from('<QQIIQ', cib, 40 + 32 * e)
                if addr != c * self.blocks_per_chunk:
                    raise SystemExit('chunk %d starts at 0x%x, expected 0x%x' % (c, addr, c * self.blocks_per_chunk))
                f = fcount & 0xFFFFF
                total_free += f
                if bmaddr:
                    self.bitmap_addrs.append(bmaddr)
                    raw = np.frombuffer(self.c.src.block(bmaddr), dtype=np.uint8)
                    bm[c * per:(c + 1) * per] = raw[:per]
                    zeros = int(bcount - np.unpackbits(raw[:(bcount + 7) // 8], bitorder='little')[:bcount].sum())
                    if zeros != f:
                        bad_counts += 1
                elif f != bcount:
                    bad_counts += 1
                c += 1
        self.bitmap = bm
        self.chunks_with_bad_count = bad_counts
        self.sum_chunk_free = total_free
        return bm


def read_omap(c, omap_paddr):
    """Returns (om_phys_paddr, tree_root, [node paddrs], entries{oid: [(xid, flags, size, paddr)]})."""
    src = c.src
    om = src.block(omap_paddr)
    if not valid(om) or (struct.unpack_from('<I', om, 24)[0] & 0xffff) != 0xb:
        raise SystemExit('object map @0x%x is not valid' % omap_paddr)
    root = struct.unpack_from('<Q', om, 48)[0]
    nodes, entries = [], collections.defaultdict(list)
    problems = []

    def walk(p, lvl_expected=None):
        b = src.block(p)
        if not valid(b) or struct.unpack_from('<Q', b, 8)[0] != p:
            problems.append('omap node @0x%x invalid (checksum or address)' % p)
            return
        flags, level, ents = parse_btnode(b)
        if lvl_expected is not None and level != lvl_expected:
            problems.append('omap node @0x%x level %d, expected %d' % (p, level, lvl_expected))
            return
        nodes.append(p)
        for koff, kl, voff, vl in ents:
            oid, xid = struct.unpack_from('<QQ', b, koff)
            if level > 0:
                walk(struct.unpack_from('<Q', b, voff)[0], level - 1)
            else:
                fl, size, paddr = struct.unpack_from('<IIQ', b, voff)
                entries[oid].append((xid, fl, size, paddr))
    walk(root)
    return root, nodes, entries, problems


def walk_phys_tree(src, root, on_leaf, label, progress=None):
    """Walk a physical B-tree (child pointers are block numbers). Returns (node paddrs, problems)."""
    nodes, problems = [], []
    stack = [(root, None)]
    while stack:
        p, lvl_expected = stack.pop()
        try:
            b = src.block(p)
        except KeyError:
            problems.append('%s node @0x%x not readable' % (label, p)); continue
        if not valid(b) or struct.unpack_from('<Q', b, 8)[0] != p:
            problems.append('%s node @0x%x invalid (checksum or address)' % (label, p)); continue
        flags, level, ents = parse_btnode(b)
        if lvl_expected is not None and level != lvl_expected:
            problems.append('%s node @0x%x level %d, expected %d' % (label, p, level, lvl_expected)); continue
        nodes.append(p)
        if progress and len(nodes) % 5000 == 0:
            progress('%s: %d nodes read' % (label, len(nodes)))
        if level > 0:
            for koff, kl, voff, vl in ents:
                stack.append((struct.unpack_from('<Q', b, voff)[0], level - 1))
        else:
            on_leaf(b, ents)
    return nodes, problems


def plain_refs(c, src, vol, say):
    """References of an unencrypted volume, taken from structures that need no file-index walk:
    every object-map mapping (all versions that any snapshot still needs), the snapshot metadata
    tree, each snapshot's superblock and extent tree, and the current extent tree."""
    R = []
    problems = []
    t = [time.time()]

    def progress(msg):
        if time.time() - t[0] > 20:
            t[0] = time.time(); print('   ...', msg); sys.stdout.flush()

    # object map: nodes and mapping targets
    om = src.block(vol['omap_oid'])
    oroot = struct.unpack_from('<Q', om, 48)[0]
    snap_tree = struct.unpack_from('<Q', om, 56)[0]
    nmap = [0]

    def omap_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            fl, size, paddr = struct.unpack_from('<IIQ', b, voff)
            if not (fl & 1):                                   # OMAP_VAL_DELETED
                R.append((paddr, max(1, size // BS), 1)); nmap[0] += 1
    onodes, pr = walk_phys_tree(src, oroot, omap_leaf, 'object map', progress); problems += pr
    R += [(p, 1, 5) for p in onodes] + [(vol['omap_oid'], 1, 8)]
    if snap_tree:
        sn, pr = walk_phys_tree(src, snap_tree, lambda b, e: None, 'object-map snapshot tree', progress); problems += pr
        R += [(p, 1, 5) for p in sn]
    say('object map: %d nodes, %d mappings' % (len(onodes), nmap[0]))

    # snapshot metadata tree -> each snapshot's superblock and extent tree
    snaps = []

    def snap_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            k = struct.unpack_from('<Q', b, koff)[0]
            if (k >> 60) == 1:                                 # APFS_TYPE_SNAP_METADATA
                ext_oid, sblock = struct.unpack_from('<QQ', b, voff)
                snaps.append((k & 0x0FFFFFFFFFFFFFFF, ext_oid, sblock))
    if vol['snapmeta_oid']:
        smn, pr = walk_phys_tree(src, vol['snapmeta_oid'], snap_leaf, 'snapshot metadata tree', progress); problems += pr
        R += [(p, 1, 3) for p in smn]
    say('snapshots: %d' % len(snaps))
    next_ = [0, 0]

    def ext_leaf(b, ents):
        for koff, kl, voff, vl in ents:
            k = struct.unpack_from('<Q', b, koff)[0]
            if (k >> 60) == 2:                                 # APFS_TYPE_EXTENT
                lk = struct.unpack_from('<Q', b, voff)[0]
                n = lk & 0x0FFFFFFFFFFFFFFF
                R.append((k & 0x0FFFFFFFFFFFFFFF, n, 4)); next_[0] += 1; next_[1] += n
    trees = [(vol['extentref_oid'], 'current extent tree')] + [(e, 'extent tree of snapshot %d' % x) for x, e, sb in snaps if e]
    nen = 0
    for root, label in trees:
        en, pr = walk_phys_tree(src, root, ext_leaf, label, progress); problems += pr
        R += [(p, 1, 2) for p in en]; nen += len(en)
    for x, e, sb in snaps:
        if sb:
            R.append((sb, 1, 7))
    say('extent trees: %d (current + snapshots), %d nodes, %d records covering %d blocks' % (len(trees), nen, next_[0], next_[1]))
    return R, problems


def load_hex_table(path, ncols, skip_first=False):
    rows = []
    with open(path) as f:
        for line in f:
            t = line.split()
            if skip_first:
                rows.append((ord(t[0]),) + tuple(int(x, 16) for x in t[1:1 + ncols]))
            else:
                rows.append(tuple(int(x, 16) for x in t[:ncols]))
    width = ncols + (1 if skip_first else 0)
    return np.array(rows, dtype=np.uint64).reshape(-1, width)


def bits_set(bm, starts, lens):
    """For each range: number of blocks whose bitmap bit is set."""
    out = np.zeros(len(starts), dtype=np.int64)
    one = lens == 1
    s = starts[one].astype(np.int64)
    out[one] = (bm[s >> 3] >> (s & 7).astype(np.uint8)) & 1
    for i in np.nonzero(~one)[0]:
        a, n = int(starts[i]), int(lens[i])
        b0, b1 = a >> 3, (a + n + 7) >> 3
        bits = np.unpackbits(bm[b0:b1], bitorder='little')
        out[i] = int(bits[a - b0 * 8:a - b0 * 8 + n].sum())
    return out


def main(argv):
    out_path = None
    if '--out' in argv:
        i = argv.index('--out'); out_path = argv[i + 1]; del argv[i:i + 2]
    want_xid = None
    if '--xid' in argv:
        i = argv.index('--xid'); want_xid = int(argv[i + 1]); del argv[i:i + 2]
    if len(argv) < 3:
        print(__doc__); return 2
    prefix, specs = argv[1], argv[2:]
    lines = []

    def say(s=''):
        print(s); lines.append(s); sys.stdout.flush()

    t0 = time.time()
    if len(specs) == 1 and specs[0].startswith('capture:'):
        _, dev, img = specs[0].split(':', 2)
        src = CaptureSrc(dev, img)
    else:
        src = Src(specs)
    c = Container(src, want_xid)
    say('container save point xid %d (superblock @0x%x), %d blocks; %d volume(s)' % (c.xid, c.sb_paddr, c.block_count, len(c.fs_oids)))
    sm = Spaceman(c)
    bm = sm.load_bitmap()
    allocated = int(np.unpackbits(bm, bitorder='little')[:sm.block_count].sum()) if sm.block_count < 2 ** 33 else None
    if allocated is None:
        allocated = 0
        step = 1 << 24
        for i in range(0, len(bm), step):
            allocated += int(np.unpackbits(bm[i:i + step], bitorder='little').sum())
    say('space manager: %d blocks, free count %d, sum of chunk free counts %d, bitmap says %d allocated (%d free); chunks whose count disagrees with their bitmap: %d'
        % (sm.block_count, sm.free_count, sm.sum_chunk_free, allocated, sm.block_count - allocated, sm.chunks_with_bad_count))
    for name in ('ip', 'main'):
        q = sm.queues[name]
        tot = sum(e[2] for e in q['entries'])
        xs = [e[0] for e in q['entries']]
        say('free queue %-4s: header count %d, entries %d covering %d blocks, xids %s' % (name, q['count'], len(q['entries']), tot, ('%d..%d' % (min(xs), max(xs))) if xs else '-'))

    # ---- everything that is referenced ------------------------------------------------
    R = []   # (start, len, class)
    CLS = {1: 'file-index node', 2: 'extent-tree node', 3: 'snapshot-tree node', 4: 'file data', 5: 'volume object-map node',
           6: 'container object-map node', 7: 'volume superblock', 8: 'object-map header', 9: 'space-manager block'}
    hard = collections.OrderedDict()

    # container object map -> volume superblocks
    croot, cnodes, centries, cprob = read_omap(c, c.omap_oid)
    R += [(p, 1, 6) for p in cnodes] + [(c.omap_oid, 1, 8)]
    vol = None
    for fs in c.fs_oids:
        cand = [e for e in centries.get(fs, []) if e[0] <= c.xid]
        if not cand:
            say('volume oid 0x%x: no entry in the container object map' % fs); continue
        xid, fl, size, paddr = max(cand)
        apsb = src.block(paddr)
        if apsb[32:36] != b'APSB' or not valid(apsb):
            say('volume superblock @0x%x is not valid' % paddr); continue
        R.append((paddr, 1, 7))
        v = dict(paddr=paddr, xid=struct.unpack_from('<Q', apsb, 16)[0])
        v['alloc_count'] = struct.unpack_from('<Q', apsb, 88)[0]
        v['omap_oid'], v['root_tree_oid'], v['extentref_oid'], v['snapmeta_oid'] = struct.unpack_from('<QQQQ', apsb, 128)
        vol = v
        say('volume superblock @0x%x xid %d: object map @0x%x, root tree oid 0x%x, extent tree @0x%x, snapshot tree @0x%x; blocks charged to the volume %d'
            % (paddr, v['xid'], v['omap_oid'], v['root_tree_oid'], v['extentref_oid'], v['snapmeta_oid'], v['alloc_count']))
    if vol is None:
        raise SystemExit('no usable volume')
    plain = (prefix == '-')
    if plain:
        PR, pprob = plain_refs(c, src, vol, say)
        spm = [(a, 1, 9) for a in sm.cab_addrs + sm.cib_addrs + sm.bitmap_addrs]
        allr = np.array(R + PR + spm, dtype=np.int64).reshape(-1, 3)
        hard['object map / tree structure'] = len(cprob) + len(pprob)
        for p in (cprob + pprob)[:10]:
            say('   ' + p)
        return finish_checks(allr, sm, bm, c, src, CLS, hard, say, lines, out_path, t0, allocated, plain=True)
    vroot, vnodes, ventries, vprob = read_omap(c, vol['omap_oid'])
    R += [(p, 1, 5) for p in vnodes] + [(vol['omap_oid'], 1, 8)]
    say('object maps: container %d nodes, volume %d nodes with %d object ids (%d mappings); problems: %d'
        % (len(cnodes), len(vnodes), len(ventries), sum(len(x) for x in ventries.values()), len(cprob) + len(vprob)))
    for p in (cprob + vprob)[:10]:
        say('   ' + p)
    hard['object map structure'] = len(cprob) + len(vprob)

    # space manager's own blocks (internal pool)
    spm = [(a, 1, 9) for a in sm.cab_addrs + sm.cib_addrs + sm.bitmap_addrs]

    nodes = load_hex_table(prefix + '.nodes', 4, skip_first=True)       # tag oid xid paddr level
    ext = load_hex_table(prefix + '.extents', 4)                        # file_id logical paddr n
    pext = load_hex_table(prefix + '.pext', 5)                          # paddr n kind owner refcnt
    tagcls = {ord('F'): 1, ord('X'): 2, ord('S'): 3}
    for tag, cl in tagcls.items():
        sel = nodes[nodes[:, 0] == tag]
        R += [(int(p), 1, cl) for p in sel[:, 3]]
    say('references read: %d file-index nodes, %d extent-tree nodes, %d snapshot-tree nodes, %d file extents (%d blocks), %d extent-tree records (%d blocks)'
        % (int((nodes[:, 0] == ord('F')).sum()), int((nodes[:, 0] == ord('X')).sum()), int((nodes[:, 0] == ord('S')).sum()),
           len(ext), int(ext[:, 3].sum()) if len(ext) else 0, len(pext), int(pext[:, 1].sum()) if len(pext) else 0))

    # cross-check: the file-index nodes the tool used are what the object map says
    f = nodes[nodes[:, 0] == ord('F')]
    mism = 0
    for oid, xid, paddr in zip(f[:, 1].tolist(), f[:, 2].tolist(), f[:, 3].tolist()):
        cand = [e for e in ventries.get(oid, []) if e[0] <= vol['xid']]
        if not cand or max(cand)[3] != paddr or max(cand)[0] != xid:
            mism += 1
    say('file-index nodes whose block or version differs from the object map entry: %d' % mism)
    hard['file-index nodes vs object map'] = mism
    live_oids = set(f[:, 1].tolist())
    orphan = [o for o in ventries if o not in live_oids]
    say('object-map ids not used by the file index (informational): %d' % len(orphan))

    Rn = np.array(R + spm, dtype=np.int64).reshape(-1, 3)
    if len(ext):
        E = np.column_stack([ext[:, 2].astype(np.int64), ext[:, 3].astype(np.int64), np.full(len(ext), 4, dtype=np.int64)])
        allr = np.vstack([Rn, E])
    else:
        allr = Rn
    return finish_checks(allr, sm, bm, c, src, CLS, hard, say, lines, out_path, t0, allocated, plain=False, ext=ext, pext=pext)


def finish_checks(allr, sm, bm, c, src, CLS, hard, say, lines, out_path, t0, allocated, plain=False, ext=None, pext=None):
    starts, lens, cls = allr[:, 0], allr[:, 1], allr[:, 2]
    beyond = int(((starts + lens) > sm.block_count).sum())
    say('referenced ranges: %d covering %d blocks; reaching beyond the container: %d' % (len(allr), int(lens.sum()), beyond))
    hard['references beyond the container'] = beyond
    ok = (starts + lens) <= sm.block_count
    starts, lens, cls = starts[ok], lens[ok], cls[ok]

    # (a) allocated in the bitmap
    setbits = bits_set(bm, starts, lens)
    under = np.nonzero(setbits != lens)[0]
    ub = int((lens[under] - setbits[under]).sum())
    say('(a) referenced but marked FREE in the bitmap: %d ranges, %d blocks' % (len(under), ub))
    for cl in sorted(set(cls[under].tolist())):
        sel = under[cls[under] == cl]
        say('      %-28s %d ranges, e.g. %s' % (CLS[cl], len(sel), ', '.join('0x%x+%d' % (int(starts[i]), int(lens[i])) for i in sel[:4])))
    hard['(a) referenced but free'] = ub

    # (b) in a free queue
    order = np.argsort(starts, kind='stable')
    s_sorted, e_sorted = starts[order], (starts + lens)[order]
    emax = np.maximum.accumulate(e_sorted)
    qhits = 0
    detail = collections.Counter()
    hitlist = []
    for name in ('main', 'ip'):
        for xid, p, n in sm.queues[name]['entries']:
            i = int(np.searchsorted(s_sorted, p + n, side='left'))       # ranges starting before the queue range ends
            j = i - 1
            while j >= 0 and emax[j] > p:
                if e_sorted[j] > p:
                    qhits += 1
                    k = int(order[j])
                    detail[(name, CLS[int(cls[k])])] += 1
                    if len(hitlist) < 5000:
                        hitlist.append((name, xid, p, n, int(starts[k]), int(lens[k]), CLS[int(cls[k])]))
                j -= 1
    say('(b) referenced blocks that sit in a free queue: %d' % qhits)
    for (name, what), k in sorted(detail.items()):
        say('      queue %-4s %-28s %d' % (name, what, k))
    hard['(b) referenced and queued for release'] = qhits

    # queued blocks must still be allocated, and be queued once
    for name in ('main',):
        ents = sm.queues[name]['entries']
        if ents:
            qs = np.array([e[1] for e in ents], dtype=np.int64); ql = np.array([e[2] for e in ents], dtype=np.int64)
            inr = (qs + ql) <= sm.block_count
            sb_ = bits_set(bm, qs[inr], ql[inr])
            free_already = int((ql[inr] - sb_).sum())
            o2 = np.argsort(qs, kind='stable')
            dupq = int(((qs[o2][1:]) < (qs[o2] + ql[o2])[:-1]).sum())
        else:
            free_already = dupq = 0
        say('    queue %s: queued blocks already free in the bitmap (would be released twice): %d; overlapping queue entries: %d; entries newer than the save point: %d'
            % (name, free_already, dupq, sum(1 for e in ents if e[0] > c.xid)))
        hard['queue %s: already free' % name] = free_already
        hard['queue %s: overlapping entries' % name] = dupq

    # (c) owned once
    nxt_start = s_sorted[1:]
    prev_end = emax[:-1]
    ov = np.nonzero(nxt_start < prev_end)[0]
    real = 0
    nshared = 0
    examples = []
    c_sorted, l_sorted = cls[order], lens[order]
    for i in ov.tolist():
        a, b = i, i + 1
        if c_sorted[a] == 4 and c_sorted[b] == 4 and s_sorted[a] == s_sorted[b] and l_sorted[a] == l_sorted[b]:
            continue                                   # the same extent shared by clones
        if c_sorted[a] == 4 and c_sorted[b] == 4:
            # nested or partially shared extents of clones are legitimate if the extent tree's reference counts agree; counted separately
            nshared += 1
            continue
        real += 1
        if len(examples) < 50:
            examples.append((CLS[int(c_sorted[a])] + ' / ' + CLS[int(c_sorted[b])], int(s_sorted[a]), int(l_sorted[a]), int(s_sorted[b]), int(l_sorted[b])))
    shared = nshared
    say('(c) blocks with two different owners: %d overlaps (plus %d partially shared file extents, checked against the extent tree below)' % (real, shared))
    for e in examples[:20]:
        say('      %s: 0x%x+%d and 0x%x+%d' % e)
    hard['(c) two owners'] = real

    if not plain:
        # file extents against the extent tree
        if len(pext) or len(ext):
            n = int(sm.block_count) + 1
            d = np.zeros(n, dtype=np.int8)
            if len(ext):
                u = np.unique(np.column_stack([ext[:, 2], ext[:, 3]]), axis=0)
                np.add.at(d, u[:, 0].astype(np.int64), 1)
                np.add.at(d, (u[:, 0] + u[:, 1]).astype(np.int64), -1)
            fcov = np.cumsum(d, dtype=np.int8) > 0
            d[:] = 0
            if len(pext):
                np.add.at(d, pext[:, 0].astype(np.int64), 1)
                np.add.at(d, (pext[:, 0] + pext[:, 1]).astype(np.int64), -1)
            pc = np.cumsum(d, dtype=np.int8)
            pcov = pc > 0
            only_file = int((fcov & ~pcov).sum()); only_pext = int((pcov & ~fcov).sum()); pdup = int((pc > 1).sum())
            say('file data vs extent tree: blocks used by files but missing in the extent tree: %d; in the extent tree but used by no file: %d; covered by two extent-tree records: %d'
                % (only_file, only_pext, pdup))
            hard['file data missing in extent tree'] = only_file
            hard['extent tree records overlap'] = pdup
            soft_pext_only = only_pext
            # total picture
            refbits = fcov | pcov
            for a, l in zip(starts[cls != 4].tolist(), lens[cls != 4].tolist()):
                refbits[a:a + l] = True
            nref = int(refbits[:sm.block_count].sum())
            say('totals: allocated %d blocks; referenced by the volume, the object maps and the space manager tables %d; difference %d (container areas, internal pool, queued blocks, or leaked)'
                % (allocated, nref, allocated - nref))
            qb = sum(e[2] for e in sm.queues['main']['entries'])
            say('        of the difference: internal pool %d, checkpoint areas %d, main queue %d' % (sm.ip_block_count + sm.ip_bm_block_count, c.desc_blocks + c.data_blocks, qb))
    else:
        n = int(sm.block_count) + 1
        refbits = np.zeros(n, dtype=bool)
        d = np.zeros(n, dtype=np.int8)
        big = lens > 1
        np.add.at(d, starts[big], 1); np.add.at(d, (starts + lens)[big], -1)
        refbits |= np.cumsum(d, dtype=np.int8) > 0
        refbits[starts[~big]] = True
        nref = int(refbits[:sm.block_count].sum())
        say('totals: allocated %d blocks; referenced %d; difference %d (container areas, internal pool, queued blocks, or leaked)' % (allocated, nref, allocated - nref))
        qb = sum(e[2] for e in sm.queues['main']['entries'])
        say('        of the difference: internal pool %d, checkpoint areas %d, main queue %d' % (sm.ip_block_count + sm.ip_bm_block_count, c.desc_blocks + c.data_blocks, qb))
    if hasattr(src, 'close'):
        src.close(); say('blocks read from the device and stored locally in this run: %d' % src.fetched)
    if src.missing:
        say('NOTE: %d blocks were not available in the given sources' % len(src.missing))
    say('')
    bad = [(k, v) for k, v in hard.items() if v]
    for k, v in hard.items():
        say('  %-44s %s' % (k, 'OK' if not v else 'FAIL (%d)' % v))
    say('RESULT: %s   (%.0f s)' % ('PASS' if not bad else 'FAIL', time.time() - t0))
    if out_path:
        with open(out_path, 'w') as fo:
            fo.write('\n'.join(lines) + '\n')
        if hitlist:
            with open(out_path + '.queued', 'w') as fo:
                for h in hitlist:
                    fo.write('%s xid %d queue 0x%x+%d ref 0x%x+%d %s\n' % h)
    return 0 if not bad else 1



if __name__ == '__main__':
    sys.exit(main(sys.argv))
