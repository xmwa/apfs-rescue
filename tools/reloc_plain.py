#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Move index blocks of an UNENCRYPTED APFS volume out of harm's way (read-only planner).

A block that the index still uses but that sits in the space manager's free queue will be
released and reused at the next read-write mount. This tool copies each such block to a free
block and re-points its single reference; the queue is left alone, so the old block is then
released correctly.

  reloc_plain.py <source> <patch_out> <space_patch_out> (--queued | --random N [seed] | --list file)

Handles two kinds of blocks:
  - a node of the volume's object map (physical B-tree node): copied, its own address field set to
    the new block, and the pointer in its parent (or in the object-map header, for the root) updated
  - the target of an object-map entry (a file-index node, found by object id and version): copied
    unchanged, and the entry's block number updated
Everything else is refused. <source> is a device, an image, or capture:<dev or ->:<image>.
"""
import os, random, struct, sys
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import refcheck as rc
import omap_repair as r
import spaceman_fix as sf
BS = 4096


def resum(b):
    b = bytearray(b)
    struct.pack_into('<Q', b, 0, r.fletcher64(bytes(b[8:])))
    return bytes(b)


def main(a):
    bundle = None
    if '--present-in' in a:                         # only use blocks that physically exist in a sparse bundle
        i = a.index('--present-in'); bundle, part_off = a[i + 1], int(a[i + 2]); del a[i:i + 3]
    spec, patch_out, space_out, mode = a[1], a[2], a[3], a[4]
    BAND = 8388608
    band_info = {}

    def present(b):
        if bundle is None:
            return True
        bi, bo = divmod(part_off + b * BS, BAND)
        if bi not in band_info:
            pb = os.path.join(bundle, 'bands', '%x' % bi); pm = os.path.join(bundle, 'mapped', '%x' % bi)
            if not os.path.exists(pb):
                band_info[bi] = None
            else:
                band_info[bi] = (os.path.getsize(pb), open(pm, 'rb').read() if os.path.exists(pm) else b'')
        info = band_info[bi]
        if info is None or info[0] < bo + BS:
            return False
        m = info[1]
        if m == b'':
            return True                               # no map file: the whole piece is present
        if len(m) != 256:
            return False
        k = bo // BS
        return bool((m[k >> 3] >> (k & 7)) & 1)
    if spec.startswith('capture:'):
        _, dev, img = spec.split(':', 2); src = rc.CaptureSrc(dev, img)
    else:
        src = rc.Src([spec])
    base = src.parts[0][4] if hasattr(src, 'parts') else 0      # byte offset of the container inside an image with a partition table
    c = rc.Container(src)
    sm = rc.Spaceman(c)
    bm = sm.load_bitmap()
    croot, cnodes, centries, cprob = rc.read_omap(c, c.omap_oid)
    fs = c.fs_oids[0]
    apsb_paddr = max(e for e in centries[fs] if e[0] <= c.xid)[3]
    apsb = src.block(apsb_paddr)
    vol_omap = struct.unpack_from('<Q', apsb, 128)[0]
    om = src.block(vol_omap)
    root = struct.unpack_from('<Q', om, 48)[0]
    print('container xid %d, volume object map header @0x%x, tree root @0x%x' % (c.xid, vol_omap, root))

    # ---- walk the object map, remembering where every pointer is stored ---------------------
    node = {}        # paddr -> dict(level, parent, voff_in_parent)
    target = {}      # paddr -> (leaf paddr, value offset, oid, xid, flags, size)
    stack = [(root, None, None, None)]
    while stack:
        p, parent, voff_in_parent, lvl = stack.pop()
        b = src.block(p)
        if not rc.valid(b) or struct.unpack_from('<Q', b, 8)[0] != p:
            raise SystemExit('object-map node @0x%x is not valid' % p)
        flags, level, ents = rc.parse_btnode(b)
        if lvl is not None and level != lvl:
            raise SystemExit('object-map node @0x%x: level %d, expected %d' % (p, level, lvl))
        node[p] = dict(level=level, parent=parent, voff=voff_in_parent)
        for koff, kl, voff, vl in ents:
            if level > 0:
                stack.append((struct.unpack_from('<Q', b, voff)[0], p, voff, level - 1))
            else:
                oid, xid = struct.unpack_from('<QQ', b, koff)
                fl, size, paddr = struct.unpack_from('<IIQ', b, voff)
                if fl & 1:
                    continue
                if paddr in target:
                    raise SystemExit('block 0x%x is the target of two object-map entries' % paddr)
                target[paddr] = (p, voff, oid, xid, fl, size)
    print('object map: %d nodes, %d live mappings' % (len(node), len(target)))

    queued = {}
    for name in ('main', 'ip'):
        for xid, p, n in sm.queues[name]['entries']:
            for k in range(p, p + n):
                queued[k] = name
    # ---- which blocks to move ------------------------------------------------------------------
    if mode == '--queued':
        both = sorted(p for p in node if p in target)
        T = sorted(set(p for p in queued if p in node or p in target) | set(both))
        print('referenced blocks in a free queue: %d (object-map nodes %d, entry targets %d)'
              % (sum(1 for p in T if p in queued), sum(1 for p in T if p in node and p in queued), sum(1 for p in T if p in target and p not in node and p in queued)))
        print('object-map nodes that an entry also points at (moved as nodes; the entry keeps the old block): %d, of these queued: %d'
              % (len(both), sum(1 for p in both if p in queued)))
        if any(p in queued for p in both):
            raise SystemExit('a block that is both a node and an entry target is queued; not handled')
    elif mode == '--random':
        n = int(a[5]); rnd = random.Random(int(a[6]) if len(a) > 6 else 1)
        nn = sorted(node); tt = sorted(target)
        T = sorted(set(rnd.sample(nn, min(len(nn), max(3, n // 5))) + [root] + rnd.sample(tt, min(len(tt), n))))
        print('test selection: %d blocks (object-map nodes %d incl. the root, entry targets %d)'
              % (len(T), sum(1 for p in T if p in node), sum(1 for p in T if p in target)))
    else:
        T = sorted(set(int(x, 0) for x in open(a[5]).read().split()))
    bad = [p for p in T if p not in node and p not in target]
    if bad:
        raise SystemExit('cannot handle %d blocks that are neither object-map nodes nor entry targets, e.g. 0x%x' % (len(bad), bad[0]))
    if not T:
        print('nothing to move'); return 0
    for p in T:
        if p in target and p not in node:
            leaf, voff, oid, xid, fl, size = target[p]
            if fl & 4:
                raise SystemExit('entry target 0x%x is encrypted; this tool only handles unencrypted volumes' % p)
            if size != BS:
                raise SystemExit('entry target 0x%x has size %d; only single blocks are handled' % (p, size))

    # ---- free blocks to move them to -------------------------------------------------------------
    per = sm.blocks_per_chunk
    ip_lo, ip_hi = sm.ip_base, sm.ip_base + sm.ip_block_count
    need = len(T); pick = []
    # walk the chunk-info entries, take chunks that have a bitmap block and plenty of free space
    cidx = 0
    cand = []
    for aaddr in sm.cib_addrs:
        cib = src.block(aaddr)
        for e in range(struct.unpack_from('<I', cib, 36)[0]):
            xid, addr, bcount, fcount, bmaddr = struct.unpack_from('<QQIIQ', cib, 40 + 32 * e)
            f = fcount & 0xFFFFF
            if bmaddr and f >= 2048 and bcount == per:
                cand.append((cidx, addr, f))
            cidx += 1
    if not cand:
        raise SystemExit('no chunk with a bitmap block and enough free space')
    if bundle is None:
        cand.sort(key=lambda x: -x[2])
    else:
        # in a sparse bundle, free space that physically exists is space that was used before:
        # look at chunks that are partly used, fullest first
        cand = [x for x in cand if x[2] < per]
        cand.sort(key=lambda x: -x[2])
    used_chunks = 0
    tried = 0
    for ci, addr, f in cand:
        if len(pick) >= need:
            break
        bits = np.unpackbits(bm[addr // 8:(addr + per) // 8], bitorder='little')
        free = [addr + int(i) for i in np.nonzero(bits == 0)[0]]
        free = [b for b in free if b not in queued and not (ip_lo <= b < ip_hi) and b not in node and b not in target
                and not (c.desc_base <= b < c.desc_base + c.desc_blocks) and not (c.data_base <= b < c.data_base + c.data_blocks)]
        if bundle is None:
            # stay clear of the edges of free runs: take from the middle of the chunk's free list
            take = free[len(free) // 4:len(free) // 4 + (need - len(pick))]
        else:
            take = [b for b in free if present(b)][:min(1024, need - len(pick))]
            tried += 1
            if tried > 4000:
                break
        if take:
            pick += take; used_chunks += 1
        if bundle is not None and used_chunks >= 200:
            break
    if len(pick) < need:
        raise SystemExit('not enough free blocks found: %d of %d after trying %d chunks (%d used)' % (len(pick), need, tried, used_chunks))
    newp = dict(zip(T, pick))
    print('new blocks: %d, taken from %d chunk(s), 0x%x .. 0x%x' % (len(pick), used_chunks, min(pick), max(pick)))

    # ---- build the patch ---------------------------------------------------------------------------
    work = {}                                          # original paddr of an object-map node -> bytearray

    def w(p):
        if p not in work:
            work[p] = bytearray(src.block(p))
        return work[p]
    patch = {}
    header = None
    mismatch = []
    for p in T:
        if p in target and p not in node:
            leaf, voff, oid, xid, fl, size = target[p]
            blk = src.block(p)
            o_oid, o_xid = struct.unpack_from('<QQ', blk, 8)
            if not rc.valid(blk) or o_oid != oid or o_xid != xid:
                mismatch.append((p, oid, xid, o_oid, o_xid, rc.valid(blk)))
                continue
            patch[newp[p]] = blk
            lb = w(leaf)
            if struct.unpack_from('<Q', lb, voff + 8)[0] != p:
                raise SystemExit('internal: entry for 0x%x not where expected' % p)
            struct.pack_into('<Q', lb, voff + 8, newp[p])
    if mismatch:
        with open(patch_out + '.mismatch', 'w') as f:
            for m in mismatch:
                f.write('%x oid %x xid %d holds oid %x xid %d checksum %s\n' % (m[0], m[1], m[2], m[3], m[4], 'ok' if m[5] else 'bad'))
        raise SystemExit('%d entry targets do not hold the object their entry names (list in %s.mismatch); stopping' % (len(mismatch), patch_out))
    for p in T:
        if p in node:
            info = node[p]
            w(p)
            if info['parent'] is None:
                header = bytearray(om)
                struct.pack_into('<Q', header, 48, newp[p])
            else:
                pb = w(info['parent'])
                if struct.unpack_from('<Q', pb, info['voff'])[0] != p:
                    raise SystemExit('internal: pointer to 0x%x not where expected' % p)
                struct.pack_into('<Q', pb, info['voff'], newp[p])
    for p, b in work.items():
        final = newp.get(p, p)
        struct.pack_into('<Q', b, 8, final)             # a physical object's id is its block number
        patch[final] = resum(b)
    if header is not None:
        patch[vol_omap] = resum(header)
    overl = [p for p in patch if p in pick and p in work]
    with open(patch_out, 'wb') as f:
        f.write(r.PATCH_MAGIC + struct.pack('<QI', base, len(patch)))
        for p in sorted(patch):
            f.write(struct.pack('<Q', p) + patch[p])
    print('patch: %d blocks (%d moved copies, %d object-map pages edited in place%s) -> %s'
          % (len(patch), len(pick), len(patch) - len(pick) - (1 if header is not None else 0), ', object-map header' if header is not None else '', patch_out))
    with open(patch_out + '.map', 'w') as f:
        for p in T:
            f.write('%x %x %s\n' % (p, newp[p], 'omap-node' if p in node else 'target oid %x xid %d' % (target[p][2], target[p][3])))

    # ---- space manager: the new blocks become allocated -------------------------------------------
    class S:                                            # what spaceman_fix needs from a source
        off = base
        block = staticmethod(lambda b: src.block(b))
    s2 = sf.Spaceman(S, c.xid)
    sf.edit(s2, set(pick), True, space_out)
    if hasattr(src, 'close'):
        src.close()
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
