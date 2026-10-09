#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["numpy"]
# ///
"""Second drive repair, planning step (read-only; writes only patch files in the project folder).

Puts the 106 lost file-index leaves back from the copy saved on the pre-repair dump date:
  1. picks a free block for each (free in the bitmap, in no free queue, inside the index zone),
  2. has apfs-reloc re-encrypt the saved node for its new block          -> wd2-nodes.patch
  3. points the object-map entry of each node at the new block            -> wd2-omap.patch
  4. marks the new blocks as allocated in the space manager               -> wd2-space.patch

  repair2_plan.py <image> <refs_log_with_WRONGOID> <pre_repair_used_nodes> <pre_repair_dump> <password_cmd_output_on_stdin>
"""
import os, re, struct, subprocess, sys
import numpy as np
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import refcheck as rc
import omap_repair as r
import spaceman_fix as sf

BS = 4096


def main(a):
    image, refs_log, used_path, old_copy = a[1:5]
    password = sys.stdin.buffer.read()
    # --- the damaged leaves and what their parents expect ---------------------------------
    bad = {}
    for l in open(refs_log):
        m = re.match(r'WRONGOID F oid (0x[0-9a-f]+): block @(0x[0-9a-f]+) holds oid (0x[0-9a-f]+) xid (\d+) level (\d+) \(parent (0x[0-9a-f]+) xid (\d+) index (\d+)\): ids (\d+)/(\d+)\.\.(\d+)/(\d+)( \(to end)?', l)
        if m:
            bad[int(m.group(1), 16)] = dict(cur_paddr=int(m.group(2), 16), lo=(int(m.group(9)), int(m.group(10))),
                                            hi=None if m.group(13) else (int(m.group(11)), int(m.group(12))))
    print('damaged leaves:', len(bad))
    used = {}
    for l in open(used_path):
        t = l.split()
        used[int(t[0], 16)] = (int(t[1], 16), int(t[2], 16), int(t[3]))
    miss = [o for o in bad if o not in used]
    if miss:
        raise SystemExit('no saved version known for: %s' % [hex(o) for o in miss])

    # --- current state: bitmap, queues, object map -----------------------------------------
    src = rc.Src([image])
    c = rc.Container(src)
    sm = rc.Spaceman(c)
    bm = sm.load_bitmap()
    queued = set()
    for name in ('main', 'ip'):
        for xid, p, n in sm.queues[name]['entries']:
            queued.update(range(p, p + n))
    croot, cnodes, centries, cprob = rc.read_omap(c, c.omap_oid)
    fs = c.fs_oids[0]
    apsb_paddr = max(e for e in centries[fs] if e[0] <= c.xid)[3]
    apsb = src.block(apsb_paddr)
    vol_omap = struct.unpack_from('<Q', apsb, 128)[0]
    print('container xid %d; volume superblock @0x%x; volume object map @0x%x' % (c.xid, apsb_paddr, vol_omap))

    # --- 1. free blocks inside the index zone ----------------------------------------------
    ZLO, ZHI = 0x6a3b6, 0xf4313
    zone_bits = np.unpackbits(bm[ZLO // 8:(ZHI + 7) // 8], bitorder='little')
    base = (ZLO // 8) * 8
    free = [base + int(i) for i in np.nonzero(zone_bits == 0)[0] if ZLO <= base + int(i) < ZHI and (base + int(i)) not in queued]
    print('free blocks in the index zone (not queued): %d' % len(free))
    # stay away from the damaged spots and take blocks from the upper, emptier part of the zone
    taken = set(v['cur_paddr'] for v in bad.values())
    free = [b for b in free if b not in taken]
    if len(free) < len(bad) + 1000:
        raise SystemExit('too few free blocks in the zone')
    pick = free[len(free) // 2:len(free) // 2 + len(bad)]
    order = sorted(bad, key=lambda o: bad[o]['lo'])
    newp = dict(zip(order, pick))

    lst = os.path.join(HERE, 'wd2-nodes.list')
    with open(lst, 'w') as f:
        for o in order:
            xid, oldp, lvl = used[o]
            f.write('%x %x %x %x\n' % (o, xid, oldp, newp[o]))
    # --- 2. re-encrypt the saved nodes -------------------------------------------------------
    p = subprocess.run([os.path.join(HERE, 'apfs-fuse/build-clt4/apfs-reloc'), image, old_copy, '0', lst, os.path.join(HERE, 'wd2-nodes.patch')],
                       input=password, capture_output=True)
    rep = [l for l in p.stdout.decode(errors='replace').splitlines() if l.startswith(('OK ', 'BAD '))]
    open(os.path.join(HERE, 'wd2-nodes.report'), 'w').write('\n'.join(rep) + '\n')
    nbad = sum(1 for l in rep if l.startswith('BAD'))
    print('apfs-reloc: %d prepared, %d rejected (exit %d)' % (len(rep) - nbad, nbad, p.returncode))
    for l in rep:
        if l.startswith('BAD'):
            print('   ', l)
    if nbad or p.returncode or len(rep) != len(bad):
        raise SystemExit('not every node could be prepared; stopping')
    # fit under the parent: first key must be the parent's key, last key below the next sibling's
    fit_bad = 0
    for l in rep:
        t = l.split()
        o = int(t[1], 16)
        fk = tuple(int(x) for x in t[7].split('/')); lk = tuple(int(x) for x in t[8].split('/'))
        exp = bad[o]
        prob = []
        if fk != exp['lo']:
            prob.append('first key %s, parent expects %s' % (fk, exp['lo']))
        if exp['hi'] is not None and not (lk < exp['hi']):
            prob.append('last key %s reaches the next sibling %s' % (lk, exp['hi']))
        if int(t[5]) != 0:
            prob.append('level %s' % t[5])
        if prob:
            fit_bad += 1
            print('   oid 0x%x (saved xid %d): %s' % (o, used[o][0], '; '.join(prob)))
    print('saved nodes that do not fit where the parent puts them: %d' % fit_bad)

    # --- 3. object-map entries ---------------------------------------------------------------
    want = {o: (used[o][0], newp[o]) for o in bad}       # oid -> (xid of the restored version, new block)
    patched = {}
    found = set()

    def walk(pb):
        b = bytearray(src.block(pb))
        if not rc.valid(bytes(b)) or struct.unpack_from('<Q', b, 8)[0] != pb:
            raise SystemExit('omap node @0x%x invalid' % pb)
        flags, level, ents = rc.parse_btnode(bytes(b))
        changed = False
        for koff, kl, voff, vl in ents:
            oid, xid = struct.unpack_from('<QQ', b, koff)
            if level > 0:
                # descend only where a wanted oid can be
                walk(struct.unpack_from('<Q', b, voff)[0])
            elif oid in want:
                wx, wp = want[oid]
                fl, size, paddr = struct.unpack_from('<IIQ', b, voff)
                if oid in found:
                    raise SystemExit('oid 0x%x has more than one object-map entry' % oid)
                found.add(oid)
                if xid != wx:
                    struct.pack_into('<Q', b, koff + 8, wx)
                struct.pack_into('<Q', b, voff + 8, wp)
                changed = True
        if changed:
            struct.pack_into('<Q', b, 0, r.fletcher64(bytes(b[8:])))
            patched[pb] = bytes(b)
    om = src.block(vol_omap)
    walk(struct.unpack_from('<Q', om, 48)[0])
    if found != set(want):
        raise SystemExit('object-map entries not found for: %s' % [hex(o) for o in set(want) - found])
    with open(os.path.join(HERE, 'wd2-omap.patch'), 'wb') as f:
        f.write(r.PATCH_MAGIC + struct.pack('<QI', 0, len(patched)))
        for pb in sorted(patched):
            f.write(struct.pack('<Q', pb) + patched[pb])
    print('object map: %d entries changed in %d leaf pages -> wd2-omap.patch' % (len(found), len(patched)))

    # --- 4. space manager --------------------------------------------------------------------
    s2 = sf.Spaceman(r.Source(image), c.xid)
    sf.edit(s2, set(pick), True, os.path.join(HERE, 'wd2-space.patch'))
    print('new blocks: 0x%x .. 0x%x' % (min(pick), max(pick)))
    return 0 if not fit_bad else 3


if __name__ == '__main__':
    sys.exit(main(sys.argv))
