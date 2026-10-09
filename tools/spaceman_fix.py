#!/usr/bin/env python3
"""Plan a fix for "underallocation" in an APFS container: blocks that are in
use but marked free in the space manager's bitmaps.

Read-only. Produces a patch file in the format of omap_repair.py; apply it with
`omap_repair.py apply` (to an overlay first).

  spaceman_fix.py plan  <source> <container_xid> <fsck_log> <patch_out>
  spaceman_fix.py info  <source> <container_xid>
  spaceman_fix.py break <source> <container_xid> <block> [<block> ...] <patch_out>
        (test helper: marks allocated blocks as free, to create the damage on a dummy)

<fsck_log> is the output of `fsck_apfs -n`, with lines like
  error: underallocation detected on Main device: (0x1d24321b+1) bitmap address (0x3bc75)

For every listed block the tool sets its bit in the chunk's bitmap block, lowers
the chunk's free count in its chunk-info block, and lowers the device free count
in the space manager object. Checksums are recomputed. Blocks are rewritten in
place; nothing is moved.
"""
import re
import struct
import sys

import omap_repair as r

BS = r.BS
OBJ = 32                      # sizeof(obj_phys_t)
CI_MASK = 0x000FFFFF


def valid(blk):
    return len(blk) >= BS and struct.unpack_from('<Q', blk, 0)[0] == r.fletcher64(blk[8:])


def resum(buf):
    b = bytearray(buf)
    struct.pack_into('<Q', b, 0, r.fletcher64(bytes(b[8:])))
    return bytes(b)


class Spaceman:
    def __init__(self, src, xid):
        self.src = src
        first = src.block(0)
        if first[32:36] != b'NXSB':
            raise SystemExit('no container superblock at block 0')
        desc_blocks, data_blocks, desc_base, data_base = struct.unpack_from('<IIQQ', first, 104)
        if desc_blocks & 0x80000000 or data_blocks & 0x80000000:
            raise SystemExit('checkpoint areas are not contiguous; not handled')
        # the container superblock of the wanted save point
        sb = None
        for i in range(desc_blocks):
            b = src.block(desc_base + i)
            if b[32:36] == b'NXSB' and struct.unpack_from('<Q', b, 16)[0] == xid and valid(b):
                sb = b
                self.sb_paddr = desc_base + i
        if sb is None:
            raise SystemExit('no valid container superblock with xid %d' % xid)
        self.xid = xid
        desc_index, desc_len = struct.unpack_from('<II', sb, 136)
        self.data_base, self.data_blocks = data_base, data_blocks
        sm_oid = struct.unpack_from('<Q', sb, 152)[0]
        # checkpoint maps of this save point
        self.sm_paddr = None
        for k in range(desc_len):
            p = desc_base + (desc_index + k) % desc_blocks
            b = src.block(p)
            if (struct.unpack_from('<I', b, 24)[0] & 0xffff) != 0xc or not valid(b):
                continue
            count = struct.unpack_from('<I', b, 36)[0]
            for j in range(count):
                typ, sub, size, pad, fs_oid, oid, paddr = struct.unpack_from('<IIIIQQQ', b, 40 + 40 * j)
                if oid == sm_oid:
                    self.sm_paddr, self.sm_size = paddr, size
        if self.sm_paddr is None:
            raise SystemExit('space manager object not found in the checkpoint map')
        self.sm_nblocks = self.sm_size // BS
        self.sm_blocks = [data_base + (self.sm_paddr - data_base + i) % data_blocks for i in range(self.sm_nblocks)]
        self.sm = b''.join(src.block(p) for p in self.sm_blocks)
        if struct.unpack_from('<Q', self.sm, 0)[0] != r.fletcher64(self.sm[8:]):
            raise SystemExit('space manager object fails its checksum')
        if (struct.unpack_from('<I', self.sm, 24)[0] & 0xffff) != 5:
            raise SystemExit('object is not a space manager')
        self.blocks_per_chunk, self.chunks_per_cib, self.cibs_per_cab = struct.unpack_from('<III', self.sm, 36)
        (self.block_count, self.chunk_count, self.cib_count, self.cab_count,
         self.free_count, self.addr_offset) = struct.unpack_from('<QQIIQI', self.sm, 48)
        # chunk-info block addresses
        n = self.cab_count if self.cab_count else self.cib_count
        top = list(struct.unpack_from('<%dQ' % n, self.sm, self.addr_offset))
        if self.cab_count:
            self.cib_addrs = []
            for a in top:
                cab = src.block(a)
                if not valid(cab):
                    raise SystemExit('cib address block @0x%x fails its checksum' % a)
                cnt = struct.unpack_from('<I', cab, 36)[0]
                self.cib_addrs += list(struct.unpack_from('<%dQ' % cnt, cab, 40))
        else:
            self.cib_addrs = top
        self.cibs = {}

    def cib(self, index):
        if index not in self.cibs:
            b = self.src.block(self.cib_addrs[index])
            if not valid(b) or (struct.unpack_from('<I', b, 24)[0] & 0xffff) != 7:
                raise SystemExit('chunk-info block %d @0x%x is not valid' % (index, self.cib_addrs[index]))
            self.cibs[index] = bytearray(b)
        return self.cibs[index]

    def chunk(self, block):
        """(cib index, entry offset in the cib, first block of the chunk, free count field, bitmap paddr)"""
        c = block // self.blocks_per_chunk
        ci, ei = divmod(c, self.chunks_per_cib)
        b = self.cib(ci)
        if ei >= struct.unpack_from('<I', b, 36)[0]:
            raise SystemExit('block 0x%x: chunk entry %d is beyond its chunk-info block' % (block, ei))
        off = 40 + 32 * ei
        xid, addr, bcount, fcount, bm = struct.unpack_from('<QQIIQ', b, off)
        if addr != c * self.blocks_per_chunk:
            raise SystemExit('block 0x%x: chunk entry starts at 0x%x, expected 0x%x' % (block, addr, c * self.blocks_per_chunk))
        return ci, off, addr, fcount, bm

    def describe(self):
        print('container save point xid %d, superblock @0x%x' % (self.xid, self.sb_paddr))
        print('space manager @0x%x (%d blocks): %d blocks in %d chunks of %d; %d chunk-info blocks, %d address blocks; free count %d'
              % (self.sm_paddr, self.sm_nblocks, self.block_count, self.chunk_count, self.blocks_per_chunk,
                 self.cib_count, self.cab_count, self.free_count))


def zero_bits(bm):
    return len(bm) * 8 - sum(bin(x).count('1') for x in bm)


def edit(sm, blocks, to_allocated, patch_path, expect_bitmap=None):
    src = sm.src
    bitmaps = {}
    changed = 0
    already = 0
    per_chunk = {}
    for blk in sorted(blocks):
        ci, off, addr, fcount, bm_paddr = sm.chunk(blk)
        if bm_paddr == 0:
            raise SystemExit('block 0x%x: its chunk has no bitmap block (chunk recorded as entirely free); not handled' % blk)
        if expect_bitmap and blk in expect_bitmap and expect_bitmap[blk] != bm_paddr:
            raise SystemExit('block 0x%x: bitmap is @0x%x, fsck reported 0x%x' % (blk, bm_paddr, expect_bitmap[blk]))
        if bm_paddr not in bitmaps:
            raw = src.block(bm_paddr)
            if (fcount & CI_MASK) != zero_bits(raw):
                raise SystemExit('chunk at 0x%x: free count %d does not match its bitmap (%d free bits); layout not as assumed'
                                 % (addr, fcount & CI_MASK, zero_bits(raw)))
            bitmaps[bm_paddr] = bytearray(raw)
        bm = bitmaps[bm_paddr]
        i = blk - addr
        bit = (bm[i >> 3] >> (i & 7)) & 1
        if bit == (1 if to_allocated else 0):
            already += 1
            continue
        bm[i >> 3] ^= 1 << (i & 7)
        changed += 1
        per_chunk[(ci, off)] = per_chunk.get((ci, off), 0) + 1
    delta = -1 if to_allocated else 1
    for (ci, off), n in per_chunk.items():
        b = sm.cib(ci)
        f = struct.unpack_from('<I', b, off + 20)[0]
        new = (f & CI_MASK) + delta * n
        if new < 0 or new > sm.blocks_per_chunk:
            raise SystemExit('free count would go out of range')
        struct.pack_into('<I', b, off + 20, (f & ~CI_MASK) | new)
    patches = {}
    for p, bm in bitmaps.items():
        patches[p] = bytes(bm)
    for ci in set(k[0] for k in per_chunk):
        patches[sm.cib_addrs[ci]] = resum(sm.cibs[ci])
    smb = bytearray(sm.sm)
    struct.pack_into('<Q', smb, 72, sm.free_count + delta * changed)
    smb = resum(smb)
    for k, p in enumerate(sm.sm_blocks):
        patches[p] = smb[k * BS:(k + 1) * BS]
    with open(patch_path, 'wb') as f:
        f.write(r.PATCH_MAGIC + struct.pack('<QI', src.off, len(patches)))
        for p in sorted(patches):
            f.write(struct.pack('<Q', p) + patches[p])
    print('blocks to mark %s: %d (already so: %d); bitmap blocks touched: %d; chunk-info blocks touched: %d'
          % ('allocated' if to_allocated else 'free', changed, already, len(bitmaps), len(set(k[0] for k in per_chunk))))
    print('device free count %d -> %d' % (sm.free_count, sm.free_count + delta * changed))
    print('patch: %d blocks -> %s' % (len(patches), patch_path))


def main(a):
    if len(a) >= 4 and a[1] == 'info':
        sm = Spaceman(r.Source(a[2]), int(a[3]))
        sm.describe()
        # self-consistency of the layout on a sample of chunks, and of the totals
        import random
        random.seed(1)
        total = 0
        bad = 0
        sample = set(random.sample(range(sm.chunk_count), min(300, sm.chunk_count)))
        for c in range(sm.chunk_count):
            ci, ei = divmod(c, sm.chunks_per_cib)
            xid, addr, bcount, fcount, bm = struct.unpack_from('<QQIIQ', sm.cib(ci), 40 + 32 * ei)
            total += fcount & CI_MASK
            if c in sample and bm:
                if zero_bits(sm.src.block(bm)) != (fcount & CI_MASK):
                    bad += 1
        print('sum of chunk free counts: %d (space manager says %d, difference %d)' % (total, sm.free_count, total - sm.free_count))
        print('sampled chunks whose bitmap disagrees with their free count: %d of %d' % (bad, len(sample)))
        return 0
    if len(a) >= 6 and a[1] == 'plan':
        sm = Spaceman(r.Source(a[2]), int(a[3]))
        sm.describe()
        blocks, expect = set(), {}
        for line in open(a[4], errors='ignore'):
            m = re.search(r'underallocation detected on Main device: \(0x([0-9a-f]+)\+(\d+)\) bitmap address \(0x([0-9a-f]+)\)', line)
            if m:
                for i in range(int(m.group(2))):
                    blocks.add(int(m.group(1), 16) + i)
                    expect[int(m.group(1), 16) + i] = int(m.group(3), 16)
        print('underallocated blocks listed by fsck: %d' % len(blocks))
        if not blocks:
            raise SystemExit('nothing to do')
        edit(sm, blocks, True, a[5], expect)
        return 0
    if len(a) >= 6 and a[1] == 'break':
        sm = Spaceman(r.Source(a[2]), int(a[3]))
        sm.describe()
        edit(sm, set(int(x, 0) for x in a[4:-1]), False, a[-1])
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
