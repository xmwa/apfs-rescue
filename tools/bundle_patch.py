#!/usr/bin/env python3
"""Apply (or undo) block patches to an APFS partition inside a sparsebundle by
writing directly into its band files. The bundle must not be attached.

  bundle_patch.py check <bundle> <part_offset> <expected_originals>... -- <patch>...
  bundle_patch.py apply <bundle> <part_offset> <undo_out> <patch>...
  bundle_patch.py undo  <bundle> <part_offset> <undo_file>

check : read-only. The current content of every block a patch touches must equal
        the originals saved during the rehearsal (same order as the patches).
apply : saves the current content of all touched blocks to <undo_out>, writes
        the patches in the given order, syncs, and reads every block back.
"""
import os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import omap_repair as r
BS, BAND = 4096, 8388608

def loc(bundle, off, paddr):
    bi, bo = divmod(off + paddr * BS, BAND)
    return os.path.join(bundle, "bands", "%x" % bi), os.path.join(bundle, "mapped", "%x" % bi), bo

def read(bundle, off, paddr):
    pb, pm, bo = loc(bundle, off, paddr)
    with open(pb, "rb") as f:
        f.seek(bo); d = f.read(BS)
    if len(d) != BS: raise SystemExit("band %s is too short for block 0x%x" % (pb, paddr))
    if os.path.exists(pm):
        m = open(pm, "rb").read(); i = bo // BS
        if len(m) == 256 and not (m[i >> 3] >> (i & 7)) & 1:
            raise SystemExit("block 0x%x is not marked as present in its band map; not handled" % paddr)
    return d

def attached(bundle):
    import subprocess
    return os.path.realpath(bundle) in subprocess.run(["hdiutil", "info"], capture_output=True, text=True).stdout

def main(a):
    if len(a) < 4: print(__doc__); return 2
    cmd, bundle, off = a[1], a[2], int(a[3])
    if cmd == "check":
        sep = a.index("--"); origs, patches = a[4:sep], a[sep + 1:]
        if len(origs) != len(patches): raise SystemExit("need one originals file per patch")
        cur = {}; bad = 0; n = 0
        for of, pf in zip(origs, patches):
            _, ob = r.read_patch(of); _, pb = r.read_patch(pf)
            if [p for p, _ in ob] != [p for p, _ in pb]: raise SystemExit("%s does not belong to %s" % (of, pf))
            for (p, o), (_, new) in zip(ob, pb):
                have = cur.get(p) or read(bundle, off, p); n += 1
                if have != o: bad += 1
                cur[p] = new
        print("blocks checked: %d, differing from the rehearsal's originals: %d" % (n, bad))
        return 1 if bad else 0
    if cmd == "apply":
        undo, patches = a[4], a[5:]
        if attached(bundle): raise SystemExit("the bundle is attached; detach it first")
        if os.path.exists(undo): raise SystemExit("undo file exists, refusing to overwrite")
        seq = []
        for pf in patches:
            _, pb = r.read_patch(pf); seq += pb
        touched = sorted(set(p for p, _ in seq))
        with open(undo, "wb") as u:
            u.write(r.PATCH_MAGIC + struct.pack("<QI", off, len(touched)))
            for p in touched: u.write(struct.pack("<Q", p) + read(bundle, off, p))
            u.flush(); os.fsync(u.fileno())
        final = {}; files = set()
        for p, blk in seq:
            pb, pm, bo = loc(bundle, off, p)
            fd = os.open(pb, os.O_RDWR)
            if os.pwrite(fd, blk, bo) != BS: raise SystemExit("short write in %s" % pb)
            os.fsync(fd); os.close(fd); final[p] = blk; files.add(pb)
        os.sync()
        badr = sum(1 for p, blk in final.items() if read(bundle, off, p) != blk)
        print("wrote %d blocks (%d distinct) into %d band files; originals saved in %s; read-back mismatches: %d" % (len(seq), len(final), len(files), undo, badr))
        return 1 if badr else 0
    if cmd == "undo":
        if attached(bundle): raise SystemExit("the bundle is attached; detach it first")
        _, ub = r.read_patch(a[4])
        for p, blk in ub:
            pb, pm, bo = loc(bundle, off, p); fd = os.open(pb, os.O_RDWR); os.pwrite(fd, blk, bo); os.fsync(fd); os.close(fd)
        os.sync(); print("restored %d original blocks" % len(ub)); return 0
    print(__doc__); return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv))
