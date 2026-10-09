#!/usr/bin/env python3
"""Read-only: compare a random sample of files on the repaired drive (mounted by
macOS) with a copy made earlier. Usage: native-compare.py <sample_size> <mounted volume> <copy dir>"""
import hashlib, os, random, sys, time
SRC = sys.argv[2]; DST = os.path.expanduser(sys.argv[3])
N = int(sys.argv[1]) if len(sys.argv) > 1 else 4000
TOPS = ["ARIA2_layouts", "Workspace", "Corblivar", "tmp", "Backups"]
random.seed(20261006)
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        while True:
            b = f.read(1 << 20)
            if not b: break
            h.update(b)
    return h.hexdigest()
t0 = time.time(); cands = []; seen = 0
for top in TOPS:
    for d, ds, fs in os.walk(os.path.join(DST, top)):
        for f in fs:
            if f == ".DS_Store": continue
            seen += 1
            # reservoir sampling over all files
            p = os.path.join(d, f)
            if len(cands) < N: cands.append(p)
            else:
                j = random.randrange(seen)
                if j < N: cands[j] = p
print("files in the copies: %d, sampled: %d (listing took %.0fs)" % (seen, len(cands), time.time() - t0), flush=True)
ok = diff = missing = skipped = 0; nbytes = 0; t1 = time.time()
for i, p in enumerate(sorted(cands)):
    rel = os.path.relpath(p, DST); q = os.path.join(SRC, rel)
    try:
        if os.path.islink(p):
            if os.path.islink(q) and os.readlink(p) == os.readlink(q): ok += 1
            else: diff += 1; print("DIFF (symlink)", rel, flush=True)
            continue
        if not os.path.lexists(q): missing += 1; print("MISSING on drive", rel, flush=True); continue
        sz = os.path.getsize(p)
        if sz != os.path.getsize(q): diff += 1; print("DIFF (size)", rel, flush=True); continue
        if sz > 2 * 1024**3: skipped += 1; continue
        if sha(p) == sha(q): ok += 1; nbytes += sz
        else: diff += 1; print("DIFF (content)", rel, flush=True)
    except Exception as e:
        diff += 1; print("ERROR", rel, e, flush=True)
    if (i + 1) % 500 == 0:
        print("progress: %d of %d, identical %d, different %d, missing %d, %.1f GB, %.0fs" % (i + 1, len(cands), ok, diff, missing, nbytes / 1e9, time.time() - t1), flush=True)
print("RESULT: compared %d, identical %d, different %d, missing %d, skipped (>2 GB) %d, %.1f GB read, %.0fs" % (ok + diff, ok, diff, missing, skipped, nbytes / 1e9, time.time() - t1), flush=True)
