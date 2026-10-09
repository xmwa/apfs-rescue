#!/usr/bin/env python3
"""Write workload for the rehearsal (gate G3). Works only inside <mountpoint>/_wtest and in files
named zz_wtest_* that it creates itself; never changes an existing file.
  write_workload.py <mountpoint> <phase A|B|C> <state.json> [rounds]
A: create, overwrite, rename, delete; new 8 MiB pieces inside each sparsebundle; one large file.
B: (after a remount) verify everything A left behind, then more of the same.
C: (after another remount) verify, then delete every test file."""
import hashlib, json, os, random, sys, time

mnt, phase, state_path = sys.argv[1], sys.argv[2], sys.argv[3]
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 150
if not os.path.ismount(mnt):
    raise SystemExit('%s is not a mount point' % mnt)
st = os.statvfs(mnt)
if st.f_flag & 1:
    raise SystemExit('volume is mounted read-only')
root = os.path.join(mnt, '_wtest')
state = json.load(open(state_path)) if os.path.exists(state_path) else {'files': {}, 'log': []}
files = state['files']
rnd = random.Random(20261006 + len(state['log']))
written = 0


def put(path, size):
    global written
    data = rnd.randbytes(size)
    with open(path, 'wb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())
    files[path] = hashlib.sha256(data).hexdigest()
    written += size


def verify():
    bad = 0
    for p, h in list(files.items()):
        try:
            d = open(p, 'rb').read()
        except OSError as e:
            print('VERIFY FAIL cannot read', p, e); bad += 1; continue
        if hashlib.sha256(d).hexdigest() != h:
            print('VERIFY FAIL content differs', p); bad += 1
    return bad


def bundle_dirs():
    tm = os.path.join(mnt, 'Time Machine')
    out = []
    for n in sorted(os.listdir(tm)):
        b = os.path.join(tm, n, 'bands')
        if n.endswith('.sparsebundle') and os.path.isdir(b):
            out.append(b)
    return out


def churn(n_rounds, tag):
    os.makedirs(root, exist_ok=True)
    mine = [p for p in files if p.startswith(root)]
    for i in range(n_rounds):
        d = os.path.join(root, '%s_d%03d' % (tag, i // 10))
        os.makedirs(d, exist_ok=True)
        for j in range(20):
            p = os.path.join(d, 'f%03d_%02d.bin' % (i, j)); put(p, rnd.randint(1, 200) * 1024); mine.append(p)
        if i % 5 == 0:
            p = os.path.join(d, 'm%03d.bin' % i); put(p, rnd.randint(4, 16) << 20); mine.append(p)
        if i % 7 == 3 and len(mine) > 60:                       # delete
            for p in rnd.sample(mine, 25):
                os.remove(p); files.pop(p, None); mine.remove(p)
        if i % 11 == 5 and len(mine) > 20:                      # rename
            for p in rnd.sample(mine, 8):
                q = p + '.renamed'; os.rename(p, q); files[q] = files.pop(p); mine.remove(p); mine.append(q)
        if i % 13 == 6 and len(mine) > 20:                      # overwrite in place
            for p in rnd.sample(mine, 5):
                put(p, rnd.randint(1, 300) * 1024)
        os.sync()
        if i % 25 == 24:
            print('  %s round %d/%d, %d files, %.1f GB written' % (tag, i + 1, n_rounds, len(files), written / 1e9)); sys.stdout.flush()


t0 = time.time()
if phase == 'A':
    churn(rounds, 'a')
    for b in ([] if os.environ.get('WTEST_NO_BUNDLES') else bundle_dirs()):   # new pieces inside each backup image's folder (rehearsal copies only)
        for k in range(12):
            put(os.path.join(b, 'zz_wtest_%02d' % k), 8 << 20)
        os.sync()
        for k in range(0, 12, 2):
            p = os.path.join(b, 'zz_wtest_%02d' % k); os.remove(p); files.pop(p, None)
        os.sync()
    os.makedirs(root, exist_ok=True)
    big = os.path.join(root, 'big.bin'); h = hashlib.sha256()
    with open(big, 'wb') as f:
        for _ in range(int(os.environ.get('WTEST_BIG_CHUNKS', '96'))):
            d = rnd.randbytes(16 << 20); f.write(d); h.update(d); written += len(d)
        f.flush(); os.fsync(f.fileno())
    files[big] = h.hexdigest()
elif phase == 'B':
    bad = verify(); print('phase B verify: %d files, %d bad' % (len(files), bad))
    if bad: sys.exit(5)
    churn(rounds, 'b')
elif phase == 'C':
    bad = verify(); print('phase C verify: %d files, %d bad' % (len(files), bad))
    if bad: sys.exit(5)
    for p in list(files):
        os.remove(p); files.pop(p)
    import shutil
    shutil.rmtree(root, ignore_errors=True)
    os.sync()
os.sync()
state['log'].append({'phase': phase, 'seconds': round(time.time() - t0), 'bytes_written': written, 'files_now': len(files)})
json.dump(state, open(state_path, 'w'))
print('phase %s done: %.2f GB written in %d s, %d test files on the volume' % (phase, written / 1e9, time.time() - t0, len(files)))
