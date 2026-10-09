#!/usr/bin/env python3
"""Large write and read-back test.   bigwrite.py write <dir> <n_files> <state.json> | verify <state.json> | delete <state.json>
Each file is 1 GiB of pseudo-random data; SHA-256 of what was written is kept in the state file
(on the internal SSD) and compared with what the drive returns later."""
import hashlib, json, os, random, sys, time
cmd = sys.argv[1]
if cmd == 'write':
    d, n, sp = sys.argv[2], int(sys.argv[3]), sys.argv[4]
    os.makedirs(d, exist_ok=True)
    rnd = random.Random(987654321); files = {}; t = time.time()
    for i in range(n):
        p = os.path.join(d, 'big_%04d.bin' % i); h = hashlib.sha256()
        with open(p, 'wb') as f:
            for _ in range(64):
                b = rnd.randbytes(16 << 20); f.write(b); h.update(b)
            f.flush(); os.fsync(f.fileno())
        files[p] = h.hexdigest()
        if i % 10 == 9: print('  written %d/%d GiB, %.0f MB/s' % (i + 1, n, (i + 1) * 1024 / (time.time() - t))); sys.stdout.flush()
    os.sync(); json.dump({'dir': d, 'files': files}, open(sp, 'w'))
    print('write done: %d GiB in %d s' % (n, time.time() - t))
elif cmd == 'verify':
    st = json.load(open(sys.argv[2])); bad = 0; t = time.time()
    for i, (p, hx) in enumerate(sorted(st['files'].items())):
        h = hashlib.sha256()
        try:
            with open(p, 'rb') as f:
                while True:
                    b = f.read(16 << 20)
                    if not b: break
                    h.update(b)
        except OSError as e:
            print('VERIFY FAIL cannot read', p, e); bad += 1; continue
        if h.hexdigest() != hx: print('VERIFY FAIL content differs', p); bad += 1
    print('verify done: %d files, %d bad, %d s' % (len(st['files']), bad, time.time() - t))
    sys.exit(5 if bad else 0)
elif cmd == 'delete':
    st = json.load(open(sys.argv[2]))
    for p in st['files']:
        if os.path.exists(p): os.remove(p)
    try: os.rmdir(st['dir'])
    except OSError: pass
    os.sync(); print('deleted')
