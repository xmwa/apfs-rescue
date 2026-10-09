#!/usr/bin/env python3
"""Plan a repair of an APFS volume object map (omap) that keeps several
versions per object (a volume with snapshots, e.g. a Time Machine backup).

Read-only. Produces a patch file in the format of omap_repair.py, which is
applied (to an overlay first) with `omap_repair.py apply`.

  omap_repair_mv.py plan <source> <omap_root_block> <target_xid> <used_nodes>
                         <rawscan_file> <snapshots_file> <patch_out>

  <used_nodes>     from apfs-audit: live file-system tree nodes "oid xid paddr level"
  <rawscan_file>   from apfs-rawscan: every valid object found on the device
  <snapshots_file> from apfs-snaps: "xid sblock name" per line

What goes into a rebuilt leaf for an object id range:
  - the live version of every object the current file-system tree uses
  - for every snapshot, the newest on-disk version not newer than the snapshot
  - entries of an older surviving copy of the leaf that still point at valid
    blocks (this keeps deletion markers)
Lost index pages are rebuilt from the surviving leaves that belong under them.
"""
import bisect
import collections
import struct
import sys

import omap_repair as r

BS = r.BS
LEAF_CAP = r.LEAF_CAPACITY          # 112
LEAF_FILL = 110
INDEX_CAP = r.INDEX_CAPACITY        # 144
INDEX_FILL = 120
DELETED = 1


def plan(source, root_paddr, target_xid, used_path, rawscan_path, snaps_path, patch_path):
    src = r.Source(source)

    snaps = sorted(int(l.split()[0]) for l in open(snaps_path) if l.strip() and l.split()[0].isdigit())
    snaps = [s for s in snaps if s <= target_xid]
    print('snapshots: %d (xid %d .. %d)' % (len(snaps), snaps[0], snaps[-1]))

    used = {}
    for line in open(used_path):
        p = line.split()
        if len(p) >= 3:
            used[int(p[0], 16)] = (int(p[1], 16), int(p[2], 16))
    print('live file-system tree nodes: %d' % len(used))

    # ---- pass 1: walk the tree, find lost pages and outdated leaves --------------
    root = r.parse_node(src.block(root_paddr), root_paddr)
    if not root or not (root['flags'] & 1):
        raise SystemExit('not a valid omap root')
    print('omap root @0x%x: level %d, %d keys, xid %d' % (root_paddr, root['level'], root['nkeys'], root['xid']))

    used_oids = sorted(used)
    reachable = set([root_paddr])
    bad = []                        # (level, paddr, lo_key, hi_key, parent_paddr, index)
    stale = []                      # (paddr, lo_key, hi_key, parent_paddr, index, node)
    first_key = {}                  # paddr -> first key, for untouched good pages
    parent_of = {}                  # paddr -> (parent paddr, index)
    good_keys = 0
    good_nodes = 1
    flag_kinds = collections.Counter()

    def live_in(lo_oid, hi_oid):
        a = bisect.bisect_left(used_oids, lo_oid)
        b = len(used_oids) if hi_oid is None else bisect.bisect_left(used_oids, hi_oid)
        return used_oids[a:b]

    def walk(node, hi):
        nonlocal good_keys, good_nodes
        for i, (key, val) in enumerate(node['entries']):
            b = val[0]
            chi = node['entries'][i + 1][0] if i + 1 < node['nkeys'] else hi
            parent_of[b] = (node['paddr'], i)
            child = r.parse_node(src.block(b), b)
            ok = (child and child['level'] == node['level'] - 1 and child['nkeys'] > 0
                  and child['entries'][0][0] == key and child['xid'] <= target_xid)
            if not ok:
                bad.append((node['level'] - 1, b, key, chi, node['paddr'], i))
                continue
            reachable.add(b)
            first_key[b] = key
            if child['level'] > 0:
                good_nodes += 1
                walk(child, chi)
                continue
            # leaf: every live object in its span must be mapped to its live version
            have = {}
            for (oid, xid), (flags, size, paddr) in child['entries']:
                flag_kinds[flags] += 1
                if not (flags & DELETED) and xid <= target_xid:
                    if oid not in have or xid > have[oid][0]:
                        have[oid] = (xid, paddr)
            wrong = 0
            for oid in live_in(key[0], chi[0] + 1 if chi else None):
                k = (oid, used[oid][0])
                if k >= key and (chi is None or k < chi) and have.get(oid) != used[oid]:
                    wrong += 1
            if wrong:
                stale.append((b, key, chi, node['paddr'], i, child, wrong))
            else:
                good_keys += child['nkeys']
                good_nodes += 1

    walk(root, None)
    print('pass 1: %d good pages, %d mappings in good leaves; lost pages: %s; outdated leaves: %d'
          % (good_nodes, good_keys, dict(collections.Counter(b[0] for b in bad)), len(stale)))
    print('entry flag kinds seen in good leaves: %s' % dict(flag_kinds))

    # ---- ranges that need rebuilt content -----------------------------------------
    ranges = [(b[2][0], b[3][0] if b[3] else None) for b in bad] + [(s[1][0], s[2][0] if s[2] else None) for s in stale]
    lo_all = min(x[0] for x in ranges)
    print('rebuild ranges: %d, lowest object id 0x%x' % (len(ranges), lo_all))

    # ---- load on-disk versions of file-system tree nodes and omap pages -----------
    versions = collections.defaultdict(list)      # oid -> [(xid, paddr)]
    omap_pages = {}                               # paddr -> (xid, level)
    max_oid = 0
    with open(rawscan_path) as f:
        for line in f:
            if line[0] != 'N':
                continue
            p = line.split()
            sub = p[4]
            if sub == 'e' and p[8] == '0':
                oid = int(p[1], 16)
                if oid < lo_all:
                    continue
                xid = int(p[2], 16)
                if xid <= target_xid:
                    versions[oid].append((xid, int(p[3], 16)))
                    if oid > max_oid:
                        max_oid = oid
            elif sub == 'b':
                paddr = int(p[3], 16)
                if int(p[1], 16) == paddr:
                    omap_pages[paddr] = (int(p[2], 16), int(p[5], 16))
    for v in versions.values():
        v.sort()
    ver_oids = sorted(versions)
    print('on-disk versions loaded for %d objects at or above 0x%x (highest 0x%x); omap pages on disk: %d'
          % (len(versions), lo_all, max_oid, len(omap_pages)))

    def needed(lo_key, hi_key):
        """Mappings a page for the key range [lo_key, hi_key) must hold:
        {(oid, xid): (flags, size, paddr)} and the uncertain ones. Page borders are
        (oid, xid) keys, so the versions of one object can be split between pages."""
        out = {}
        uncertain = set()
        lo_oid = lo_key[0]
        hi_oid = None if hi_key is None else hi_key[0] + 1
        a = bisect.bisect_left(ver_oids, lo_oid)
        b = len(ver_oids) if hi_oid is None else bisect.bisect_left(ver_oids, hi_oid)
        oids = set(ver_oids[a:b]) | set(live_in(lo_oid, hi_oid))
        for oid in oids:
            vers = versions.get(oid, [])
            if oid in used:
                ux, up = used[oid]
                out[(oid, ux)] = (0, BS, up)
            for i, (x, pa) in enumerate(vers):
                nxt = vers[i + 1][0] if i + 1 < len(vers) else None
                j = bisect.bisect_left(snaps, x)
                if j >= len(snaps):
                    continue                      # no snapshot at or after this version
                if nxt is not None and snaps[j] >= nxt:
                    continue                      # superseded before the next snapshot
                if (oid, x) not in out:
                    out[(oid, x)] = (0, BS, pa)
                    if nxt is None and oid not in used:
                        uncertain.add((oid, x))   # object may have been deleted before that snapshot
        out = dict((k, v) for k, v in out.items() if k >= lo_key and (hi_key is None or k < hi_key))
        uncertain = set(k for k in uncertain if k in out)
        return out, uncertain

    def in_range(key, lo_key, hi_key):
        return key >= lo_key and (hi_key is None or key < hi_key)

    def valid_entry(key, val):
        oid, xid = key
        flags, size, paddr = val
        if xid > target_xid:
            return False
        if flags & DELETED:
            return True
        return (xid, paddr) in versions.get(oid, ()) or used.get(oid) == (xid, paddr)

    # ---- orphaned leaves (on disk, not reachable) ----------------------------------
    orphan_blocks = sorted(p for p, (xid, lvl) in omap_pages.items() if p not in reachable and xid <= target_xid)
    orphan_leaves = []
    for p in orphan_blocks:
        if omap_pages[p][1] != 0:
            continue
        n = r.parse_node(src.block(p), p)
        if n and n['level'] == 0 and n['nkeys'] and n['entries'][0][0][0] >= lo_all - 200000:
            orphan_leaves.append(n)
    orphan_leaves.sort(key=lambda n: n['entries'][0][0])
    orphan_first = [n['entries'][0][0][0] for n in orphan_leaves]
    print('orphaned omap pages on disk: %d, of which leaves near the damaged ranges: %d' % (len(orphan_blocks), len(orphan_leaves)))

    pool = [p for p in orphan_blocks]            # blocks that hold superseded omap pages
    pool_used = set()

    def take_block(prefer=None):
        if prefer is not None and prefer in omap_pages and prefer not in pool_used and prefer not in reachable:
            pool_used.add(prefer)
            return prefer
        while pool:
            p = pool.pop()
            if p not in pool_used:
                pool_used.add(p)
                return p
        raise SystemExit('no spare omap blocks left')

    def is_current(leaf, lo_key, hi_key):
        ents = leaf['entries']
        if ents[0][0] < lo_key or (hi_key is not None and ents[-1][0] >= hi_key):
            return False
        if leaf['xid'] > target_xid:
            return False
        have = {}
        for key, val in ents:
            if not valid_entry(key, val):
                return False
            if not (val[0] & DELETED) and (key[0] not in have or key[1] > have[key[0]][0]):
                have[key[0]] = (key[1], val[2])
        for oid in live_in(ents[0][0][0], ents[-1][0][0] + 1):
            k = (oid, used[oid][0])
            if ents[0][0] <= k <= ents[-1][0] and have.get(oid) != used[oid]:
                return False
        return True

    patches = {}
    problems = []
    stats = collections.Counter()

    def pack(entries_sorted):
        """Split a sorted entry list into leaf-sized chunks without separating versions of one object."""
        chunks, cur = [], []
        i = 0
        while i < len(entries_sorted):
            j = i
            while j < len(entries_sorted) and entries_sorted[j][0][0] == entries_sorted[i][0][0]:
                j += 1
            grp = entries_sorted[i:j]
            if cur and len(cur) + len(grp) > LEAF_FILL:
                chunks.append(cur)
                cur = []
            cur = cur + grp
            i = j
        if cur:
            chunks.append(cur)
        return chunks

    def leaves_for_range(lo_key, hi_key, xid_for_new):
        """Ordered [(first_key, paddr)] of leaves covering the key range; rebuilt leaves are added to patches."""
        need, uncertain = needed(lo_key, hi_key)
        a = bisect.bisect_left(orphan_first, lo_key[0])
        b = len(orphan_first) if hi_key is None else bisect.bisect_right(orphan_first, hi_key[0])
        cands = [n for n in orphan_leaves[a:b] if n['paddr'] not in pool_used and is_current(n, lo_key, hi_key)]
        cands.sort(key=lambda n: -n['xid'])
        chosen = []
        for n in cands:
            f, l = n['entries'][0][0], n['entries'][-1][0]
            if all(l < c['entries'][0][0] or f > c['entries'][-1][0] for c in chosen):
                chosen.append(n)
        chosen.sort(key=lambda n: n['entries'][0][0])
        firsts = [n['entries'][0][0] for n in chosen]
        lasts = [n['entries'][-1][0] for n in chosen]
        covered = set()
        for n in chosen:
            pool_used.add(n['paddr'])
            for key, val in n['entries']:
                covered.add(key)
        stats['leaves_reattached'] += len(chosen)
        out = [(f, n['paddr']) for f, n in zip(firsts, chosen)]
        # Mappings no surviving leaf holds go into new leaves, but only in the gaps
        # between surviving leaves. Inside a surviving leaf's own span that leaf is
        # trusted: it was verified to hold every live version there.
        runs = collections.defaultdict(list)
        for k in sorted(need):
            if k in covered:
                continue
            i = bisect.bisect_right(firsts, k) - 1
            if i >= 0 and k <= lasts[i]:
                stats['rule_only_inside_surviving_leaf'] += 1
                if used.get(k[0], (None,))[0] == k[1]:
                    problems.append('live object 0x%x is not in the surviving leaf that spans it' % k[0])
                continue
            runs[i].append((k, need[k]))
        for idx in sorted(runs):
            for chunk in pack(runs[idx]):
                blk = take_block()
                patches[blk] = r.build_leaf(blk, xid_for_new, chunk)
                out.append((chunk[0][0], blk))
                stats['leaves_built'] += 1
                stats['mappings_built'] += len(chunk)
        out.sort()
        return out

    def build_index_pages(children, level, paddr, xid):
        """children: sorted [(first_key, paddr)]. Builds one page at <paddr>, adding lower index levels if needed."""
        if level == 1 or len(children) <= INDEX_CAP and level == 1:
            if len(children) > INDEX_CAP:
                problems.append('index @0x%x: %d leaves do not fit in one level-1 page' % (paddr, len(children)))
                return
            patches[paddr] = r.build_index(paddr, xid, 1, children)
            stats['index_built'] += 1
            return
        groups = [children[i:i + INDEX_FILL] for i in range(0, len(children), INDEX_FILL)]
        subs = []
        for g in groups:
            blk = take_block()
            build_index_pages(g, level - 1, blk, xid)
            subs.append((g[0][0], blk))
        if len(subs) > INDEX_CAP:
            problems.append('index @0x%x: %d sub-pages do not fit' % (paddr, len(subs)))
            return
        patches[paddr] = r.build_index(paddr, xid, level, subs)
        stats['index_built'] += 1

    new_first = {}                 # paddr -> first key after the rebuild

    # ---- lost pages ------------------------------------------------------------------
    for level, paddr, lo_key, hi_key, parent, idx in sorted(bad, key=lambda b: b[2]):
        if level == 0:
            need, uncertain = needed(lo_key, hi_key)
            # keep still-valid entries of the newest surviving older copy of this leaf
            a = bisect.bisect_left(orphan_first, lo_key[0])
            b = bisect.bisect_right(orphan_first, lo_key[0])
            olds = [n for n in orphan_leaves[a:b] if n['xid'] <= target_xid and n['paddr'] not in pool_used
                    and n['entries'][0][0] == lo_key]
            if olds:
                # An older copy of this very leaf survives. Trust it for everything it
                # could know: keep its still-valid entries, and take from the version
                # rule only what is newer than that copy (plus the live versions).
                old = max(olds, key=lambda n: n['xid'])
                old_keys = set(k for k, v in old['entries'])
                need = dict((k, v) for k, v in need.items()
                            if k in old_keys or k[1] > old['xid'] or used.get(k[0], (None,))[0] == k[1])
                for key, val in old['entries']:
                    if not in_range(key, lo_key, hi_key):
                        continue
                    if key not in need and valid_entry(key, val) and (key[0] not in used or val[0] & DELETED or key[1] < used[key[0]][0]):
                        need[key] = val
                stats['old_copies_used'] += 1
            ents = sorted(need.items())
            if len(ents) > LEAF_CAP:
                ents = [e for e in ents if e[0] not in uncertain]
            if len(ents) > LEAF_CAP:
                # last resort: drop the oldest non-live versions until it fits (history only)
                live = set((o, used[o][0]) for o in set(k[0] for k, v in ents) if o in used)
                extra = sorted((e for e in ents if e[0] not in live and not (e[1][0] & DELETED)), key=lambda e: e[0][1])
                drop = set(e[0] for e in extra[:len(ents) - LEAF_CAP])
                stats['history_versions_dropped'] += len(drop)
                ents = [e for e in ents if e[0] not in drop]
            if len(ents) > LEAF_CAP:
                problems.append('leaf @0x%x (0x%x..): %d mappings do not fit in one leaf' % (paddr, lo_key[0], len(ents)))
                continue
            if not ents:
                problems.append('leaf @0x%x (0x%x..): nothing to put in it' % (paddr, lo_key[0]))
                continue
            patches[paddr] = r.build_leaf(paddr, root['xid'], ents)
            new_first[paddr] = ents[0][0]
            stats['lost_leaves_rebuilt'] += 1
            stats['mappings_built'] += len(ents)
        else:
            children = leaves_for_range(lo_key, hi_key, root['xid'])
            if not children:
                problems.append('index @0x%x: no leaves found for 0x%x..' % (paddr, lo_key[0]))
                continue
            # verify ordering / no overlap between consecutive leaves is implied by the selection
            build_index_pages(children, level, paddr, root['xid'])
            new_first[paddr] = children[0][0]
            print('  lost level-%d page @0x%x [0x%x..%s]: %d leaves under it' % (level, paddr, lo_key[0], ('0x%x' % hi_key[0]) if hi_key else 'end', len(children)))

    # ---- outdated leaves that are still linked -----------------------------------------
    for paddr, lo_key, hi_key, parent, idx, node, wrong in stale:
        need, uncertain = needed(lo_key, hi_key)
        for key, val in node['entries']:
            if key not in need and valid_entry(key, val) and (key[0] not in used or val[0] & DELETED):
                need[key] = val
        ents = sorted(need.items())
        if len(ents) > LEAF_CAP:
            ents = [e for e in ents if e[0] not in uncertain]
        if len(ents) > LEAF_CAP or not ents:
            problems.append('outdated leaf @0x%x: %d mappings cannot be placed' % (paddr, len(ents)))
            continue
        patches[paddr] = r.build_leaf(paddr, root['xid'], ents)
        new_first[paddr] = ents[0][0]
        stats['outdated_leaves_rebuilt'] += 1

    # ---- keys in parents must equal the first key of the rebuilt child -----------------
    edited = {}                    # index page paddr -> current raw

    def node_now(p):
        raw = edited.get(p) or patches.get(p) or src.block(p)
        return r.parse_node(raw, p)

    changed = dict(new_first)
    guard = 0
    while changed and guard < 8:
        guard += 1
        nxt = {}
        for child, fk in changed.items():
            if child not in parent_of:
                continue
            parent, idx = parent_of[child]
            pn = node_now(parent)
            if pn['entries'][idx][0] == fk:
                continue
            raw = r.set_key(pn, idx, fk)
            edited[parent] = raw
            stats['parent_keys_fixed'] += 1
            if idx == 0 and parent != root_paddr:
                nxt[parent] = fk
        changed = nxt
    for p, raw in edited.items():
        patches[p] = raw

    # ---- root header counts ---------------------------------------------------------------
    def count(p, level_hint=None):
        n = node_now(p)
        if n is None:
            problems.append('page @0x%x is still not valid after the rebuild' % p)
            return 0, 0
        if n['level'] == 0:
            return n['nkeys'], 1
        k = nn = 0
        for key, val in n['entries']:
            a, b = count(val[0])
            k += a
            nn += b
        return k, nn + 1

    if not problems:
        keys, nodes = count(root_paddr)
        hk, hn = struct.unpack_from('<QQ', root['raw'], BS - 16)
        print('root header: mappings %d -> %d, pages %d -> %d' % (hk, keys, hn, nodes))
        patches[root_paddr] = r.set_root_key_count(patches.get(root_paddr, edited.get(root_paddr, root['raw'])), keys, nodes)

    print('rebuilt: %s' % dict(stats))
    with open(patch_path, 'wb') as f:
        f.write(r.PATCH_MAGIC + struct.pack('<QI', src.off, len(patches)))
        for p in sorted(patches):
            f.write(struct.pack('<Q', p) + patches[p])
    print('patch: %d blocks -> %s' % (len(patches), patch_path))
    for p in problems[:30]:
        print('PROBLEM: ' + p)
    return 1 if problems else 0


def check(source, root_paddr, target_xid, used_path, patch_path):
    """Read-only: the tree as it would be after the patch; structure, order, and every live object resolves to its live version."""
    src = r.Source(source)
    _, blocks = r.read_patch(patch_path)
    over = dict(blocks)
    used = {}
    for line in open(used_path):
        p = line.split()
        if len(p) >= 3:
            used[int(p[0], 16)] = (int(p[1], 16), int(p[2], 16))

    def get(b):
        return r.parse_node(over.get(b) or src.block(b), b)

    root = get(root_paddr)
    errors = []
    best = {}
    counts = dict(nodes=1, keys=0)
    seen = set()

    def walk(node, hi):
        keys = [e[0] for e in node['entries']]
        if any(keys[i] >= keys[i + 1] for i in range(len(keys) - 1)):
            errors.append('page @0x%x: keys not ascending' % node['paddr'])
        if hi is not None and keys and keys[-1] >= hi:
            errors.append('page @0x%x: last key reaches into the next sibling' % node['paddr'])
        if node['level'] == 0:
            counts['keys'] += len(keys)
            for (oid, xid), (flags, size, paddr) in node['entries']:
                if xid <= target_xid and (oid not in best or xid > best[oid][0]):
                    best[oid] = (xid, paddr, flags)
            return
        for i, (key, val) in enumerate(node['entries']):
            b = val[0]
            if b in seen:
                errors.append('block 0x%x referenced twice' % b)
                continue
            seen.add(b)
            child = get(b)
            if not child:
                errors.append('child @0x%x of @0x%x is not a valid omap page' % (b, node['paddr']))
                continue
            counts['nodes'] += 1
            if child['level'] != node['level'] - 1:
                errors.append('child @0x%x has level %d under level %d' % (b, child['level'], node['level']))
                continue
            if not child['nkeys'] or child['entries'][0][0] != key:
                errors.append('child @0x%x: first key differs from the parent key' % b)
            walk(child, node['entries'][i + 1][0] if i + 1 < node['nkeys'] else hi)

    walk(root, None)
    hk, hn = struct.unpack_from('<QQ', root['raw'], BS - 16)
    if (hk, hn) != (counts['keys'], counts['nodes']):
        errors.append('root header says %d mappings / %d pages, tree has %d / %d' % (hk, hn, counts['keys'], counts['nodes']))
    wrong = [o for o in used if o not in best or best[o][2] & DELETED or (best[o][0], best[o][1]) != used[o]]
    print('tree after patch: %d pages, %d mappings' % (counts['nodes'], counts['keys']))
    print('live objects: %d, resolving to their live version: %d, wrong or absent: %d' % (len(used), len(used) - len(wrong), len(wrong)))
    for e in errors[:20]:
        print('CHECK ERROR: ' + e)
    if wrong:
        print('first wrong/absent: ' + ', '.join('0x%x' % o for o in sorted(wrong)[:8]))
    ok = not errors and not wrong
    print('CHECK ' + ('PASSED' if ok else 'FAILED'))
    return 0 if ok else 1


if __name__ == '__main__':
    a = sys.argv
    if len(a) >= 9 and a[1] == 'plan':
        sys.exit(plan(a[2], int(a[3], 0), int(a[4]), a[5], a[6], a[7], a[8]))
    if len(a) >= 7 and a[1] == 'check':
        sys.exit(check(a[2], int(a[3], 0), int(a[4]), a[5], a[6]))
    print(__doc__)
    sys.exit(2)
