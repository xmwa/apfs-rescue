#!/usr/bin/env python3
"""Plan and apply an in-place repair of an APFS volume object map (omap)
whose leaf writes were lost.

A lost write leaves the block at the right address holding old content. The
repair rebuilds what each such leaf should contain and writes it to the same
block, so no pointer and no free-space record has to change.

  plan   <source> <omap_root_block> <used_nodes_file> <patch_out> [omapscan_salvage_file]
         Reads <source> (device or image, read-only), walks the omap tree,
         and writes a patch file. Nothing else is modified.
  check  <source> <omap_root_block> <used_nodes_file> <patch_file>
         Read-only: replays the patch in memory and validates the whole tree.
  apply  <target> <patch_file> <undo_out>
         Writes the patch to <target>, first saving the original blocks to
         <undo_out>.
  undo   <target> <undo_file>
         Puts the saved original blocks back.

<used_nodes_file> comes from `apfs-audit ... <used_nodes_out>`: the live
file-system tree nodes as "oid xid paddr level" (hex).
"""
import bisect
import os
import struct
import sys

BS = 4096
HDR = 56                 # sizeof(btree_node_phys_t)
INFO = 40                # sizeof(btree_info_t), only in root nodes
LEAF_TOC_LEN = 448       # table space of a fixed-size omap leaf: 112 entries
LEAF_CAPACITY = LEAF_TOC_LEN // 4
OMAP_VAL_ENCRYPTED = 4
PATCH_MAGIC = b'OMAPFIX1'


def fletcher64(body):
    s1 = s2 = 0
    for (w,) in struct.iter_unpack('<I', body):
        s1 = (s1 + w) % 0xffffffff
        s2 = (s2 + s1) % 0xffffffff
    c1 = 0xffffffff - ((s1 + s2) % 0xffffffff)
    c2 = 0xffffffff - ((s1 + c1) % 0xffffffff)
    return (c2 << 32) | c1


class Source:
    """Read-only block access to an APFS container (partition device or image)."""

    def __init__(self, path):
        self.fd = os.open(path, os.O_RDONLY)
        self.off = 0
        first = os.pread(self.fd, BS, 0)
        if first[32:36] != b'NXSB':
            # disk image with a partition table: find the container
            pos = -1
            for base in range(0, 2 * 1024 * 1024 * 1024, BS):   # containers start on a block boundary
                if os.pread(self.fd, 4, base + 32) == b'NXSB':
                    pos = base
                    break
            if pos < 0:
                raise SystemExit('no APFS container found in ' + path)
            self.off = pos

    def block(self, b):
        return os.pread(self.fd, BS, self.off + b * BS)


def parse_node(blk, paddr):
    """Returns a dict for a valid omap B-tree node, else None."""
    if len(blk) != BS:
        return None
    cksum, oid, xid, typ, sub = struct.unpack_from('<QQQII', blk, 0)
    if sub != 0xb or (typ & 0xffff) not in (2, 3) or oid != paddr:
        return None
    if cksum != fletcher64(blk[8:]):
        return None
    flags, level, nkeys = struct.unpack_from('<HHI', blk, 32)
    toff, tlen = struct.unpack_from('<HH', blk, 40)
    toc = HDR + toff
    keys = toc + tlen
    vend = BS - (INFO if flags & 1 else 0)
    leaf = bool(flags & 2)
    entries = []
    for i in range(nkeys):
        k, v = struct.unpack_from('<HH', blk, toc + 4 * i)
        key = struct.unpack_from('<QQ', blk, keys + k)
        val = struct.unpack_from('<IIQ', blk, vend - v) if leaf else struct.unpack_from('<Q', blk, vend - v)
        entries.append((key, val))
    return dict(paddr=paddr, xid=xid, type=typ, flags=flags, level=level, nkeys=nkeys, entries=entries, raw=blk)


def build_leaf(paddr, xid, entries):
    """A fresh non-root omap leaf: entries = [((oid, xid), (flags, size, paddr))], sorted."""
    n = len(entries)
    if n > LEAF_CAPACITY:
        raise ValueError('too many entries for one leaf: %d' % n)
    blk = bytearray(BS)
    struct.pack_into('<QQII', blk, 8, paddr, xid, 0x40000003, 0xb)
    struct.pack_into('<HHI', blk, 32, 0x6, 0, n)                 # leaf | fixed kv size, level 0
    struct.pack_into('<HH', blk, 40, 0, LEAF_TOC_LEN)            # table space
    area = BS - HDR - LEAF_TOC_LEN
    struct.pack_into('<HH', blk, 44, 16 * n, area - 32 * n)      # free space
    struct.pack_into('<HH', blk, 48, 0xffff, 0)                  # key free list
    struct.pack_into('<HH', blk, 52, 0xffff, 0)                  # value free list
    keys = HDR + LEAF_TOC_LEN
    for i, (key, val) in enumerate(entries):
        struct.pack_into('<HH', blk, HDR + 4 * i, 16 * i, 16 * (i + 1))
        struct.pack_into('<QQ', blk, keys + 16 * i, key[0], key[1])
        struct.pack_into('<IIQ', blk, BS - 16 * (i + 1), val[0], val[1], val[2])
    struct.pack_into('<Q', blk, 0, fletcher64(bytes(blk[8:])))
    return bytes(blk)


INDEX_TOC_LEN = 576      # table space of an omap index node: 144 entries
INDEX_CAPACITY = INDEX_TOC_LEN // 4


def build_index(paddr, xid, level, entries):
    """A fresh non-root omap index node: entries = [((oid, xid), child_paddr)], sorted."""
    n = len(entries)
    if n > INDEX_CAPACITY:
        raise ValueError('too many children for one index node: %d' % n)
    blk = bytearray(BS)
    struct.pack_into('<QQII', blk, 8, paddr, xid, 0x40000003, 0xb)
    struct.pack_into('<HHI', blk, 32, 0x4, level, n)             # fixed kv size
    struct.pack_into('<HH', blk, 40, 0, INDEX_TOC_LEN)
    area = BS - HDR - INDEX_TOC_LEN
    struct.pack_into('<HH', blk, 44, 16 * n, area - 24 * n)
    struct.pack_into('<HH', blk, 48, 0xffff, 0)
    struct.pack_into('<HH', blk, 52, 0xffff, 0)
    keys = HDR + INDEX_TOC_LEN
    for i, (key, child) in enumerate(entries):
        struct.pack_into('<HH', blk, HDR + 4 * i, 16 * i, 8 * (i + 1))
        struct.pack_into('<QQ', blk, keys + 16 * i, key[0], key[1])
        struct.pack_into('<Q', blk, BS - 8 * (i + 1), child)
    struct.pack_into('<Q', blk, 0, fletcher64(bytes(blk[8:])))
    return bytes(blk)


def set_key(node, index, key):
    """Copy of an index node with entry <index>'s key replaced, checksum redone."""
    blk = bytearray(node['raw'])
    toff, tlen = struct.unpack_from('<HH', blk, 40)
    k, _ = struct.unpack_from('<HH', blk, HDR + toff + 4 * index)
    struct.pack_into('<QQ', blk, HDR + toff + tlen + k, key[0], key[1])
    struct.pack_into('<Q', blk, 0, fletcher64(bytes(blk[8:])))
    return bytes(blk)


def set_root_key_count(raw, count, nodes=None):
    blk = bytearray(raw)
    struct.pack_into('<Q', blk, BS - 16, count)          # btree_info_t.bt_key_count
    if nodes is not None:
        struct.pack_into('<Q', blk, BS - 8, nodes)       # btree_info_t.bt_node_count
    struct.pack_into('<Q', blk, 0, fletcher64(bytes(blk[8:])))
    return bytes(blk)


def plan(source_path, root_paddr, used_path, patch_path, salvage_path=None):
    src = Source(source_path)

    # Blocks that held omap leaves which are no longer reachable (from
    # apfs-omapscan output, column 6). Among them are the still-current
    # children of a lost index node.
    orphan_leaves = set()
    if salvage_path:
        for line in open(salvage_path):
            p = line.split()
            if len(p) >= 7:
                orphan_leaves.add(int(p[5], 16))
        print('orphaned omap leaf blocks known from the scan: %d' % len(orphan_leaves))

    used = {}                       # oid -> (xid, paddr) of the live file-system tree node
    for line in open(used_path):
        p = line.split()
        if len(p) >= 3:
            used[int(p[0], 16)] = (int(p[1], 16), int(p[2], 16))
    print('live file-system tree nodes: %d' % len(used))

    root = parse_node(src.block(root_paddr), root_paddr)
    if not root or not (root['flags'] & 1):
        raise SystemExit('block %d is not a valid omap root' % root_paddr)
    print('omap root @%d: level %d, %d keys, xid %d, key count in header %d'
          % (root_paddr, root['level'], root['nkeys'], root['xid'], struct.unpack_from('<Q', root['raw'], BS - 16)[0]))

    patches = {}                    # paddr -> new block
    parent_edits = {}               # parent paddr -> node dict being edited
    problems = []
    total_keys = 0
    total_nodes = 1                 # the root
    extras_kept = []                # mappings for objects outside the live list, in leaves left untouched
    good_leaf_keys = set()
    used_oids = sorted(used)

    def live_entries(lo_oid, hi_oid):
        a = bisect.bisect_left(used_oids, lo_oid)
        b = len(used_oids) if hi_oid is None else bisect.bisect_left(used_oids, hi_oid)
        return [((oid, used[oid][0]), (OMAP_VAL_ENCRYPTED, BS, used[oid][1])) for oid in used_oids[a:b]]

    def is_current(leaf):
        """Every mapping in the leaf is the live one, and no live object in its span is absent."""
        ents = leaf['entries']
        if not ents:
            return False
        for (oid, xid), (flags, size, paddr) in ents:
            if used.get(oid) != (xid, paddr):
                return False
        span = bisect.bisect_right(used_oids, ents[-1][0][0]) - bisect.bisect_left(used_oids, ents[0][0][0])
        return span == len(ents)

    def rebuild_index(node, i, key, child_hi, child_paddr):
        """Rebuild a lost level-1 node at child_paddr covering [key, child_hi)."""
        nonlocal total_keys, total_nodes
        lo_oid = key[0]
        hi_oid = child_hi[0] if child_hi else None
        current = []
        for b in sorted(orphan_leaves):
            leaf = parse_node(src.block(b), b)
            if not leaf or leaf['level'] != 0 or not leaf['nkeys']:
                continue
            first = leaf['entries'][0][0][0]
            if first < lo_oid or (hi_oid is not None and first >= hi_oid):
                continue
            if is_current(leaf):
                current.append(leaf)
        current.sort(key=lambda l: (l['entries'][0][0], -l['xid']))
        chosen = []
        for leaf in current:                      # drop overlapping duplicates
            if chosen and leaf['entries'][0][0][0] <= chosen[-1]['entries'][-1][0][0]:
                continue
            chosen.append(leaf)
        covered = set(e[0][0] for l in chosen for e in l['entries'])
        want = live_entries(lo_oid, hi_oid)
        uncovered = [e for e in want if e[0][0] not in covered]
        print('    current child leaves found: %d, covering %d of %d live objects; %d to place'
              % (len(chosen), len(covered), len(want), len(uncovered)))

        # Place uncovered mappings. A run of uncovered objects between two current
        # leaves is merged into a neighbour if it fits (that leaf is rewritten in
        # place). Otherwise it becomes a new leaf, written into a block that still
        # holds a superseded omap leaf for the same key range.
        leaves = [dict(paddr=l['paddr'], xid=l['xid'], entries=list(l['entries']), changed=False) for l in chosen]
        stale = []
        chosen_blocks = set(l['paddr'] for l in chosen)
        for blk_no in sorted(orphan_leaves):
            if blk_no in chosen_blocks:
                continue
            leaf = parse_node(src.block(blk_no), blk_no)
            if leaf and leaf['level'] == 0 and leaf['nkeys']:
                stale.append(leaf)
        used_stale = set()

        def find_leaf_index(oid):
            idx = -1
            for j, l in enumerate(leaves):
                if l['entries'][0][0][0] <= oid:
                    idx = j
            return idx

        runs = []
        for e in uncovered:
            j = find_leaf_index(e[0][0])
            if runs and runs[-1][0] == j:
                runs[-1][1].append(e)
            else:
                runs.append((j, [e]))

        new_leaves = []
        for j, run in runs:
            prev = leaves[j] if j >= 0 else None
            nxt = leaves[j + 1] if j + 1 < len(leaves) else None
            if prev is not None and len(prev['entries']) + len(run) <= LEAF_CAPACITY:
                prev['entries'] = sorted(prev['entries'] + run)
                prev['changed'] = True
                continue
            if nxt is not None and len(nxt['entries']) + len(run) <= LEAF_CAPACITY:
                nxt['entries'] = sorted(nxt['entries'] + run)
                nxt['changed'] = True
                continue
            for k in range(0, len(run), LEAF_CAPACITY):
                chunk = run[k:k + LEAF_CAPACITY]
                lo_c, hi_c = chunk[0][0][0], chunk[-1][0][0]
                cands = [l for l in stale if l['paddr'] not in used_stale
                         and l['entries'][0][0][0] <= hi_c and l['entries'][-1][0][0] >= lo_c]
                if not cands:
                    problems.append('index @%d: no block available for %d objects from 0x%x' % (child_paddr, len(chunk), lo_c))
                    return
                pick = max(cands, key=lambda l: l['xid'])
                used_stale.add(pick['paddr'])
                new_leaves.append(dict(paddr=pick['paddr'], xid=node['xid'], entries=chunk, changed=True))
                print('    new leaf for %d objects (0x%x..0x%x) placed in block %d, which held a superseded leaf (xid %d)'
                      % (len(chunk), lo_c, hi_c, pick['paddr'], pick['xid']))
        leaves = sorted(leaves + new_leaves, key=lambda l: l['entries'][0][0])

        if not leaves:
            problems.append('index @%d: no current child leaves found' % child_paddr)
            return
        if len(leaves) > INDEX_CAPACITY:
            problems.append('index @%d: %d children do not fit' % (child_paddr, len(leaves)))
            return
        for l in leaves:
            if l['changed']:
                patches[l['paddr']] = build_leaf(l['paddr'], node['xid'], l['entries'])
                print('    leaf @%d rewritten with %d entries' % (l['paddr'], len(l['entries'])))
            else:
                good_leaf_keys.update(e[0][0] for e in l['entries'])
            total_keys += len(l['entries'])
            total_nodes += 1
        idx_entries = [(l['entries'][0][0], l['paddr']) for l in leaves]
        patches[child_paddr] = build_index(child_paddr, node['xid'], node['level'] - 1, idx_entries)
        total_nodes += 1
        print('    index @%d rebuilt with %d children' % (child_paddr, len(idx_entries)))
        if idx_entries[0][0] != key:
            print('    parent key (0x%x, %d) -> (0x%x, %d)' % (key[0], key[1], idx_entries[0][0][0], idx_entries[0][0][1]))
            cur = parent_edits.get(node['paddr'], node)
            parent_edits[node['paddr']] = dict(cur, raw=set_key(cur, i, idx_entries[0][0]))

    def walk(node, hi):
        nonlocal total_keys, total_nodes
        for i, (key, val) in enumerate(node['entries']):
            child_paddr = val[0]
            child_hi = node['entries'][i + 1][0] if i + 1 < node['nkeys'] else hi
            child = parse_node(src.block(child_paddr), child_paddr)
            ok = child and child['level'] == node['level'] - 1 and child['nkeys'] > 0 and child['entries'][0][0] == key
            if ok and child['level'] == 0:
                # A leaf can sit at the right place with the right first key and
                # still be an outdated copy. Compare it with the live objects.
                want = live_entries(key[0], child_hi[0] if child_hi else None)
                have = set(child['entries'])
                # conflict: a live object is mapped differently or is absent.
                # extra: a mapping for an object the file-system tree does not
                # use. Extras alone do not make a leaf outdated; it is left alone.
                absent_or_conflict = [e for e in want if e not in have]
                extra = [e for e in child['entries'] if e[0][0] not in used]
                if extra and not absent_or_conflict:
                    extras_kept.extend((child_paddr, e) for e in extra)
                if absent_or_conflict:
                    diff = len(absent_or_conflict)
                    print('  STALE LEAF @%d [oid 0x%x ..] xid %d: %d live objects mapped wrongly or absent (%d other mappings dropped) -> rebuilt with %d entries'
                          % (child_paddr, key[0], child['xid'], diff, len(extra), len(want)))
                    if not want or len(want) > LEAF_CAPACITY:
                        problems.append('stale leaf @%d: %d live entries cannot be placed in one leaf' % (child_paddr, len(want)))
                        continue
                    patches[child_paddr] = build_leaf(child_paddr, node['xid'], want)
                    total_keys += len(want)
                    total_nodes += 1
                    if want[0][0] != key:
                        cur = parent_edits.get(node['paddr'], node)
                        parent_edits[node['paddr']] = dict(cur, raw=set_key(cur, i, want[0][0]))
                    continue
            if ok:
                total_nodes += 1
                if child['level'] == 0:
                    total_keys += child['nkeys']
                    good_leaf_keys.update(k[0] for k, _ in child['entries'])
                else:
                    walk(child, child_hi)
                continue

            what = 'not an omap node' if not child else 'level %d, xid %d, first oid 0x%x' % (child['level'], child['xid'], child['entries'][0][0][0] if child['nkeys'] else 0)
            rng = 'oid 0x%x .. %s' % (key[0], ('0x%x' % child_hi[0]) if child_hi else 'end')
            if node['level'] == 2:
                print('  LOST INDEX NODE @%d [%s] holds: %s' % (child_paddr, rng, what))
                rebuild_index(node, i, key, child_hi, child_paddr)
                continue
            if node['level'] != 1:
                problems.append('index node lost at block %d (%s): level %d not handled' % (child_paddr, rng, node['level'] - 1))
                continue

            ents = live_entries(key[0], child_hi[0] if child_hi else None)
            print('  LOST LEAF @%d [%s] holds: %s -> rebuilt with %d entries' % (child_paddr, rng, what, len(ents)))
            if not ents:
                problems.append('leaf @%d: no live objects found for its range' % child_paddr)
                continue
            if len(ents) > LEAF_CAPACITY:
                problems.append('leaf @%d: %d entries do not fit in one leaf' % (child_paddr, len(ents)))
                continue
            patches[child_paddr] = build_leaf(child_paddr, node['xid'], ents)
            total_keys += len(ents)
            total_nodes += 1
            if ents[0][0] != key:
                print('    parent key (0x%x, %d) -> (0x%x, %d)' % (key[0], key[1], ents[0][0][0], ents[0][0][1]))
                cur = parent_edits.get(node['paddr'], node)
                raw = set_key(cur, i, ents[0][0])
                parent_edits[node['paddr']] = dict(cur, raw=raw)

    walk(root, None)

    # Bottom-up pass: every index entry's key must equal the first key of the
    # child it points to, at every level, after all rebuilt leaves are in place.
    def node_after(b):
        return parse_node(patches.get(b) or src.block(b), b)

    def fix_keys(b):
        node = node_after(b)
        if not node or node['level'] == 0:
            return node['entries'][0][0] if node and node['nkeys'] else None
        changed = False
        for i, (key, val) in enumerate(list(node['entries'])):
            first = fix_keys(val[0])
            if first is not None and first != key:
                node = dict(node, raw=set_key(node, i, first))
                node = parse_node(node['raw'], b)
                changed = True
                print('  key fixed in index @%d entry %d: (0x%x, %d) -> (0x%x, %d)' % (b, i, key[0], key[1], first[0], first[1]))
        if changed:
            patches[b] = node['raw']
        return node['entries'][0][0] if node['nkeys'] else None

    if not problems:
        fix_keys(root_paddr)

    total_keys += 0
    if extras_kept:
        print('mappings for objects outside the live list, left in place in healthy leaves: %d' % len(extras_kept))
        for b, e in extras_kept[:10]:
            print('    leaf @%d: object 0x%x xid %d -> block %d' % (b, e[0][0], e[0][1], e[1][2]))
    header_count, header_nodes = struct.unpack_from('<QQ', root['raw'], BS - 16)
    if (total_keys != header_count or total_nodes != header_nodes) and not problems:
        print('root header: keys %d -> %d, nodes %d -> %d' % (header_count, total_keys, header_nodes, total_nodes))
        patches[root_paddr] = set_root_key_count(patches.get(root_paddr, root['raw']), total_keys, total_nodes)

    missing = [oid for oid in used if oid not in good_leaf_keys
               and not any(oid == struct.unpack_from('<Q', b, HDR + LEAF_TOC_LEN + 16 * i)[0]
                           for b in patches.values() if struct.unpack_from('<H', b, 32)[0] & 2
                           for i in range(struct.unpack_from('<I', b, 36)[0]))]
    if missing:
        problems.append('%d live objects are in no leaf after the repair (first: 0x%x)' % (len(missing), min(missing)))

    with open(patch_path, 'wb') as f:
        f.write(PATCH_MAGIC + struct.pack('<QI', src.off, len(patches)))
        for paddr in sorted(patches):
            f.write(struct.pack('<Q', paddr) + patches[paddr])
    print('patch: %d blocks -> %s' % (len(patches), patch_path))
    for p in problems:
        print('PROBLEM: ' + p)
    return 1 if problems else 0


def check(source_path, root_paddr, used_path, patch_path):
    """Read-only: walks the omap tree as it would be after the patch and checks
    structure, ordering, header counts, and that every live object resolves to
    exactly its live version."""
    src = Source(source_path)
    _, blocks = read_patch(patch_path)
    over = dict(blocks)
    used = {}
    for line in open(used_path):
        p = line.split()
        if len(p) >= 3:
            used[int(p[0], 16)] = (int(p[1], 16), int(p[2], 16))

    def get(b):
        return parse_node(over.get(b) or src.block(b), b)

    root = get(root_paddr)
    errors = []
    seen_blocks = set()
    found = {}
    counts = dict(nodes=1, keys=0)

    def walk(node, hi):
        ents = node['entries']
        keys = [e[0] for e in ents]
        if keys != sorted(keys) or len(set(keys)) != len(keys):
            errors.append('node @%d: keys not strictly ascending' % node['paddr'])
        if hi is not None and keys and keys[-1] >= hi:
            errors.append('node @%d: last key reaches into the next sibling' % node['paddr'])
        if node['level'] == 0:
            counts['keys'] += len(ents)
            for (oid, xid), (flags, size, paddr) in ents:
                if oid in found:
                    errors.append('object 0x%x appears twice' % oid)
                found[oid] = (xid, paddr)
            return
        for i, (key, val) in enumerate(ents):
            b = val[0]
            child_hi = ents[i + 1][0] if i + 1 < len(ents) else hi
            if b in seen_blocks:
                errors.append('block %d referenced twice' % b)
                continue
            seen_blocks.add(b)
            child = get(b)
            if not child:
                errors.append('child @%d of @%d is not a valid omap node' % (b, node['paddr']))
                continue
            counts['nodes'] += 1
            if child['level'] != node['level'] - 1:
                errors.append('child @%d has level %d under a level %d node' % (b, child['level'], node['level']))
                continue
            if not child['nkeys'] or child['entries'][0][0] != key:
                errors.append('child @%d: first key differs from the parent key' % b)
            walk(child, child_hi)

    walk(root, None)
    hk, hn = struct.unpack_from('<QQ', root['raw'], BS - 16)
    if hk != counts['keys']:
        errors.append('root header key count %d, tree has %d' % (hk, counts['keys']))
    if hn != counts['nodes']:
        errors.append('root header node count %d, tree has %d' % (hn, counts['nodes']))
    wrong = [o for o in used if found.get(o) != used[o]]
    extra = [o for o in found if o not in used]
    print('tree after patch: %d nodes, %d mappings' % (counts['nodes'], counts['keys']))
    print('live objects: %d, resolving to their live version: %d, wrong or absent: %d' % (len(used), len(used) - len(wrong), len(wrong)))
    print('mappings for objects not in the live list: %d' % len(extra))
    for e in errors[:20]:
        print('CHECK ERROR: ' + e)
    if wrong:
        print('first wrong/absent: ' + ', '.join('0x%x' % o for o in sorted(wrong)[:8]))
    if extra:
        print('first extra: ' + ', '.join('0x%x' % o for o in sorted(extra)[:8]))
    ok = not errors and not wrong
    print('CHECK ' + ('PASSED' if ok else 'FAILED'))
    return 0 if ok else 1


def read_patch(path):
    data = open(path, 'rb').read()
    if data[:8] != PATCH_MAGIC:
        raise SystemExit('not a patch file: ' + path)
    off, n = struct.unpack_from('<QI', data, 8)
    pos = 20
    out = []
    for _ in range(n):
        paddr = struct.unpack_from('<Q', data, pos)[0]
        out.append((paddr, data[pos + 8:pos + 8 + BS]))
        pos += 8 + BS
    return off, out


def apply(target_path, patch_path, undo_path):
    off, blocks = read_patch(patch_path)
    if os.path.exists(undo_path):
        raise SystemExit('undo file already exists, refusing to overwrite: ' + undo_path)
    fd = os.open(target_path, os.O_RDWR)
    first = os.pread(fd, BS, off)
    if first[32:36] != b'NXSB':
        raise SystemExit('target does not have an APFS container at the expected offset')
    with open(undo_path, 'wb') as u:
        u.write(PATCH_MAGIC + struct.pack('<QI', off, len(blocks)))
        for paddr, _ in blocks:
            u.write(struct.pack('<Q', paddr) + os.pread(fd, BS, off + paddr * BS))
        u.flush()
        os.fsync(u.fileno())
    for paddr, blk in blocks:
        if os.pwrite(fd, blk, off + paddr * BS) != BS:
            raise SystemExit('short write at block %d' % paddr)
    os.fsync(fd)
    for paddr, blk in blocks:
        if os.pread(fd, BS, off + paddr * BS) != blk:
            raise SystemExit('read-back mismatch at block %d' % paddr)
    os.close(fd)
    print('applied %d blocks to %s, originals saved in %s, read-back verified' % (len(blocks), target_path, undo_path))
    return 0


def main(argv):
    if len(argv) >= 6 and argv[1] == 'plan':
        return plan(argv[2], int(argv[3], 0), argv[4], argv[5], argv[6] if len(argv) > 6 else None)
    if len(argv) >= 6 and argv[1] == 'check':
        return check(argv[2], int(argv[3], 0), argv[4], argv[5])
    if len(argv) >= 5 and argv[1] == 'apply':
        return apply(argv[2], argv[3], argv[4])
    if len(argv) >= 4 and argv[1] == 'undo':
        off, blocks = read_patch(argv[3])
        fd = os.open(argv[2], os.O_RDWR)
        for paddr, blk in blocks:
            os.pwrite(fd, blk, off + paddr * BS)
        os.fsync(fd)
        os.close(fd)
        print('restored %d original blocks' % len(blocks))
        return 0
    print(__doc__)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv))
