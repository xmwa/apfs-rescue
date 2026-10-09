/*
 * apfs-omapscan: read-only inspection of a volume's object map (omap).
 *
 * Phase 1 walks the omap B-tree from its root and reports every child that
 * is not what its parent expects (wrong level, bad checksum, wrong first key).
 * Phase 2 scans a block range for omap nodes that are still on disk but no
 * longer reachable from the root, and prints the mappings they hold for the
 * key range the damaged child was supposed to cover.
 *
 * Usage: apfs-omapscan <device> [scan_lo_block scan_hi_block]
 *   diagnostics go to stderr, recovered mappings to stdout as
 *   "oid xid paddr flags size leaf_paddr leaf_xid" (hex)
 *
 * The omap is not encrypted, so no password is needed.
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <vector>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>
#include <ApfsLib/Util.h>

struct Key { uint64_t oid; uint64_t xid; };

static bool key_less(const Key &a, const Key &b)
{
	return a.oid < b.oid || (a.oid == b.oid && a.xid < b.xid);
}

struct NodeInfo {
	uint64_t paddr = 0;
	uint64_t xid = 0;
	uint16_t flags = 0;
	uint16_t level = 0;
	uint32_t nkeys = 0;
	std::vector<Key> keys;
	std::vector<uint64_t> children;      // level > 0
	std::vector<omap_val_t> vals;        // leaves
};

static uint32_t g_bs = 4096;

// Parses an omap B-tree node. Returns false if the block is not a valid one.
static bool parse_node(const uint8_t *blk, uint64_t paddr, NodeInfo &n)
{
	const btree_node_phys_t *btn = reinterpret_cast<const btree_node_phys_t *>(blk);
	uint32_t type = btn->btn_o.o_type & 0xFFFF;

	if (type != OBJECT_TYPE_BTREE && type != OBJECT_TYPE_BTREE_NODE) return false;
	if (btn->btn_o.o_subtype != OBJECT_TYPE_OMAP) return false;
	if (btn->btn_o.o_oid != paddr) return false;
	if (!(btn->btn_flags & BTNODE_FIXED_KV_SIZE)) return false;
	if (!VerifyBlock(blk, g_bs)) return false;

	n.paddr = paddr;
	n.xid = btn->btn_o.o_xid;
	n.flags = btn->btn_flags;
	n.level = btn->btn_level;
	n.nkeys = btn->btn_nkeys;

	const size_t hdr = sizeof(btree_node_phys_t);
	const size_t toc = hdr + btn->btn_table_space.off;
	const size_t keys = toc + btn->btn_table_space.len;
	const size_t vend = g_bs - ((n.flags & BTNODE_ROOT) ? sizeof(btree_info_t) : 0);
	const bool leaf = (n.flags & BTNODE_LEAF) != 0;
	const size_t vsize = leaf ? sizeof(omap_val_t) : sizeof(uint64_t);

	if (n.nkeys > (g_bs / 4)) return false;
	if (toc + n.nkeys * sizeof(kvoff_t) > g_bs) return false;

	const kvoff_t *e = reinterpret_cast<const kvoff_t *>(blk + toc);
	for (uint32_t k = 0; k < n.nkeys; k++) {
		size_t koff = keys + e[k].k;
		if (koff + sizeof(omap_key_t) > g_bs) return false;
		if (e[k].v > vend || e[k].v < vsize) return false;
		size_t voff = vend - e[k].v;
		const omap_key_t *ok = reinterpret_cast<const omap_key_t *>(blk + koff);
		n.keys.push_back({ ok->ok_oid, ok->ok_xid });
		if (leaf) {
			omap_val_t v;
			memcpy(&v, blk + voff, sizeof(v));
			n.vals.push_back(v);
		} else {
			uint64_t c;
			memcpy(&c, blk + voff, sizeof(c));
			n.children.push_back(c);
		}
	}
	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stderr, "Syntax: %s <device> [scan_lo_block scan_hi_block]\n", argv[0]);
		return 1;
	}

	g_debug = 0;
	g_lax = true;

	Device *device = Device::OpenDevice(argv[1]);
	if (!device) { fprintf(stderr, "cannot open device\n"); return 2; }

	uint64_t offset = 0, size = device->GetSize();
	GptPartitionMap gpt;
	if (gpt.LoadAndVerify(*device)) {
		int part = gpt.FindFirstAPFSPartition();
		if (part >= 0) gpt.GetPartitionOffsetAndSize(part, offset, size);
	}

	ApfsContainer container(device, offset, size);
	if (!container.Init(0)) { fprintf(stderr, "container init failed\n"); return 3; }
	g_bs = container.GetBlocksize();

	apfs_superblock_t apsb;
	if (!container.GetVolumeInfo(0, apsb)) { fprintf(stderr, "no volume 0\n"); return 4; }

	std::vector<uint8_t> blk(g_bs);
	if (!container.ReadBlocks(blk.data(), apsb.apfs_omap_oid)) { fprintf(stderr, "cannot read omap object\n"); return 5; }
	const omap_phys_t *om = reinterpret_cast<const omap_phys_t *>(blk.data());
	uint64_t root_paddr = om->om_tree_oid;
	fprintf(stderr, "volume '%s' xid %" PRIu64 ", omap object @ 0x%" PRIx64 ", omap tree root @ 0x%" PRIx64 "\n",
		apsb.apfs_volname, (uint64_t)apsb.apfs_o.o_xid, (uint64_t)apsb.apfs_omap_oid, root_paddr);

	// ---- Phase 1: walk from the root ------------------------------------
	struct Todo { uint64_t paddr; int level; Key minkey; Key maxkey; bool has_max; uint64_t parent; uint32_t idx; };
	std::vector<Todo> todo;
	std::set<uint64_t> reachable;
	uint64_t pmin = UINT64_MAX, pmax = 0, nodes_ok = 0, leaf_entries = 0;
	struct Hole { Key lo; Key hi; bool has_hi; uint64_t paddr; int want_level; };
	std::vector<Hole> holes;

	NodeInfo root;
	if (!container.ReadBlocks(blk.data(), root_paddr) || !parse_node(blk.data(), root_paddr, root)) {
		fprintf(stderr, "omap root node is not readable/valid\n");
		return 6;
	}
	fprintf(stderr, "root: level %u, %u keys, xid %" PRIu64 "\n", root.level, root.nkeys, root.xid);
	reachable.insert(root_paddr);
	for (uint32_t k = 0; k < root.nkeys && root.level > 0; k++) {
		bool has_max = (k + 1 < root.nkeys);
		todo.push_back({ root.children[k], root.level - 1, root.keys[k], has_max ? root.keys[k + 1] : Key{0, 0}, has_max, root_paddr, k });
	}

	while (!todo.empty()) {
		Todo t = todo.back();
		todo.pop_back();
		NodeInfo n;
		const char *why = nullptr;

		if (!container.ReadBlocks(blk.data(), t.paddr)) why = "unreadable";
		else if (!parse_node(blk.data(), t.paddr, n)) why = "not a valid omap node";
		else if (n.level != t.level) why = "wrong level";
		else if (n.nkeys == 0) why = "empty";
		else if (n.keys[0].oid != t.minkey.oid || n.keys[0].xid != t.minkey.xid) why = "first key differs from parent's key";

		if (why) {
			fprintf(stderr, "BAD CHILD: parent 0x%" PRIx64 " index %u -> block 0x%" PRIx64 " (expected level %d): %s",
				t.parent, t.idx, t.paddr, t.level, why);
			if (n.paddr)
				fprintf(stderr, " [found level %u, xid %" PRIu64 ", %u keys, first key oid 0x%" PRIx64 "]", n.level, n.xid, n.nkeys, n.nkeys ? n.keys[0].oid : 0);
			fprintf(stderr, "\n   covers keys from (oid 0x%" PRIx64 ", xid %" PRIu64 ")", t.minkey.oid, t.minkey.xid);
			if (t.has_max) fprintf(stderr, " up to (oid 0x%" PRIx64 ", xid %" PRIu64 ")", t.maxkey.oid, t.maxkey.xid);
			fprintf(stderr, "\n");
			holes.push_back({ t.minkey, t.maxkey, t.has_max, t.paddr, t.level });
			continue;
		}

		reachable.insert(t.paddr);
		nodes_ok++;
		if (t.paddr < pmin) pmin = t.paddr;
		if (t.paddr > pmax) pmax = t.paddr;

		if (n.level == 0) {
			leaf_entries += n.nkeys;
		} else {
			for (uint32_t k = 0; k < n.nkeys; k++) {
				bool has_max = (k + 1 < n.nkeys) || t.has_max;
				Key mx = (k + 1 < n.nkeys) ? n.keys[k + 1] : t.maxkey;
				todo.push_back({ n.children[k], n.level - 1, n.keys[k], mx, has_max, t.paddr, k });
			}
		}
	}

	fprintf(stderr, "walk: %" PRIu64 " good nodes below root, %" PRIu64 " mappings in reachable leaves, node blocks 0x%" PRIx64 "..0x%" PRIx64 ", %zu damaged subtree(s)\n",
		nodes_ok, leaf_entries, pmin, pmax, holes.size());

	if (holes.empty()) { fprintf(stderr, "omap tree is consistent, nothing to recover\n"); return 0; }

	// ---- Phase 2: scan for unreachable omap nodes -----------------------
	uint64_t lo, hi;
	if (argc >= 4) {
		lo = strtoull(argv[2], nullptr, 0);
		hi = strtoull(argv[3], nullptr, 0);
	} else {
		lo = (pmin > 0x40000) ? pmin - 0x40000 : 0;
		hi = pmax + 0x40000;
	}
	uint64_t total_blocks = size / g_bs;
	if (hi > total_blocks) hi = total_blocks;
	fprintf(stderr, "scanning blocks 0x%" PRIx64 "..0x%" PRIx64 " (%.1f GB) for orphaned omap nodes\n", lo, hi, (hi - lo) * (double)g_bs / 1e9);

	auto in_hole = [&](const Key &first, const Key &last) {
		for (const Hole &h : holes) {
			if (h.has_hi && !key_less(first, h.hi)) continue;   // node starts at/after hole end
			if (key_less(last, h.lo)) continue;                  // node ends before hole start
			return true;
		}
		return false;
	};
	auto key_in_hole = [&](const Key &k) {
		for (const Hole &h : holes) {
			if (key_less(k, h.lo)) continue;
			if (h.has_hi && !key_less(k, h.hi)) continue;
			return true;
		}
		return false;
	};

	const uint32_t chunk = 2048;
	std::vector<uint8_t> buf((size_t)chunk * g_bs);
	uint64_t found_nodes = 0, orphan_leaves = 0, orphan_index = 0, emitted = 0;

	for (uint64_t b = lo; b < hi; b += chunk) {
		uint64_t cnt = (hi - b < chunk) ? hi - b : chunk;
		if (!container.ReadBlocks(buf.data(), b, cnt)) {
			fprintf(stderr, "read error at block 0x%" PRIx64 ", skipping chunk\n", b);
			continue;
		}
		for (uint64_t i = 0; i < cnt; i++) {
			const uint8_t *p = buf.data() + i * g_bs;
			const obj_phys_t *o = reinterpret_cast<const obj_phys_t *>(p);
			if (o->o_subtype != OBJECT_TYPE_OMAP) continue;
			uint32_t type = o->o_type & 0xFFFF;
			if (type != OBJECT_TYPE_BTREE && type != OBJECT_TYPE_BTREE_NODE) continue;

			NodeInfo n;
			if (!parse_node(p, b + i, n) || n.nkeys == 0) continue;
			found_nodes++;
			if (reachable.count(n.paddr)) continue;
			if (!in_hole(n.keys.front(), n.keys.back())) continue;

			if (n.level > 0) {
				orphan_index++;
				fprintf(stderr, "orphan index node @ 0x%" PRIx64 ": level %u, xid %" PRIu64 ", %u keys, oid 0x%" PRIx64 "..0x%" PRIx64 "\n",
					n.paddr, n.level, n.xid, n.nkeys, n.keys.front().oid, n.keys.back().oid);
			} else {
				orphan_leaves++;
				for (uint32_t k = 0; k < n.nkeys; k++) {
					if (!key_in_hole(n.keys[k])) continue;
					printf("%" PRIx64 " %" PRIx64 " %" PRIx64 " %x %x %" PRIx64 " %" PRIx64 "\n",
						n.keys[k].oid, n.keys[k].xid, (uint64_t)n.vals[k].ov_paddr,
						(unsigned)n.vals[k].ov_flags, (unsigned)n.vals[k].ov_size, n.paddr, n.xid);
					emitted++;
				}
			}
		}
	}

	fprintf(stderr, "scan: %" PRIu64 " valid omap nodes in range; in the damaged key range: %" PRIu64 " orphan index nodes, %" PRIu64 " orphan leaves, %" PRIu64 " mappings written\n",
		found_nodes, orphan_index, orphan_leaves, emitted);
	return 0;
}
