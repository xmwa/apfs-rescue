/*
 * apfs-audit: read-only structural audit of a volume's file-system tree.
 *
 * Walks the tree from the root, top down, and checks every parent/child link:
 *   MISSING    child cannot be loaded (no usable block for its object id)
 *   LEVEL      child is not one level below its parent
 *   MINKEY     child's first key differs from the key its parent holds for it
 *   OVERLAP    child's last key reaches into the range of the next sibling
 *   DUPLICATE  the same object id is referenced from two places
 * Each of these marks a spot where the on-disk versions do not fit together,
 * i.e. what a repair has to resolve. Because it never follows a node twice it
 * cannot loop.
 *
 * Usage: apfs-audit <device> <omap_fallback_file> [used_nodes_out] [container_xid] [earlier_used_nodes_file]   (password on stdin)
 *   used_nodes_out: every tree node the walk used, as "oid xid paddr level" (hex);
 *   this is the set of object ids that are live, with the version that was read.
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/ApfsNodeMapper.h>
#include <ApfsLib/BTree.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>

struct K { uint64_t id; uint64_t type; };

static K key_of(const void *key)
{
	const j_key_t *k = reinterpret_cast<const j_key_t *>(key);
	return { k->obj_id_and_type & OBJ_ID_MASK, k->obj_id_and_type >> OBJ_TYPE_SHIFT };
}
static bool less(const K &a, const K &b) { return a.id < b.id || (a.id == b.id && a.type < b.type); }

static uint64_t n_nodes[8] = { 0 }, n_records = 0, by_type[16] = { 0 };
static uint64_t n_missing = 0, n_level = 0, n_minkey = 0, n_overlap = 0, n_dup = 0;
static std::unordered_set<uint64_t> g_seen;
static time_t g_last = 0;
static FILE *g_used = nullptr;

// Resume: level-1 subtrees that an earlier, interrupted run already walked
// completely (taken from that run's used-nodes file). They are not read again;
// their lines are copied to the new used-nodes file.
static std::unordered_map<uint64_t, std::vector<std::string>> g_done1;
static uint64_t n_resumed_leaves = 0;

static void load_resume(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) return;
	char line[128];
	uint64_t cur = 0;
	std::vector<std::string> lines;
	bool have = false;
	while (fgets(line, sizeof(line), f)) {
		unsigned long long oid, xid, paddr; unsigned level;
		if (sscanf(line, "%llx %llx %llx %x", &oid, &xid, &paddr, &level) != 4) continue;
		if (level >= 1) {
			if (have) g_done1.emplace(cur, std::move(lines));   // closed by a later index node: complete
			lines.clear();
			have = (level == 1);
			cur = oid;
			if (have) lines.push_back(line);
		} else if (have) {
			lines.push_back(line);
		}
	}
	fclose(f);                                                   // the last group may be incomplete: dropped
}

static uint64_t xid_of(const std::shared_ptr<BTreeNode> &n)
{
	return reinterpret_cast<const obj_phys_t *>(n->block().data())->o_xid;
}

static void walk(BTree &tree, const std::shared_ptr<BTreeNode> &node)
{
	const uint32_t cnt = node->entries_cnt();
	n_nodes[node->level() < 8 ? node->level() : 7]++;
	if (g_used)
		fprintf(g_used, "%" PRIx64 " %" PRIx64 " %" PRIx64 " %x\n", node->nodeid(), xid_of(node), (uint64_t)node->paddr(), (unsigned)node->level());

	time_t now = time(nullptr);
	if (now - g_last >= 30) {
		g_last = now;
		printf("[apfs-audit] nodes: %" PRIu64 " leaves, %" PRIu64 " index; %" PRIu64 " records; issues: missing %" PRIu64 ", level %" PRIu64 ", minkey %" PRIu64 ", overlap %" PRIu64 ", duplicate %" PRIu64 "\n",
			n_nodes[0], n_nodes[1] + n_nodes[2] + n_nodes[3] + n_nodes[4] + n_nodes[5] + n_nodes[6] + n_nodes[7], n_records, n_missing, n_level, n_minkey, n_overlap, n_dup);
		fflush(stdout);
	}

	if (node->level() == 0) {
		for (uint32_t i = 0; i < cnt; i++) {
			BTreeEntry e;
			if (!node->GetEntry(e, i)) continue;
			by_type[key_of(e.key).type & 15]++;
			n_records++;
		}
		return;
	}

	for (uint32_t i = 0; i < cnt; i++) {
		BTreeEntry e, en;
		if (!node->GetEntry(e, i)) continue;

		const K pk = key_of(e.key);
		std::vector<uint8_t> pkey(reinterpret_cast<const uint8_t *>(e.key), reinterpret_cast<const uint8_t *>(e.key) + e.key_len);
		const uint64_t child_oid = *reinterpret_cast<const uint64_t *>(e.val);

		bool has_next = false;
		K nk = { 0, 0 };
		if (i + 1 < cnt && node->GetEntry(en, i + 1)) { nk = key_of(en.key); has_next = true; }

		if (!g_seen.insert(child_oid).second) {
			n_dup++;
			printf("DUPLICATE oid 0x%" PRIx64 " referenced again from node 0x%" PRIx64 " index %u (file id %" PRIu64 ")\n", child_oid, node->nodeid(), i, pk.id);
			continue;
		}

		std::shared_ptr<BTreeNode> child = tree.AuditGetNode(child_oid, node, i);
		if (!child) {
			n_missing++;
			printf("MISSING oid 0x%" PRIx64 " (parent 0x%" PRIx64 " xid %" PRIu64 " index %u, level %u expected): file ids %" PRIu64 "..%" PRIu64 "%s\n",
				child_oid, node->nodeid(), xid_of(node), i, node->level() - 1, pk.id, has_next ? nk.id : 0, has_next ? "" : " (to end of parent)");
			continue;
		}

		if (child->level() + 1 != node->level()) {
			n_level++;
			printf("LEVEL oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 " has level %u, parent 0x%" PRIx64 " expects %u\n",
				child_oid, xid_of(child), (uint64_t)child->paddr(), child->level(), node->nodeid(), node->level() - 1);
			continue;
		}

		if (child->entries_cnt() > 0) {
			BTreeEntry cf, cl;
			if (child->GetEntry(cf, 0)) {
				if (cf.key_len != pkey.size() || memcmp(cf.key, pkey.data(), pkey.size()) != 0) {
					n_minkey++;
					const K ck = key_of(cf.key);
					printf("MINKEY oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 ": first key file id %" PRIu64 "/type %" PRIu64 ", parent 0x%" PRIx64 " xid %" PRIu64 " expects %" PRIu64 "/%" PRIu64 "\n",
						child_oid, xid_of(child), (uint64_t)child->paddr(), ck.id, ck.type, node->nodeid(), xid_of(node), pk.id, pk.type);
				}
			}
			if (has_next && child->GetEntry(cl, child->entries_cnt() - 1)) {
				const K lk = key_of(cl.key);
				if (less(nk, lk)) {
					n_overlap++;
					printf("OVERLAP oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 ": last key file id %" PRIu64 " is beyond the next sibling's start %" PRIu64 " (parent 0x%" PRIx64 ")\n",
						child_oid, xid_of(child), (uint64_t)child->paddr(), lk.id, nk.id, node->nodeid());
				}
			}
		}

		if (child->level() == 1) {
			auto done = g_done1.find(child_oid);
			if (done != g_done1.end()) {
				n_nodes[1]++;
				n_nodes[0] += done->second.size() - 1;
				n_resumed_leaves += done->second.size() - 1;
				if (g_used)
					for (const std::string &l : done->second) fputs(l.c_str(), g_used);
				continue;
			}
		}

		walk(tree, child);
	}
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "Syntax: %s <device> <omap_fallback_file>   (password on stdin)\n", argv[0]);
		return 1;
	}

	g_debug = 0;
	g_lax = true;

	if (argc > 3) {
		g_used = fopen(argv[3], "w");
		if (!g_used) { fprintf(stderr, "cannot write %s\n", argv[3]); return 1; }
	}

	if (argc > 5) {
		load_resume(argv[5]);
		printf("[apfs-audit] resuming: %zu level-1 subtrees already verified by an earlier run\n", g_done1.size());
	}

	size_t n = OmapFallbackLoad(argv[2]);
	printf("[apfs-audit] loaded %zu fallback mappings\n", n);

	std::string password;
	std::getline(std::cin, password);

	Device *device = Device::OpenDevice(argv[1]);
	if (!device) { fprintf(stderr, "cannot open device\n"); return 2; }

	uint64_t offset = 0, size = device->GetSize();
	GptPartitionMap gpt;
	if (gpt.LoadAndVerify(*device)) {
		int part = gpt.FindFirstAPFSPartition();
		if (part >= 0) gpt.GetPartitionOffsetAndSize(part, offset, size);
	}

	ApfsContainer *container = new ApfsContainer(device, offset, size);
	// optional 4th argument: container save point (xid) to load instead of the newest
	xid_t want_xid = (argc > 4) ? strtoull(argv[4], nullptr, 10) : 0;
	if (!container->Init(want_xid)) { fprintf(stderr, "container init failed\n"); return 3; }

	ApfsVolume *volume = container->GetVolume(0, password);
	if (!volume) { fprintf(stderr, "cannot open volume\n"); return 4; }

	std::shared_ptr<BTreeNode> root = volume->fstree().AuditRoot();
	if (!root) { printf("[apfs-audit] the root of the file-system tree is unreadable\n"); return 5; }

	printf("[apfs-audit] root oid 0x%" PRIx64 " xid %" PRIu64 " level %u, %u entries\n", root->nodeid(), xid_of(root), root->level(), root->entries_cnt());
	fflush(stdout);

	time_t start = time(nullptr);
	g_last = start;
	g_seen.insert(root->nodeid());
	walk(volume->fstree(), root);

	if (g_used) fclose(g_used);

	static const char *names[16] = { "any", "snap_metadata", "extent", "inode", "xattr", "sibling_link", "dstream_id", "crypto_state", "file_extent", "dir_rec", "dir_stats", "snap_name", "sibling_map", "file_info", "?", "?" };
	uint64_t index_nodes = 0;
	for (int l = 1; l < 8; l++) index_nodes += n_nodes[l];
	printf("[apfs-audit] done in %lds: %" PRIu64 " leaves, %" PRIu64 " index nodes, %" PRIu64 " records\n", (long)(time(nullptr) - start), n_nodes[0], index_nodes, n_records);
	if (n_resumed_leaves) printf("[apfs-audit] %" PRIu64 " leaves were taken from the earlier run (their records are not counted above)\n", n_resumed_leaves);
	printf("[apfs-audit] issues: missing %" PRIu64 ", level %" PRIu64 ", minkey %" PRIu64 ", overlap %" PRIu64 ", duplicate %" PRIu64 "\n", n_missing, n_level, n_minkey, n_overlap, n_dup);
	for (int t = 0; t < 16; t++)
		if (by_type[t]) printf("   %-14s %" PRIu64 "\n", names[t], by_type[t]);
	return (n_missing || n_level || n_minkey || n_overlap || n_dup) ? 6 : 0;
}
