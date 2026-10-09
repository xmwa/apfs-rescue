/*
 * apfs-snapcheck: read-only check that a volume's object map serves its
 * snapshots, newest first, limited to a set of object-id ranges (the ranges
 * whose object-map pages were rebuilt).
 *
 * For each snapshot the file-system tree is walked from its root. Subtrees
 * that cannot reach the ranges (index node older than <min_xid>) and subtrees
 * already walked for a newer snapshot (same object id and version) are
 * skipped. Every node inside the ranges is resolved through the object map,
 * read, and checked against its parent (exists, right level, first key).
 *
 * Usage: apfs-snapcheck <device> <container_xid> <ranges_file> <min_xid> <snap_xid> [<snap_xid> ...]
 *   ranges_file: "lo_oid hi_oid" per line, hex, hi "-" = open end
 *   snap_xid 0 = the live volume
 */
#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
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

static std::vector<std::pair<uint64_t, uint64_t>> g_ranges;
static uint64_t g_min_xid = 0;

struct PairHash { size_t operator()(const std::pair<uint64_t, uint64_t> &p) const { return p.first * 0x9E3779B97F4A7C15ULL ^ p.second; } };
static std::unordered_set<std::pair<uint64_t, uint64_t>, PairHash> g_seen;      // (oid, xid) verified or walked

struct Stat { uint64_t checked = 0, shared = 0, pruned = 0, no_map = 0, unreadable = 0, level = 0, minkey = 0, index = 0; };
static Stat st;
static uint64_t g_snap = 0;
static time_t g_last = 0;

static bool in_ranges(uint64_t oid)
{
	auto it = std::upper_bound(g_ranges.begin(), g_ranges.end(), std::make_pair(oid, UINT64_MAX));
	if (it == g_ranges.begin()) return false;
	--it;
	return oid >= it->first && oid < it->second;
}

static void walk(BTree &tree, const std::shared_ptr<BTreeNode> &node)
{
	const uint32_t cnt = node->entries_cnt();
	const bool leaf_children = (node->level() == 1);
	st.index++;

	time_t now = time(nullptr);
	if (now - g_last >= 60) {
		g_last = now;
		printf("[snapcheck] snapshot %" PRIu64 ": %" PRIu64 " index nodes walked, %" PRIu64 " nodes in the ranges checked, %" PRIu64 " shared with newer snapshots, problems %" PRIu64 "\n",
			g_snap, st.index, st.checked, st.shared, st.no_map + st.unreadable + st.level + st.minkey);
		fflush(stdout);
	}

	for (uint32_t i = 0; i < cnt; i++) {
		BTreeEntry e;
		if (!node->GetEntry(e, i)) continue;
		const uint64_t child = *reinterpret_cast<const uint64_t *>(e.val);
		const bool inr = in_ranges(child);

		if (leaf_children && !inr) continue;                    // mapping lives in an untouched page

		omap_res_t omr;
		if (!tree.AuditOmapLookup(child, omr) || (omr.flags & OMAP_VAL_DELETED)) {
			st.no_map++;
			const j_key_t *k = reinterpret_cast<const j_key_t *>(e.key);
			printf("NOMAP snapshot %" PRIu64 ": no usable mapping for oid 0x%" PRIx64 " (level %u, parent 0x%" PRIx64 ", file id %" PRIu64 ")\n",
				g_snap, child, node->level() - 1, node->nodeid(), (uint64_t)(k->obj_id_and_type & OBJ_ID_MASK));
			continue;
		}
		if (!inr && !leaf_children && omr.xid < g_min_xid) { st.pruned++; continue; }
		if (!g_seen.insert(std::make_pair(child, (uint64_t)omr.xid)).second) { st.shared++; continue; }

		std::shared_ptr<BTreeNode> c = tree.AuditGetNode(child, node, i);
		if (!c) {
			st.unreadable++;
			printf("UNREADABLE snapshot %" PRIu64 ": oid 0x%" PRIx64 " maps to xid %" PRIu64 " @0x%" PRIx64 " but that block is not this node\n", g_snap, child, (uint64_t)omr.xid, (uint64_t)omr.paddr);
			continue;
		}
		if (inr) st.checked++;
		if (c->level() + 1 != node->level()) {
			st.level++;
			printf("LEVEL snapshot %" PRIu64 ": oid 0x%" PRIx64 " xid %" PRIu64 " has level %u, parent 0x%" PRIx64 " expects %u\n", g_snap, child, (uint64_t)omr.xid, c->level(), node->nodeid(), node->level() - 1);
			continue;
		}
		BTreeEntry cf;
		if (c->entries_cnt() > 0 && c->GetEntry(cf, 0) && (cf.key_len != e.key_len || memcmp(cf.key, e.key, e.key_len) != 0)) {
			st.minkey++;
			printf("MINKEY snapshot %" PRIu64 ": oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 ": first key differs from the key in parent 0x%" PRIx64 "\n", g_snap, child, (uint64_t)omr.xid, (uint64_t)omr.paddr, node->nodeid());
		}
		if (!leaf_children) walk(tree, c);
	}
}

int main(int argc, char *argv[])
{
	if (argc < 6) { fprintf(stderr, "Usage: %s <device> <container_xid> <ranges_file> <min_xid> <snap_xid>...\n", argv[0]); return 1; }
	g_debug = 0; g_lax = true;

	FILE *f = fopen(argv[3], "r");
	if (!f) { perror("ranges"); return 1; }
	char a[64], b[64];
	while (fscanf(f, "%63s %63s", a, b) == 2)
		g_ranges.push_back(std::make_pair(strtoull(a, nullptr, 16), b[0] == '-' ? UINT64_MAX : strtoull(b, nullptr, 16)));
	fclose(f);
	std::sort(g_ranges.begin(), g_ranges.end());
	g_min_xid = strtoull(argv[4], nullptr, 10);
	printf("[snapcheck] %zu ranges, subtrees older than xid %" PRIu64 " are skipped\n", g_ranges.size(), g_min_xid);

	Device *device = Device::OpenDevice(argv[1]);
	if (!device) return 2;
	uint64_t offset = 0, size = device->GetSize();
	GptPartitionMap gpt;
	if (gpt.LoadAndVerify(*device)) { int part = gpt.FindFirstAPFSPartition(); if (part >= 0) gpt.GetPartitionOffsetAndSize(part, offset, size); }
	ApfsContainer *container = new ApfsContainer(device, offset, size);
	if (!container->Init(strtoull(argv[2], nullptr, 10))) { fprintf(stderr, "container init failed\n"); return 3; }

	uint64_t total_problems = 0;
	for (int k = 5; k < argc; k++) {
		g_snap = strtoull(argv[k], nullptr, 10);
		st = Stat();
		time_t t0 = time(nullptr); g_last = t0;
		ApfsVolume *vol = container->GetVolume(0, std::string(), g_snap);
		if (!vol) { printf("RESULT snapshot %" PRIu64 ": CANNOT OPEN\n", g_snap); total_problems++; continue; }
		std::shared_ptr<BTreeNode> root = vol->fstree().AuditRoot();
		if (!root) { printf("RESULT snapshot %" PRIu64 ": root of the file index unreadable\n", g_snap); total_problems++; delete vol; continue; }
		walk(vol->fstree(), root);
		uint64_t problems = st.no_map + st.unreadable + st.level + st.minkey;
		total_problems += problems;
		printf("RESULT snapshot %" PRIu64 ": %s | checked %" PRIu64 " nodes in the ranges, %" PRIu64 " shared with newer snapshots, %" PRIu64 " old subtrees skipped | no mapping %" PRIu64 ", unreadable %" PRIu64 ", wrong level %" PRIu64 ", key mismatch %" PRIu64 " | %lds\n",
			g_snap, problems ? "PROBLEMS" : "OK", st.checked, st.shared, st.pruned, st.no_map, st.unreadable, st.level, st.minkey, (long)(time(nullptr) - t0));
		fflush(stdout);
		delete vol;
	}
	printf("[snapcheck] done, %" PRIu64 " problems in total\n", total_problems);
	return total_problems ? 6 : 0;
}
