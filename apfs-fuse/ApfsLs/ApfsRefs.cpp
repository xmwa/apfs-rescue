/*
 * apfs-refs: read-only dump of every block a volume references, for an
 * independent ownership check (see repair-plan-v2.md, gate G1).
 *
 * Walks, top down:
 *   F  the file-system tree            (nodes found through the object map)
 *   X  the extent reference tree       (physical tree)
 *   S  the snapshot metadata tree      (physical tree)
 * and writes
 *   <prefix>.nodes     "<F|X|S> oid xid paddr level"            (hex)
 *   <prefix>.extents   "file_id logical_addr paddr nblocks"     (hex)  file data, from the file-system tree
 *   <prefix>.pext      "paddr nblocks kind owner refcnt"        (hex)  from the extent reference tree
 * Structural problems go to stdout:
 *   WRONGOID  the block the object map gives holds a different object (or a newer version than the tree)
 *   MISSING / LEVEL / MINKEY / OVERLAP / DUPLICATE as in apfs-audit
 *
 * Usage: apfs-refs <device> <out_prefix> [container_xid]      (volume password on stdin)
 * The device is opened read-only.
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <string>
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

struct Stats {
	uint64_t nodes[8] = { 0 }, records = 0, by_type[16] = { 0 };
	uint64_t missing = 0, wrongoid = 0, level = 0, minkey = 0, overlap = 0, dup = 0;
	uint64_t extents = 0, extent_blocks = 0;
	uint64_t issues() const { return missing + wrongoid + level + minkey + overlap + dup; }
};

static FILE *g_nodes = nullptr, *g_ext = nullptr, *g_pext = nullptr;
static time_t g_last = 0;
static uint32_t g_bs = 4096;

static uint64_t xid_of(const std::shared_ptr<BTreeNode> &n)
{
	return reinterpret_cast<const obj_phys_t *>(n->block().data())->o_xid;
}

static void walk(BTree &tree, const std::shared_ptr<BTreeNode> &node, char tag, uint64_t tree_xid, Stats &st, std::unordered_set<uint64_t> &seen)
{
	const uint32_t cnt = node->entries_cnt();
	st.nodes[node->level() < 8 ? node->level() : 7]++;
	fprintf(g_nodes, "%c %" PRIx64 " %" PRIx64 " %" PRIx64 " %x\n", tag, node->nodeid(), xid_of(node), (uint64_t)node->paddr(), (unsigned)node->level());

	time_t now = time(nullptr);
	if (now - g_last >= 30) {
		g_last = now;
		uint64_t idx = 0; for (int l = 1; l < 8; l++) idx += st.nodes[l];
		printf("[apfs-refs] tree %c: %" PRIu64 " leaves, %" PRIu64 " index; %" PRIu64 " records, %" PRIu64 " extents; issues %" PRIu64 "\n", tag, st.nodes[0], idx, st.records, st.extents, st.issues());
		fflush(stdout);
	}

	if (node->level() == 0) {
		for (uint32_t i = 0; i < cnt; i++) {
			BTreeEntry e;
			if (!node->GetEntry(e, i)) continue;
			const K k = key_of(e.key);
			st.by_type[k.type & 15]++;
			st.records++;
			if (tag == 'F' && k.type == APFS_TYPE_FILE_EXTENT && e.key_len >= sizeof(j_file_extent_key_t) && e.val_len >= sizeof(j_file_extent_val_t)) {
				const j_file_extent_key_t *fk = reinterpret_cast<const j_file_extent_key_t *>(e.key);
				const j_file_extent_val_t *fv = reinterpret_cast<const j_file_extent_val_t *>(e.val);
				const uint64_t phys = fv->phys_block_num;
				const uint64_t len = fv->len_and_flags & J_FILE_EXTENT_LEN_MASK;
				if (phys != 0 && len != 0) {
					const uint64_t nb = (len + g_bs - 1) / g_bs;
					fprintf(g_ext, "%" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 "\n", k.id, (uint64_t)fk->logical_addr, phys, nb);
					st.extents++; st.extent_blocks += nb;
				}
			} else if (tag == 'X' && k.type == APFS_TYPE_EXTENT && e.val_len >= 20) {
				const j_phys_ext_val_t *pv = reinterpret_cast<const j_phys_ext_val_t *>(e.val);
				const uint64_t lk = pv->len_and_kind;
				fprintf(g_pext, "%" PRIx64 " %" PRIx64 " %x %" PRIx64 " %x\n", k.id, lk & PEXT_LEN_MASK, (unsigned)(lk >> PEXT_KIND_SHIFT), (uint64_t)pv->owning_obj_id, (unsigned)pv->refcnt);
				st.extents++; st.extent_blocks += lk & PEXT_LEN_MASK;
			}
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

		if (!seen.insert(child_oid).second) {
			st.dup++;
			printf("DUPLICATE %c oid 0x%" PRIx64 " referenced again from node 0x%" PRIx64 " index %u (id %" PRIu64 ")\n", tag, child_oid, node->nodeid(), i, pk.id);
			continue;
		}

		std::shared_ptr<BTreeNode> child = tree.AuditGetNode(child_oid, node, i);
		if (!child) {
			st.missing++;
			printf("MISSING %c oid 0x%" PRIx64 " (parent 0x%" PRIx64 " xid %" PRIu64 " index %u, level %u expected): ids %" PRIu64 "/%" PRIu64 "..%" PRIu64 "/%" PRIu64 "%s\n",
				tag, child_oid, node->nodeid(), xid_of(node), i, node->level() - 1, pk.id, pk.type, has_next ? nk.id : 0, has_next ? nk.type : 0, has_next ? "" : " (to end of parent)");
			continue;
		}

		if (child->nodeid() != child_oid || xid_of(child) > tree_xid) {
			st.wrongoid++;
			printf("WRONGOID %c oid 0x%" PRIx64 ": block @0x%" PRIx64 " holds oid 0x%" PRIx64 " xid %" PRIu64 " level %u (parent 0x%" PRIx64 " xid %" PRIu64 " index %u): ids %" PRIu64 "/%" PRIu64 "..%" PRIu64 "/%" PRIu64 "%s\n",
				tag, child_oid, (uint64_t)child->paddr(), child->nodeid(), xid_of(child), child->level(), node->nodeid(), xid_of(node), i, pk.id, pk.type, has_next ? nk.id : 0, has_next ? nk.type : 0, has_next ? "" : " (to end of parent)");
			continue;
		}

		if (child->level() + 1 != node->level()) {
			st.level++;
			printf("LEVEL %c oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 " has level %u, parent 0x%" PRIx64 " expects %u\n",
				tag, child_oid, xid_of(child), (uint64_t)child->paddr(), child->level(), node->nodeid(), node->level() - 1);
			continue;
		}

		if (child->entries_cnt() > 0) {
			BTreeEntry cf, cl;
			if (child->GetEntry(cf, 0)) {
				if (cf.key_len != pkey.size() || memcmp(cf.key, pkey.data(), pkey.size()) != 0) {
					st.minkey++;
					const K ck = key_of(cf.key);
					printf("MINKEY %c oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 ": first key id %" PRIu64 "/type %" PRIu64 ", parent 0x%" PRIx64 " xid %" PRIu64 " expects %" PRIu64 "/%" PRIu64 "\n",
						tag, child_oid, xid_of(child), (uint64_t)child->paddr(), ck.id, ck.type, node->nodeid(), xid_of(node), pk.id, pk.type);
				}
			}
			if (has_next && child->GetEntry(cl, child->entries_cnt() - 1)) {
				const K lk = key_of(cl.key);
				if (less(nk, lk)) {
					st.overlap++;
					printf("OVERLAP %c oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 ": last key id %" PRIu64 " is beyond the next sibling's start %" PRIu64 " (parent 0x%" PRIx64 ")\n",
						tag, child_oid, xid_of(child), (uint64_t)child->paddr(), lk.id, nk.id, node->nodeid());
				}
			}
		}

		walk(tree, child, tag, tree_xid, st, seen);
	}
}

static FILE *open_out(const std::string &prefix, const char *ext)
{
	const std::string p = prefix + ext;
	FILE *f = fopen(p.c_str(), "w");
	if (!f) { fprintf(stderr, "cannot write %s\n", p.c_str()); exit(1); }
	setvbuf(f, nullptr, _IOFBF, 1 << 20);
	return f;
}

static void run(BTree &tree, char tag, const char *name, uint64_t tree_xid, Stats &st)
{
	std::shared_ptr<BTreeNode> root = tree.AuditRoot();
	if (!root) { printf("[apfs-refs] tree %c (%s): root is unreadable or the tree is absent\n", tag, name); return; }
	printf("[apfs-refs] tree %c (%s): root oid 0x%" PRIx64 " xid %" PRIu64 " @0x%" PRIx64 " level %u, %u entries\n", tag, name, root->nodeid(), xid_of(root), (uint64_t)root->paddr(), root->level(), root->entries_cnt());
	fflush(stdout);
	std::unordered_set<uint64_t> seen;
	seen.insert(root->nodeid());
	time_t start = time(nullptr);
	walk(tree, root, tag, tree_xid, st, seen);
	uint64_t idx = 0; for (int l = 1; l < 8; l++) idx += st.nodes[l];
	printf("[apfs-refs] tree %c (%s) done in %lds: %" PRIu64 " leaves, %" PRIu64 " index nodes, %" PRIu64 " records, %" PRIu64 " extents covering %" PRIu64 " blocks\n", tag, name, (long)(time(nullptr) - start), st.nodes[0], idx, st.records, st.extents, st.extent_blocks);
	printf("[apfs-refs] tree %c issues: missing %" PRIu64 ", wrongoid %" PRIu64 ", level %" PRIu64 ", minkey %" PRIu64 ", overlap %" PRIu64 ", duplicate %" PRIu64 "\n", tag, st.missing, st.wrongoid, st.level, st.minkey, st.overlap, st.dup);
	fflush(stdout);
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "Syntax: %s <device> <out_prefix> [container_xid]   (password on stdin)\n", argv[0]);
		return 1;
	}

	g_debug = 0;
	g_lax = true;

	const std::string prefix = argv[2];
	g_nodes = open_out(prefix, ".nodes");
	g_ext = open_out(prefix, ".extents");
	g_pext = open_out(prefix, ".pext");

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
	xid_t want_xid = (argc > 3) ? strtoull(argv[3], nullptr, 10) : 0;
	if (!container->Init(want_xid)) { fprintf(stderr, "container init failed\n"); return 3; }
	g_bs = container->GetBlocksize();

	ApfsVolume *volume = container->GetVolume(0, password);
	if (!volume) { fprintf(stderr, "cannot open volume\n"); return 4; }

	const apfs_superblock_t &sb = volume->sb();
	const uint64_t vxid = sb.apfs_o.o_xid;
	printf("[apfs-refs] volume superblock xid %" PRIu64 "; root tree oid 0x%" PRIx64 ", omap oid 0x%" PRIx64 ", extentref tree 0x%" PRIx64 ", snap meta tree 0x%" PRIx64 "\n",
		vxid, (uint64_t)sb.apfs_root_tree_oid, (uint64_t)sb.apfs_omap_oid, (uint64_t)sb.apfs_extentref_tree_oid, (uint64_t)sb.apfs_snap_meta_tree_oid);
	printf("[apfs-refs] superblock counts: files %" PRIu64 ", directories %" PRIu64 ", symlinks %" PRIu64 ", other %" PRIu64 ", snapshots %" PRIu64 "; blocks allocated to the volume %" PRIu64 "\n",
		(uint64_t)sb.apfs_num_files, (uint64_t)sb.apfs_num_directories, (uint64_t)sb.apfs_num_symlinks, (uint64_t)sb.apfs_num_other_fsobjects, (uint64_t)sb.apfs_num_snapshots, (uint64_t)sb.apfs_fs_alloc_count);
	fflush(stdout);

	g_last = time(nullptr);
	Stats f, x, s;
	run(volume->snapmetatree(), 'S', "snapshot metadata", vxid, s);
	run(volume->extentreftree(), 'X', "extent reference", vxid, x);
	run(volume->fstree(), 'F', "file system", vxid, f);

	fclose(g_nodes); fclose(g_ext); fclose(g_pext);

	static const char *names[16] = { "any", "snap_metadata", "extent", "inode", "xattr", "sibling_link", "dstream_id", "crypto_state", "file_extent", "dir_rec", "dir_stats", "snap_name", "sibling_map", "file_info", "?", "?" };
	for (int t = 0; t < 16; t++)
		if (f.by_type[t]) printf("   F %-14s %" PRIu64 "\n", names[t], f.by_type[t]);
	const uint64_t total = f.issues() + x.issues() + s.issues();
	printf("[apfs-refs] finished: %" PRIu64 " structural issues in total\n", total);
	return total ? 6 : 0;
}
