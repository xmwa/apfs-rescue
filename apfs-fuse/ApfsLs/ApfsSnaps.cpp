/*
 * apfs-snaps: read-only list of a volume's snapshots (xid and name) at a given
 * container save point. Usage: apfs-snaps <device> [container_xid]
 */
#include <cinttypes>
#include <cstdio>
#include <cstdlib>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/BTree.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>

int main(int argc, char *argv[])
{
	if (argc < 2) { fprintf(stderr, "Usage: %s <device> [container_xid]\n", argv[0]); return 1; }
	g_debug = 0; g_lax = true;
	Device *device = Device::OpenDevice(argv[1]);
	if (!device) return 2;
	uint64_t offset = 0, size = device->GetSize();
	GptPartitionMap gpt;
	if (gpt.LoadAndVerify(*device)) { int part = gpt.FindFirstAPFSPartition(); if (part >= 0) gpt.GetPartitionOffsetAndSize(part, offset, size); }
	ApfsContainer container(device, offset, size);
	if (!container.Init(argc > 2 ? strtoull(argv[2], nullptr, 10) : 0)) { fprintf(stderr, "container init failed\n"); return 3; }
	apfs_superblock_t apsb;
	if (!container.GetVolumeInfo(0, apsb)) { fprintf(stderr, "no volume 0\n"); return 4; }
	fprintf(stderr, "volume '%s' xid %" PRIu64 ", snapshot metadata tree @0x%" PRIx64 ", %" PRIu64 " snapshots recorded\n",
		apsb.apfs_volname, (uint64_t)apsb.apfs_o.o_xid, (uint64_t)apsb.apfs_snap_meta_tree_oid, (uint64_t)apsb.apfs_num_snapshots);
	if (!apsb.apfs_snap_meta_tree_oid) return 0;
	BTree tree(container);
	BTreeIterator it;
	BTreeEntry e;
	tree.Init(apsb.apfs_snap_meta_tree_oid, apsb.apfs_o.o_xid);
	if (!tree.GetIteratorBegin(it)) { fprintf(stderr, "cannot read the snapshot metadata tree\n"); return 5; }
	for (;;) {
		if (!it.GetEntry(e)) break;
		const j_snap_metadata_key_t *k = reinterpret_cast<const j_snap_metadata_key_t *>(e.key);
		const j_snap_metadata_val_t *v = reinterpret_cast<const j_snap_metadata_val_t *>(e.val);
		if ((k->hdr.obj_id_and_type >> OBJ_TYPE_SHIFT) != APFS_TYPE_SNAP_METADATA) break;
		printf("%" PRIu64 " %" PRIx64 " %s\n", (uint64_t)(k->hdr.obj_id_and_type & OBJ_ID_MASK), (uint64_t)v->sblock_oid, reinterpret_cast<const char *>(v->name));
		if (!it.next()) break;
	}
	return 0;
}
