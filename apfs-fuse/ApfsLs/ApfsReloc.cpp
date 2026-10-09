/*
 * apfs-reloc: prepare file-system tree nodes for being placed at new blocks.
 *
 * File-system tree nodes of an encrypted volume are encrypted with the block
 * number as tweak, so a node saved from block A cannot simply be written to
 * block B. This tool reads saved nodes from a file that holds an older copy
 * of part of the disk, decrypts each one as block A, checks that it really is
 * the wanted object (checksum, object id, version), re-encrypts it for block B
 * and writes the result to a patch file. It writes nothing to any disk.
 *
 * Usage: apfs-reloc <device_or_image> <old_copy_file> <old_copy_first_block> <list> <patch_out>   (password on stdin)
 *   <device_or_image>  only used to open the volume and get its key (read-only)
 *   <list> lines: "oid xid old_paddr new_paddr" (hex)
 *   <patch_out>: OMAPFIX1 patch (see omap_repair.py): the re-encrypted nodes at new_paddr
 * stdout: one line per node: "OK oid xid old new level nkeys first_id/first_type last_id/last_type" or "BAD ..."
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>
#include <fcntl.h>
#include <unistd.h>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>
#include <ApfsLib/Util.h>

int main(int argc, char *argv[])
{
	if (argc < 6) {
		fprintf(stderr, "Syntax: %s <device_or_image> <old_copy_file> <old_copy_first_block> <list> <patch_out>   (password on stdin)\n", argv[0]);
		return 1;
	}
	g_debug = 0;
	g_lax = true;

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
	if (!container->Init(0)) { fprintf(stderr, "container init failed\n"); return 3; }
	ApfsVolume *volume = container->GetVolume(0, password);
	if (!volume) { fprintf(stderr, "cannot open volume (password?)\n"); return 4; }
	const uint32_t bs = container->GetBlocksize();

	int old_fd = open(argv[2], O_RDONLY);
	if (old_fd < 0) { fprintf(stderr, "cannot open %s\n", argv[2]); return 5; }
	const uint64_t old_first = strtoull(argv[3], nullptr, 0);

	FILE *list = fopen(argv[4], "r");
	if (!list) { fprintf(stderr, "cannot open %s\n", argv[4]); return 5; }

	std::vector<std::pair<uint64_t, std::vector<uint8_t>>> out;
	char line[256];
	int bad = 0;
	while (fgets(line, sizeof(line), list)) {
		unsigned long long oid, xid, oldp, newp;
		if (sscanf(line, "%llx %llx %llx %llx", &oid, &xid, &oldp, &newp) != 4) continue;
		std::vector<uint8_t> blk(bs);
		if (oldp < old_first || pread(old_fd, blk.data(), bs, (off_t)((oldp - old_first) * bs)) != (ssize_t)bs) {
			printf("BAD %llx %llx %llx %llx cannot read the old copy\n", oid, xid, oldp, newp); bad++; continue;
		}
		volume->CryptBlocks(blk.data(), 1, oldp, false);
		const btree_node_phys_t *bn = reinterpret_cast<const btree_node_phys_t *>(blk.data());
		if (!VerifyBlock(blk.data(), bs) || bn->btn_o.o_oid != oid || bn->btn_o.o_xid != xid) {
			printf("BAD %llx %llx %llx %llx old copy is not this object (found oid %" PRIx64 " xid %" PRIx64 ", checksum %s)\n", oid, xid, oldp, newp,
				(uint64_t)bn->btn_o.o_oid, (uint64_t)bn->btn_o.o_xid, VerifyBlock(blk.data(), bs) ? "ok" : "bad");
			bad++; continue;
		}
		// first and last key, for the report (variable-size key/value node layout)
		const uint16_t flags = bn->btn_flags;
		const uint32_t nkeys = bn->btn_nkeys;
		const uint8_t *toc = blk.data() + sizeof(btree_node_phys_t) + bn->btn_table_space.off;
		const uint8_t *keys = toc + bn->btn_table_space.len;
		uint64_t fid = 0, ftype = 0, lid = 0, ltype = 0;
		if (nkeys > 0 && !(flags & BTNODE_FIXED_KV_SIZE)) {
			const kvloc_t *e0 = reinterpret_cast<const kvloc_t *>(toc);
			const kvloc_t *e1 = reinterpret_cast<const kvloc_t *>(toc) + (nkeys - 1);
			uint64_t k0, k1;
			memcpy(&k0, keys + e0->k.off, 8); memcpy(&k1, keys + e1->k.off, 8);
			fid = k0 & OBJ_ID_MASK; ftype = k0 >> OBJ_TYPE_SHIFT; lid = k1 & OBJ_ID_MASK; ltype = k1 >> OBJ_TYPE_SHIFT;
		}
		printf("OK %llx %llx %llx %llx %u %u %" PRIu64 "/%" PRIu64 " %" PRIu64 "/%" PRIu64 "\n", oid, xid, oldp, newp, (unsigned)bn->btn_level, nkeys, fid, ftype, lid, ltype);
		volume->CryptBlocks(blk.data(), 1, newp, true);
		out.emplace_back((uint64_t)newp, std::move(blk));
	}
	fclose(list);

	FILE *pf = fopen(argv[5], "wb");
	if (!pf) { fprintf(stderr, "cannot write %s\n", argv[5]); return 6; }
	const uint64_t zero = 0;
	const uint32_t n = (uint32_t)out.size();
	fwrite("OMAPFIX1", 1, 8, pf); fwrite(&zero, 8, 1, pf); fwrite(&n, 4, 1, pf);
	for (auto &e : out) { fwrite(&e.first, 8, 1, pf); fwrite(e.second.data(), 1, bs, pf); }
	fclose(pf);
	fprintf(stderr, "[apfs-reloc] %u nodes prepared, %d rejected\n", n, bad);
	return bad ? 7 : 0;
}
