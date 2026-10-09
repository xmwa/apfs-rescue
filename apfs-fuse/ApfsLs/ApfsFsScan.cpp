/*
 * apfs-fsscan: read-only scan of a block range for file-system tree nodes.
 *
 * On an encrypted volume the file-system tree nodes are encrypted, so every
 * block in the range is decrypted with the volume key and kept only if it
 * then carries a valid object checksum and the header of a virtual
 * file-system-tree B-tree node. The result lets the recovery tools find the
 * newest on-disk copy of a node even when the object map has no usable entry.
 *
 * Usage: apfs-fsscan <device> <lo_block> <hi_block>     (password on stdin)
 *   stdout: "oid xid paddr 4 1000 level nkeys" (hex), same leading columns as
 *           the omap fallback file
 *   stderr: progress and totals
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>
#include <ApfsLib/Util.h>

int main(int argc, char *argv[])
{
	if (argc < 4) {
		fprintf(stderr, "Syntax: %s <device> <lo_block> <hi_block>   (password on stdin)\n", argv[0]);
		return 1;
	}

	uint64_t lo = strtoull(argv[2], nullptr, 0);
	uint64_t hi = strtoull(argv[3], nullptr, 0);

	g_debug = 0;
	g_lax = false;

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

	// The volume object is needed for its key; with lax mode off this fails
	// cleanly if the password is wrong.
	g_lax = true;
	ApfsVolume *volume = container->GetVolume(0, password);
	if (!volume) { fprintf(stderr, "cannot open volume (password?)\n"); return 4; }

	const uint32_t bs = container->GetBlocksize();
	const uint64_t total = size / bs;
	if (hi > total) hi = total;

	const uint32_t chunk = 2048;
	std::vector<uint8_t> buf((size_t)chunk * bs);
	uint64_t found = 0, leaves = 0;
	time_t last = time(nullptr), start = last;

	fprintf(stderr, "[apfs-fsscan] blocks 0x%" PRIx64 "..0x%" PRIx64 " (%.1f GB)\n", lo, hi, (hi - lo) * (double)bs / 1e9);

	for (uint64_t b = lo; b < hi; b += chunk) {
		uint64_t cnt = (hi - b < chunk) ? hi - b : chunk;

		// tweak 0 means "do not decrypt" in ReadBlocks; block 0 is never a tree node
		if (!volume->ReadBlocks(buf.data(), b, cnt, b ? b : 1)) {
			fprintf(stderr, "[apfs-fsscan] read error at block 0x%" PRIx64 ", chunk skipped\n", b);
			continue;
		}

		for (uint64_t i = 0; i < cnt; i++) {
			const uint8_t *p = buf.data() + i * bs;
			const btree_node_phys_t *btn = reinterpret_cast<const btree_node_phys_t *>(p);
			const uint32_t type = btn->btn_o.o_type;

			if (btn->btn_o.o_subtype != OBJECT_TYPE_FSTREE) continue;
			if ((type & OBJECT_TYPE_MASK) != OBJECT_TYPE_BTREE && (type & OBJECT_TYPE_MASK) != OBJECT_TYPE_BTREE_NODE) continue;
			if ((type & OBJ_STORAGETYPE_MASK) != OBJ_VIRTUAL) continue;
			if (!VerifyBlock(p, bs)) continue;

			found++;
			if (btn->btn_level == 0) leaves++;
			printf("%" PRIx64 " %" PRIx64 " %" PRIx64 " 4 %x %x %x\n",
				(uint64_t)btn->btn_o.o_oid, (uint64_t)btn->btn_o.o_xid, b + i, bs,
				(unsigned)btn->btn_level, (unsigned)btn->btn_nkeys);
		}

		time_t now = time(nullptr);
		if (now - last >= 15) {
			last = now;
			double done = (b - lo) * (double)bs;
			fprintf(stderr, "[apfs-fsscan] %.1f GB scanned, %" PRIu64 " nodes found, %.0f MB/s\n", done / 1e9, found, done / 1e6 / (double)(now - start + 1));
		}
	}

	fprintf(stderr, "[apfs-fsscan] done: %" PRIu64 " file-system tree nodes (%" PRIu64 " leaves) in %lds\n", found, leaves, (long)(time(nullptr) - start));
	return 0;
}
