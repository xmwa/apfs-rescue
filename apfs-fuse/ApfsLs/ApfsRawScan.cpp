/*
 * apfs-rawscan: read-only inventory of an UNENCRYPTED APFS container.
 * Reads every block in a range and lists each one that carries a valid object
 * checksum and is a superblock, object map or B-tree node. No file-system
 * structure is trusted, so it works on a container whose checkpoints are broken.
 *
 * Usage: apfs-rawscan <device> <lo_block> <hi_block>
 *   stdout, one line per object (hex):
 *     X paddr xid next_xid omap_oid fs0_oid block_count          container superblock
 *     V paddr oid xid omap_oid root_tree_oid extentref snapmeta name   volume superblock
 *     O paddr xid tree_oid snap_tree_oid                          object map
 *     N oid xid paddr subtype level nkeys flags storage           B-tree node
 *   stderr: progress
 */

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

#include <fcntl.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/Util.h>

int main(int argc, char *argv[])
{
	if (argc < 4) {
		fprintf(stderr, "Usage: %s <device> <lo_block> <hi_block>\n", argv[0]);
		return 1;
	}

	const uint32_t bs = 4096;
	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) { perror("open"); return 2; }
	uint64_t lo = strtoull(argv[2], nullptr, 0), hi = strtoull(argv[3], nullptr, 0);

	const uint32_t chunk = 2048;                       // 8 MiB
	std::vector<uint8_t> buf((size_t)chunk * bs);
	uint64_t n_obj = 0, n_err = 0, nonzero_chunks = 0;
	time_t start = time(nullptr), last = start;

	for (uint64_t b = lo; b < hi; b += chunk) {
		uint64_t cnt = (hi - b < chunk) ? hi - b : chunk;
		ssize_t r = pread(fd, buf.data(), cnt * bs, (off_t)(b * bs));
		if (r != (ssize_t)(cnt * bs)) {
			n_err++;
			fprintf(stderr, "[apfs-rawscan] read error at block 0x%" PRIx64 "\n", b);
			continue;
		}

		bool any = false;
		for (uint64_t i = 0; i < cnt; i++) {
			const uint8_t *p = buf.data() + i * bs;
			const obj_phys_t *o = reinterpret_cast<const obj_phys_t *>(p);
			const uint32_t type = o->o_type & OBJECT_TYPE_MASK;

			if (o->o_oid == 0 && o->o_xid == 0) continue;
			any = true;
			if (type != 1 && type != OBJECT_TYPE_BTREE && type != OBJECT_TYPE_BTREE_NODE && type != OBJECT_TYPE_OMAP && type != 0xd) continue;
			if (o->o_xid == 0 || o->o_xid > 0x10000000ULL) continue;
			if (!VerifyBlock(p, bs)) continue;

			const uint64_t paddr = b + i;
			n_obj++;

			if (type == 1) {
				const nx_superblock_t *nx = reinterpret_cast<const nx_superblock_t *>(p);
				if (nx->nx_magic != 0x4253584E) continue;
				printf("X %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 "\n", paddr, (uint64_t)o->o_xid,
					(uint64_t)nx->nx_next_xid, (uint64_t)nx->nx_omap_oid, (uint64_t)nx->nx_fs_oid[0], (uint64_t)nx->nx_block_count);
			} else if (type == 0xd) {
				const apfs_superblock_t *sb = reinterpret_cast<const apfs_superblock_t *>(p);
				if (sb->apfs_magic != 0x42535041) continue;
				char name[64];
				snprintf(name, sizeof(name), "%.60s", reinterpret_cast<const char *>(sb->apfs_volname));
				for (char *c = name; *c; c++) if (*c == ' ') *c = '_';
				printf("V %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 " %s\n", paddr, (uint64_t)o->o_oid, (uint64_t)o->o_xid,
					(uint64_t)sb->apfs_omap_oid, (uint64_t)sb->apfs_root_tree_oid, (uint64_t)sb->apfs_extentref_tree_oid, (uint64_t)sb->apfs_snap_meta_tree_oid, name);
			} else if (type == OBJECT_TYPE_OMAP) {
				const omap_phys_t *om = reinterpret_cast<const omap_phys_t *>(p);
				printf("O %" PRIx64 " %" PRIx64 " %" PRIx64 " %" PRIx64 "\n", paddr, (uint64_t)o->o_xid, (uint64_t)om->om_tree_oid, (uint64_t)om->om_snapshot_tree_oid);
			} else {
				const btree_node_phys_t *btn = reinterpret_cast<const btree_node_phys_t *>(p);
				if (btn->btn_level > 12 || btn->btn_nkeys > 4096) continue;
				printf("N %" PRIx64 " %" PRIx64 " %" PRIx64 " %x %x %x %x %x\n", (uint64_t)o->o_oid, (uint64_t)o->o_xid, paddr,
					(unsigned)o->o_subtype, (unsigned)btn->btn_level, (unsigned)btn->btn_nkeys, (unsigned)btn->btn_flags, (unsigned)(o->o_type >> 30));
			}
		}
		if (any) nonzero_chunks++;

		time_t now = time(nullptr);
		if (now - last >= 60) {
			last = now;
			fflush(stdout);
			double frac = (double)(b - lo) / (double)(hi - lo);
			fprintf(stderr, "[apfs-rawscan] %.2f%% of range, block 0x%" PRIx64 ", %.1f GB with data read, %" PRIu64 " objects, %" PRIu64 " read errors, %lds elapsed\n",
				frac * 100.0, b, nonzero_chunks * (double)chunk * bs / 1e9, n_obj, n_err, (long)(now - start));
		}
	}

	fflush(stdout);
	fprintf(stderr, "[apfs-rawscan] done: %" PRIu64 " objects, %" PRIu64 " read errors, %lds\n", n_obj, n_err, (long)(time(nullptr) - start));
	return 0;
}
