/*
 * apfs-ls: read-only diagnostic for a damaged APFS volume. Uses ApfsLib
 * directly (no FUSE), stays in the foreground and prints every step, so a
 * failure shows where it happens.
 *
 * Usage: apfs-ls <device> [inode] [xid] [omap_fallback_file]   (volume password on stdin)
 *   inode 1 = virtual top level, 2 = the volume's root directory
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
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/ApfsNodeMapper.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>

static bool g_details = false;
static bool g_names_only = false;

static void step(const char *msg)
{
	printf("[apfs-ls] %s\n", msg);
	fflush(stdout);
}

static bool list_dir(ApfsVolume &vol, uint64_t ino, int max_entries)
{
	ApfsDir dir(vol);
	std::vector<ApfsDir::DirRec> list;

	printf("[apfs-ls] listing inode %" PRIu64 " ...\n", ino);
	fflush(stdout);

	if (!dir.ListDirectory(list, ino)) {
		printf("[apfs-ls] ListDirectory(%" PRIu64 ") FAILED\n", ino);
		return false;
	}

	printf("[apfs-ls] %zu entries\n", list.size());
	if (g_names_only) {
		// one line per entry, no per-file lookups: "N <type> <id> <name>"
		for (const ApfsDir::DirRec &e : list)
			printf("N %u %" PRIu64 " %s\n", (unsigned)(e.flags & 0xF), e.file_id, e.name.c_str());
		return true;
	}
	int shown = 0;
	for (const ApfsDir::DirRec &e : list) {
		if (shown++ >= max_entries) { printf("  ...\n"); break; }
		ApfsDir::Inode inode;
		bool ok = dir.GetInode(inode, e.file_id);
		const char *type = ((e.flags & 0xF) == 4) ? "dir " : ((e.flags & 0xF) == 8) ? "file" : ((e.flags & 0xF) == 10) ? "link" : "?   ";
		if (ok) {
			printf("  %s id=%-10" PRIu64 " size=%-14" PRIu64 " %s\n", type, e.file_id, inode.ds_size, e.name.c_str());
			if (g_details) {
				std::vector<std::string> names;
				time_t ct = inode.create_time / 1000000000ULL, mt = inode.mod_time / 1000000000ULL;
				char cb[32], mb[32];
				strftime(cb, sizeof(cb), "%Y-%m-%d %H:%M:%S", localtime(&ct));
				strftime(mb, sizeof(mb), "%Y-%m-%d %H:%M:%S", localtime(&mt));
				printf("       created %s  modified %s  owner %u:%u  mode %o  flags 0x%x  xattrs:", cb, mb, inode.owner, inode.group, inode.mode & 07777, inode.bsd_flags);
				if (dir.ListAttributes(names, e.file_id))
					for (const std::string &n : names) printf(" %s", n.c_str());
				printf("\n");
			}
		}
		else
			printf("  %s id=%-10" PRIu64 " INODE UNREADABLE  %s\n", type, e.file_id, e.name.c_str());
		fflush(stdout);
	}
	return true;
}

int main(int argc, char *argv[])
{
	if (argc < 2) {
		printf("Syntax: %s <device> [inode] [xid]   (password on stdin)\n", argv[0]);
		return 1;
	}

	uint64_t ino = (argc > 2) ? strtoull(argv[2], nullptr, 10) : 0;
	xid_t xid = (argc > 3) ? strtoull(argv[3], nullptr, 10) : 0;

	g_debug = Dbg_Errors;
	g_lax = true;

	g_details = (argc > 5);
	g_names_only = (argc > 5 && std::string(argv[5]) == "names");
	if (g_names_only) g_details = false;
	if (argc > 4) {
		size_t n = OmapFallbackLoad(argv[4]);
		printf("[apfs-ls] loaded %zu salvaged omap mappings from %s\n", n, argv[4]);
	}

	std::string password;
	std::getline(std::cin, password);

	step("opening device (read-only)");
	Device *device = Device::OpenDevice(argv[1]);
	if (!device) { step("cannot open device"); return 2; }

	uint64_t offset = 0;
	uint64_t size = device->GetSize();
	GptPartitionMap gpt;
	if (gpt.LoadAndVerify(*device)) {
		int part = gpt.FindFirstAPFSPartition();
		if (part >= 0)
			gpt.GetPartitionOffsetAndSize(part, offset, size);
	}

	step("loading container");
	ApfsContainer *container = new ApfsContainer(device, offset, size);
	if (!container->Init(xid)) { step("container init FAILED"); return 3; }

	step("unlocking and loading volume 0");
	ApfsVolume *volume = container->GetVolume(0, password);
	if (!volume) { step("GetVolume FAILED (wrong password or damaged volume superblock)"); return 4; }
	printf("[apfs-ls] volume name: %s\n", volume->name());
	fflush(stdout);

	bool ok;
	if (ino) {
		ok = list_dir(*volume, ino, getenv("APFS_LS_MAX") ? atoi(getenv("APFS_LS_MAX")) : 200);
	} else {
		ok = list_dir(*volume, 1, 50);
		ok = list_dir(*volume, 2, 200) && ok;
	}

	step(ok ? "done, no failures" : "done, WITH failures");
	return ok ? 0 : 5;
}
