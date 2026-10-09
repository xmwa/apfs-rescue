/*
 * apfs-verify: re-reads files from the raw APFS device and compares them with
 * an existing copy. A second, independent read that matches the copy rules out
 * a transient bad read during copying. Read-only on both sides.
 *
 * Usage: apfs-verify <device> <source_inode> <copy_dir> <omap_fallback_file> <percent>
 *        (volume password on stdin)
 *
 * Sampling: <percent> of the files, chosen by a fixed hash of the file id, are
 * compared. Files up to 64 MB are compared completely; larger ones by their
 * first and last 8 MB plus 6 chunks spread over the file. Files of 1 GB and
 * more are always included.
 *
 * Output: "MISMATCH", "SIZE", "MISSING" or "UNREADABLE" with the path.
 */

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ApfsLib/ApfsContainer.h>
#include <ApfsLib/ApfsVolume.h>
#include <ApfsLib/ApfsDir.h>
#include <ApfsLib/ApfsNodeMapper.h>
#include <ApfsLib/Decmpfs.h>
#include <ApfsLib/Device.h>
#include <ApfsLib/DiskStruct.h>
#include <ApfsLib/GptPartitionMap.h>
#include <ApfsLib/Global.h>

static unsigned g_percent = 10;
static uint64_t n_seen = 0, n_checked = 0, n_ok = 0, n_bytes = 0;
static uint64_t n_mismatch = 0, n_size = 0, n_missing = 0, n_unreadable = 0;
static time_t g_last_progress = 0;
static std::set<uint64_t> g_done;   // hard-linked files are compared once

static const size_t CHUNK = 8 * 1024 * 1024;

static void progress(bool force = false)
{
	time_t now = time(nullptr);
	if (!force && now - g_last_progress < 10) return;
	g_last_progress = now;
	printf("[apfs-verify] seen %" PRIu64 ", checked %" PRIu64 " (%.2f GB), ok %" PRIu64 ", mismatch %" PRIu64 ", size %" PRIu64 ", missing %" PRIu64 ", unreadable %" PRIu64 "\n",
		n_seen, n_checked, n_bytes / 1e9, n_ok, n_mismatch, n_size, n_missing, n_unreadable);
	fflush(stdout);
}

static bool selected(uint64_t id, uint64_t size)
{
	if (size >= (1ULL << 30)) return true;
	uint64_t h = id * 0x9E3779B97F4A7C15ULL;
	h ^= h >> 29;
	return (h % 100) < g_percent;
}

// Compares [off, off+n) of the source file with the copy. 0 ok, 1 mismatch, 2 unreadable source.
static int compare_range(ApfsDir &dir, uint64_t private_id, int fd, uint64_t off, size_t n, std::vector<uint8_t> &a, std::vector<uint8_t> &b)
{
	memset(a.data(), 0, n);
	if (!dir.ReadFile(a.data(), private_id, off, n)) return 2;
	ssize_t r = pread(fd, b.data(), n, off);
	if (r != (ssize_t)n) return 1;
	n_bytes += n;
	return memcmp(a.data(), b.data(), n) ? 1 : 0;
}

static void verify_file(ApfsDir &dir, uint64_t ino, const ApfsDir::Inode &inode, const std::string &path)
{
	struct stat st;

	if (lstat(path.c_str(), &st) != 0) { n_missing++; printf("MISSING %s\n", path.c_str()); return; }
	int fd = open(path.c_str(), O_RDONLY | O_NOFOLLOW);
	if (fd < 0) { n_missing++; printf("MISSING (cannot open: %s) %s\n", strerror(errno), path.c_str()); return; }

	int result = 0;

	if (inode.bsd_flags & APFS_UF_COMPRESSED) {
		std::vector<uint8_t> attr, data;
		if (!dir.GetAttribute(attr, ino, "com.apple.decmpfs") || !DecompressFile(dir, ino, data, attr)) {
			result = 2;
		} else if ((uint64_t)st.st_size != data.size()) {
			result = 3;
		} else {
			std::vector<uint8_t> b(data.size());
			if (pread(fd, b.data(), b.size(), 0) != (ssize_t)b.size() || memcmp(b.data(), data.data(), b.size())) result = 1;
			n_bytes += data.size();
		}
	} else {
		uint64_t size = (inode.optional_present_flags & ApfsDir::Inode::INO_HAS_DSTREAM) ? inode.ds_size : 0;
		if ((uint64_t)st.st_size != size) {
			result = 3;
		} else if (size > 0) {
			std::vector<uint8_t> a(CHUNK), b(CHUNK);
			if (size <= 8 * CHUNK) {
				for (uint64_t off = 0; off < size && result == 0; off += CHUNK)
					result = compare_range(dir, inode.private_id, fd, off, (size - off < CHUNK) ? (size_t)(size - off) : CHUNK, a, b);
			} else {
				// first, last and 6 evenly spread chunks, aligned to 4 KiB
				std::vector<uint64_t> offs = { 0, (size - CHUNK) & ~4095ULL };
				for (int k = 1; k <= 6; k++)
					offs.push_back(((size / 7) * k) & ~4095ULL);
				for (uint64_t off : offs) {
					size_t n = (size - off < CHUNK) ? (size_t)(size - off) : CHUNK;
					result = compare_range(dir, inode.private_id, fd, off, n, a, b);
					if (result) break;
				}
			}
		}
	}

	close(fd);
	n_checked++;

	switch (result) {
	case 0: n_ok++; break;
	case 1: n_mismatch++; printf("MISMATCH %s\n", path.c_str()); break;
	case 2: n_unreadable++; printf("UNREADABLE (source) %s\n", path.c_str()); break;
	case 3: n_size++; printf("SIZE %s\n", path.c_str()); break;
	}
}

static void walk(ApfsVolume &vol, uint64_t dir_ino, const std::string &dest, int depth)
{
	ApfsDir dir(vol);
	std::vector<ApfsDir::DirRec> list;

	if (depth > 200) return;
	if (!dir.ListDirectory(list, dir_ino)) { printf("UNREADABLE (directory) %s\n", dest.c_str()); n_unreadable++; return; }

	for (const ApfsDir::DirRec &e : list) {
		if (e.name.empty() || e.name == "." || e.name == ".." || e.name.find('/') != std::string::npos) continue;
		// .DS_Store is rewritten by Finder whenever a folder is opened
		if (e.name == ".DS_Store") continue;

		const std::string path = dest + "/" + e.name;
		ApfsDir::Inode inode;

		if (!dir.GetInode(inode, e.file_id)) continue;   // reported by the copy run already

		if (S_ISDIR(inode.mode)) {
			walk(vol, e.file_id, path, depth + 1);
		} else if (S_ISREG(inode.mode)) {
			uint64_t size = (inode.optional_present_flags & ApfsDir::Inode::INO_HAS_DSTREAM) ? inode.ds_size : 0;
			n_seen++;
			if (selected(e.file_id, size) && g_done.insert(e.file_id).second) verify_file(dir, e.file_id, inode, path);
		}
		progress();
	}
}

int main(int argc, char *argv[])
{
	if (argc < 6) {
		fprintf(stderr, "Syntax: %s <device> <source_inode> <copy_dir> <omap_fallback_file> <percent>   (password on stdin)\n", argv[0]);
		return 1;
	}

	const uint64_t src_ino = strtoull(argv[2], nullptr, 10);
	const std::string dest = argv[3];
	g_percent = (unsigned)strtoul(argv[5], nullptr, 10);
	if (g_percent > 100) g_percent = 100;

	g_debug = 0;
	g_lax = false;

	OmapFallbackLoad(argv[4]);

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

	printf("[apfs-verify] inode %" PRIu64 " vs %s, sampling %u%% of files (all files >= 1 GB)\n", src_ino, dest.c_str(), g_percent);
	fflush(stdout);

	walk(*volume, src_ino, dest, 0);

	progress(true);
	printf("[apfs-verify] done\n");
	return (n_mismatch || n_size || n_missing) ? 6 : 0;
}
