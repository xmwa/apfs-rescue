/*
 * overlayfs: presents a block device (or image file) as one file, "disk.img",
 * in a FUSE mount. Reads fall through to the base, which is opened O_RDONLY.
 * Writes are kept in memory (4 KiB blocks) and never reach the base.
 *
 * This replaces `hdiutil attach -shadow`, which refuses bases above ~8 TB.
 *
 * Usage: overlayfs <base> <base_offset> <size_bytes> <mountpoint> [status_file]
 *   base_offset/size select the region of <base> to expose (a partition inside
 *   an image, or 0 and the device size for a partition device).
 */

#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

static const size_t BS = 4096;

static int g_base = -1;
static uint64_t g_off = 0, g_size = 0;
static std::string g_status;
static std::mutex g_mtx;
static std::unordered_map<uint64_t, std::vector<uint8_t>> g_blocks;   // block number -> content
static uint64_t g_reads = 0, g_writes = 0, g_read_errors = 0;
static time_t g_last_status = 0;

static void write_status(bool force)
{
	time_t now = time(nullptr);
	if (g_status.empty() || (!force && now - g_last_status < 5)) return;
	g_last_status = now;
	FILE *f = fopen(g_status.c_str(), "w");
	if (!f) return;
	fprintf(f, "overlay blocks held in memory: %zu (%.1f MB)\nread calls: %" PRIu64 "\nwrite calls: %" PRIu64 "\nbase read errors: %" PRIu64 "\n",
		g_blocks.size(), g_blocks.size() * (double)BS / 1e6, g_reads, g_writes, g_read_errors);
	fclose(f);
}

// Reads whole blocks [first, first+count) of the exposed region from the base.
static bool base_read(uint8_t *dst, uint64_t first, size_t count)
{
	uint64_t pos = g_off + first * BS;
	size_t want = count * BS;
	size_t done = 0;
	while (done < want) {
		ssize_t r = pread(g_base, dst + done, want - done, pos + done);
		if (r <= 0) return false;
		done += r;
	}
	return true;
}

static int ov_getattr(const char *path, struct stat *st, struct fuse_file_info *)
{
	memset(st, 0, sizeof(*st));
	if (!strcmp(path, "/")) {
		st->st_mode = S_IFDIR | 0755;
		st->st_nlink = 2;
		return 0;
	}
	if (!strcmp(path, "/disk.img")) {
		st->st_mode = S_IFREG | 0666;
		st->st_nlink = 1;
		st->st_size = g_size;
		st->st_blocks = g_size / 512;
		st->st_uid = getuid();
		st->st_gid = getgid();
		return 0;
	}
	return -ENOENT;
}

static int ov_readdir(const char *path, void *buf, fuse_fill_dir_t fill, off_t, struct fuse_file_info *, enum fuse_readdir_flags)
{
	if (strcmp(path, "/")) return -ENOENT;
	fill(buf, ".", nullptr, 0, (fuse_fill_dir_flags)0);
	fill(buf, "..", nullptr, 0, (fuse_fill_dir_flags)0);
	fill(buf, "disk.img", nullptr, 0, (fuse_fill_dir_flags)0);
	return 0;
}

static int ov_open(const char *path, struct fuse_file_info *)
{
	return strcmp(path, "/disk.img") ? -ENOENT : 0;
}

static int ov_read(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *)
{
	if (strcmp(path, "/disk.img")) return -ENOENT;
	if ((uint64_t)off >= g_size) return 0;
	if ((uint64_t)off + size > g_size) size = g_size - off;

	const uint64_t first = off / BS;
	const uint64_t last = (off + size - 1) / BS;
	const size_t count = last - first + 1;
	std::vector<uint8_t> tmp(count * BS);

	if (!base_read(tmp.data(), first, count)) {
		std::lock_guard<std::mutex> lk(g_mtx);
		g_read_errors++;
		write_status(true);
		return -EIO;
	}
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		g_reads++;
		if (!g_blocks.empty())
			for (uint64_t b = first; b <= last; b++) {
				auto it = g_blocks.find(b);
				if (it != g_blocks.end())
					memcpy(tmp.data() + (b - first) * BS, it->second.data(), BS);
			}
		write_status(false);
	}
	memcpy(buf, tmp.data() + (off - first * BS), size);
	return (int)size;
}

static int ov_write(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *)
{
	if (strcmp(path, "/disk.img")) return -ENOENT;
	if ((uint64_t)off + size > g_size) return -ENOSPC;

	size_t done = 0;
	while (done < size) {
		const uint64_t pos = off + done;
		const uint64_t b = pos / BS;
		const size_t in = pos % BS;
		const size_t n = std::min(BS - in, size - done);

		std::unique_lock<std::mutex> lk(g_mtx);
		auto it = g_blocks.find(b);
		if (it == g_blocks.end()) {
			std::vector<uint8_t> blk(BS);
			if (n != BS) {                       // partial block: start from the base content
				lk.unlock();
				if (!base_read(blk.data(), b, 1)) return -EIO;
				lk.lock();
			}
			it = g_blocks.emplace(b, std::move(blk)).first;
		}
		memcpy(it->second.data() + in, buf + done, n);
		done += n;
	}
	{
		std::lock_guard<std::mutex> lk(g_mtx);
		g_writes++;
		write_status(false);
	}
	return (int)size;
}

static int ov_fsync(const char *, int, struct fuse_file_info *) { return 0; }
static int ov_flush(const char *, struct fuse_file_info *) { return 0; }
static int ov_truncate(const char *, off_t size, struct fuse_file_info *) { return (uint64_t)size == g_size ? 0 : -EPERM; }
static int ov_chmod(const char *, mode_t, struct fuse_file_info *) { return 0; }
static int ov_chown(const char *, uid_t, gid_t, struct fuse_file_info *) { return 0; }
static int ov_utimens(const char *, const struct timespec[2], struct fuse_file_info *) { return 0; }
static int ov_statfs(const char *, struct statvfs *st)
{
	memset(st, 0, sizeof(*st));
	st->f_bsize = st->f_frsize = BS;
	st->f_blocks = g_size / BS;
	st->f_bfree = st->f_bavail = g_size / BS;
	st->f_namemax = 255;
	return 0;
}

int main(int argc, char *argv[])
{
	if (argc < 5) {
		fprintf(stderr, "Usage: %s <base> <base_offset> <size_bytes> <mountpoint> [status_file]\n", argv[0]);
		return 1;
	}

	g_base = open(argv[1], O_RDONLY);          // the base is never opened for writing
	if (g_base < 0) { perror("open base"); return 2; }
	g_off = strtoull(argv[2], nullptr, 0);
	g_size = strtoull(argv[3], nullptr, 0);
	if (!g_size || g_size % BS || g_off % BS) { fprintf(stderr, "size and offset must be multiples of 4096\n"); return 2; }
	if (argc > 5) g_status = argv[5];

	static struct fuse_operations ops;
	memset(&ops, 0, sizeof(ops));
	ops.getattr = ov_getattr;
	ops.readdir = ov_readdir;
	ops.open = ov_open;
	ops.read = ov_read;
	ops.write = ov_write;
	ops.fsync = ov_fsync;
	ops.flush = ov_flush;
	ops.truncate = ov_truncate;
	ops.chmod = ov_chmod;
	ops.chown = ov_chown;
	ops.utimens = ov_utimens;
	ops.statfs = ov_statfs;

	char *fargv[] = { argv[0], (char *)"-f", (char *)"-o", (char *)"allow_other", argv[4], nullptr };
	write_status(true);
	return fuse_main(5, fargv, &ops, nullptr);
}
