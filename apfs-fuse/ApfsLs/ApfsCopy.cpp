/*
 * apfs-copy: copies a directory tree out of a (damaged) APFS volume straight
 * from the raw device with ApfsLib, without a FUSE mount, so that metadata the
 * mount cannot carry survives: creation date, extended attributes, BSD flags.
 *
 * The source device is only ever opened read-only by ApfsLib.
 *
 * Usage: apfs-copy <device> <source_inode> <dest_dir> [omap_fallback_file]
 *        (volume password on stdin; run with sudo, files are handed back to
 *         the invoking user via SUDO_UID/SUDO_GID)
 *
 * Every problem is reported on stderr as "ERROR ..." or "WARN ..." with the
 * destination path; the exit status is non-zero if any ERROR occurred.
 */

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <map>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/xattr.h>
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

static uid_t g_owner = 0;
static gid_t g_group = 0;

static uint64_t n_files = 0, n_dirs = 0, n_links = 0, n_hardlinks = 0, n_bytes = 0;
static uint64_t n_skipped = 0;
static uint64_t n_errors = 0, n_warnings = 0, n_xattrs = 0, n_compressed = 0;
static time_t g_last_progress = 0;

// inode id -> first destination path, for hard links
static std::map<uint64_t, std::string> g_seen_files;

static void err(const std::string &path, const char *what, int e = 0)
{
	n_errors++;
	fprintf(stderr, "ERROR %s: %s%s%s\n", what, path.c_str(), e ? " : " : "", e ? strerror(e) : "");
}

static void warn(const std::string &path, const char *what, int e = 0)
{
	n_warnings++;
	fprintf(stderr, "WARN %s: %s%s%s\n", what, path.c_str(), e ? " : " : "", e ? strerror(e) : "");
}

static void progress(bool force = false)
{
	time_t now = time(nullptr);
	if (!force && now - g_last_progress < 10) return;
	g_last_progress = now;
	printf("[apfs-copy] %" PRIu64 " files, %" PRIu64 " dirs, %" PRIu64 " symlinks, %.2f GB, %" PRIu64 " errors, %" PRIu64 " warnings\n",
		n_files, n_dirs, n_links, n_bytes / 1e9, n_errors, n_warnings);
	fflush(stdout);
}

static bool is_all_zero(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i]) return false;
	return true;
}

static struct timespec to_ts(uint64_t ns)
{
	struct timespec ts;
	ts.tv_sec = ns / 1000000000ULL;
	ts.tv_nsec = ns % 1000000000ULL;
	return ts;
}

// Extended attributes that are internal to APFS or cannot be set from user space.
static bool skip_xattr(const std::string &name, bool compressed)
{
	if (name == "com.apple.decmpfs") return true;            // compression header, data is stored decompressed
	if (name == "com.apple.fs.symlink") return true;         // symlink target
	if (name == "com.apple.system.Security") return true;    // ACL blob, not settable as an xattr
	if (compressed && name == "com.apple.ResourceFork") return true; // holds the compressed data
	return false;
}

// Applies xattrs, mode, owner, flags and dates. Called last for each object.
static void apply_metadata(ApfsDir &dir, uint64_t ino, const ApfsDir::Inode &inode, const std::string &path, bool is_symlink)
{
	const int nofollow_x = is_symlink ? XATTR_NOFOLLOW : 0;
	const bool compressed = (inode.bsd_flags & APFS_UF_COMPRESSED) != 0;
	std::vector<std::string> names;

	if (dir.ListAttributes(names, ino)) {
		for (const std::string &name : names) {
			std::vector<uint8_t> data;
			if (skip_xattr(name, compressed)) continue;
			if (!dir.GetAttribute(data, ino, name.c_str())) { warn(path, ("cannot read xattr " + name).c_str()); continue; }
			if (setxattr(path.c_str(), name.c_str(), data.data(), data.size(), 0, nofollow_x) != 0)
				warn(path, ("cannot set xattr " + name).c_str(), errno);
			else
				n_xattrs++;
		}
	}

	if (lchown(path.c_str(), g_owner, g_group) != 0) warn(path, "chown", errno);
	if (!is_symlink && chmod(path.c_str(), inode.mode & 07777) != 0) warn(path, "chmod", errno);

	// Dates: creation, modification, access. Order of the buffer follows the
	// attribute bit order (crtime, modtime, acctime).
	struct attrlist al;
	struct { struct timespec cr, mod, acc; } __attribute__((packed)) times;
	memset(&al, 0, sizeof(al));
	al.bitmapcount = ATTR_BIT_MAP_COUNT;
	al.commonattr = ATTR_CMN_CRTIME | ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME;
	times.cr = to_ts(inode.create_time);
	times.mod = to_ts(inode.mod_time);
	times.acc = to_ts(inode.access_time);
	if (setattrlist(path.c_str(), &al, &times, sizeof(times), is_symlink ? FSOPT_NOFOLLOW : 0) != 0)
		warn(path, "set dates", errno);

	// User flags only (hidden, nodump, ...). Never the compression flag, never
	// immutable/append (they would lock the copy), never system flags.
	uint32_t flags = inode.bsd_flags & 0xFFFF;
	flags &= ~(uint32_t)(APFS_UF_COMPRESSED | UF_IMMUTABLE | UF_APPEND | UF_DATAVAULT | UF_TRACKED);
	if (flags && lchflags(path.c_str(), flags) != 0) warn(path, "set flags", errno);
}

// Resume support: metadata (and therefore the modification date) is applied
// only after a file was written completely, so same size + same date means done.
static bool already_copied(const ApfsDir::Inode &inode, const std::string &path)
{
	struct stat st;

	if (lstat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode))
		return false;
	if ((uint64_t)st.st_mtimespec.tv_sec != inode.mod_time / 1000000000ULL)
		return false;
	if (inode.bsd_flags & APFS_UF_COMPRESSED)
		return true;
	uint64_t size = (inode.optional_present_flags & ApfsDir::Inode::INO_HAS_DSTREAM) ? inode.ds_size : 0;
	return (uint64_t)st.st_size == size;
}

static bool copy_file(ApfsDir &dir, uint64_t ino, const ApfsDir::Inode &inode, const std::string &path)
{
	int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
	if (fd < 0) { err(path, "cannot create", errno); return false; }

	bool ok = true;
	uint64_t size = 0;

	if (inode.bsd_flags & APFS_UF_COMPRESSED) {
		std::vector<uint8_t> attr, data;
		n_compressed++;
		if (!dir.GetAttribute(attr, ino, "com.apple.decmpfs")) {
			err(path, "compressed file without decmpfs attribute");
			ok = false;
		} else if (!DecompressFile(dir, ino, data, attr)) {
			err(path, "decompression failed");
			ok = false;
		} else {
			size = data.size();
			size_t off = 0;
			while (off < data.size()) {
				ssize_t w = write(fd, data.data() + off, data.size() - off);
				if (w <= 0) { err(path, "write", errno); ok = false; break; }
				off += w;
			}
		}
	} else if (inode.optional_present_flags & ApfsDir::Inode::INO_HAS_DSTREAM) {
		const size_t chunk = 8 * 1024 * 1024;
		std::vector<uint8_t> buf(chunk);
		uint64_t off = 0;
		size = inode.ds_size;

		while (off < size) {
			size_t n = (size - off < chunk) ? (size_t)(size - off) : chunk;
			memset(buf.data(), 0, n);
			if (!dir.ReadFile(buf.data(), inode.private_id, off, n)) {
				fprintf(stderr, "ERROR read failed at offset %" PRIu64 " of %" PRIu64 ": %s\n", off, size, path.c_str());
				n_errors++;
				ok = false;
				break;
			}
			if (is_all_zero(buf.data(), n)) {
				// keep holes sparse
				if (lseek(fd, off + n, SEEK_SET) < 0) { err(path, "seek", errno); ok = false; break; }
			} else {
				size_t done = 0;
				if (lseek(fd, off, SEEK_SET) < 0) { err(path, "seek", errno); ok = false; break; }
				while (done < n) {
					ssize_t w = write(fd, buf.data() + done, n - done);
					if (w <= 0) { err(path, "write", errno); ok = false; break; }
					done += w;
				}
				if (!ok) break;
			}
			off += n;
			n_bytes += n;
			progress();
		}
		if (ok && ftruncate(fd, size) != 0) { err(path, "truncate", errno); ok = false; }
	}

	if (inode.bsd_flags & APFS_UF_COMPRESSED) n_bytes += size;
	close(fd);

	if (!ok) {
		// Leave no file that looks complete but is not.
		std::string bad = path + ".INCOMPLETE";
		rename(path.c_str(), bad.c_str());
	}
	return ok;
}

static void copy_tree(ApfsVolume &vol, uint64_t dir_ino, const std::string &dest, int depth)
{
	ApfsDir dir(vol);
	std::vector<ApfsDir::DirRec> list;

	if (depth > 200) { err(dest, "directory nesting too deep, skipped"); return; }

	if (mkdir(dest.c_str(), 0700) != 0 && errno != EEXIST) { err(dest, "mkdir", errno); return; }
	n_dirs++;

	const uint64_t missing_before = g_btree_missing_nodes;
	if (!dir.ListDirectory(list, dir_ino)) { err(dest, "cannot list directory"); return; }
	if (g_btree_missing_nodes != missing_before)
		err(dest, "directory listing INCOMPLETE, part of the file index is unreadable");

	for (const ApfsDir::DirRec &e : list) {
		if (e.name.empty() || e.name == "." || e.name == ".." || e.name.find('/') != std::string::npos) {
			warn(dest + "/" + e.name, "unusable name, skipped");
			continue;
		}

		const std::string path = dest + "/" + e.name;
		ApfsDir::Inode inode;

		if (!dir.GetInode(inode, e.file_id)) { err(path, "cannot read inode"); continue; }

		if (S_ISDIR(inode.mode)) {
			copy_tree(vol, e.file_id, path, depth + 1);
			apply_metadata(dir, e.file_id, inode, path, false);
		} else if (S_ISREG(inode.mode)) {
			auto seen = g_seen_files.find(e.file_id);
			if (seen != g_seen_files.end()) {
				if (link(seen->second.c_str(), path.c_str()) != 0 && errno != EEXIST) err(path, "hard link", errno);
				else n_hardlinks++;
				continue;
			}
			if (already_copied(inode, path)) {
				n_skipped++;
				if (inode.nchildren_nlink > 1) g_seen_files[e.file_id] = path;
				continue;
			}
			if (copy_file(dir, e.file_id, inode, path)) {
				unlink((path + ".INCOMPLETE").c_str());
				apply_metadata(dir, e.file_id, inode, path, false);
				n_files++;
				if (inode.nchildren_nlink > 1) g_seen_files[e.file_id] = path;
			}
		} else if (S_ISLNK(inode.mode)) {
			std::vector<uint8_t> target;
			if (!dir.GetAttribute(target, e.file_id, "com.apple.fs.symlink")) { err(path, "cannot read symlink target"); continue; }
			target.push_back(0);
			unlink(path.c_str());
			if (symlink(reinterpret_cast<const char *>(target.data()), path.c_str()) != 0) { err(path, "symlink", errno); continue; }
			apply_metadata(dir, e.file_id, inode, path, true);
			n_links++;
		} else {
			warn(path, "special file (device/socket/fifo), skipped");
		}
		progress();
	}
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		fprintf(stderr, "Syntax: %s <device> <source_inode> <dest_dir> [omap_fallback_file]   (password on stdin)\n", argv[0]);
		return 1;
	}

	const uint64_t src_ino = strtoull(argv[2], nullptr, 10);
	const std::string dest = argv[3];

	g_debug = 0;
	g_lax = false;   // never hand back data the library could not read properly

	g_owner = getenv("SUDO_UID") ? (uid_t)strtoul(getenv("SUDO_UID"), nullptr, 10) : getuid();
	g_group = getenv("SUDO_GID") ? (gid_t)strtoul(getenv("SUDO_GID"), nullptr, 10) : getgid();

	if (argc > 4) {
		size_t n = OmapFallbackLoad(argv[4]);
		printf("[apfs-copy] loaded %zu salvaged omap mappings\n", n);
	}

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

	ApfsDir dir(*volume);
	ApfsDir::Inode root;
	if (!dir.GetInode(root, src_ino) || !S_ISDIR(root.mode)) {
		fprintf(stderr, "source inode %" PRIu64 " is not a readable directory\n", src_ino);
		return 5;
	}

	printf("[apfs-copy] copying inode %" PRIu64 " -> %s\n", src_ino, dest.c_str());
	fflush(stdout);

	copy_tree(*volume, src_ino, dest, 0);
	apply_metadata(dir, src_ino, root, dest, false);

	progress(true);
	printf("[apfs-copy] %" PRIu64 " files skipped (already copied)\n", n_skipped);
	printf("[apfs-copy] done: %" PRIu64 " hard links, %" PRIu64 " compressed files, %" PRIu64 " xattrs set\n", n_hardlinks, n_compressed, n_xattrs);
	return n_errors ? 6 : 0;
}
