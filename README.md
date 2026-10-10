# apfs-rescue

Tools written during the recovery and in-place repair of an APFS volume that macOS
would not mount and that Disk Utility's First Aid declared "corrupt and cannot be
repaired". The long story is in the blog post [How to save an APFS HDD](https://blog.wangxm.com/2026/10/how-to-save-an-apfs-hdd/). This repository holds the
code: a patched read-only driver with extra command-line tools, a block-ownership checker
that catches a class of damage Apple's checker does not, an overlay for rehearsing
writes, and the repair planners and patchers that were actually used.

## Read this first

**Use at your own discretion. The author accepts no responsibility for any loss of data,
damage to hardware, or any other consequence of using anything in this repository.** These
tools were written for one drive, one backup image and a handful of test volumes. They
have not been tested anywhere else, they are not a product, and they are not supported.
Some of them write to raw block devices. Used wrongly, or on a drive that is damaged in a
way these tools do not expect, they will destroy data that could otherwise have been
recovered.

If you are looking at this because your own drive is in trouble:

1. Stop writing to the drive. Do not run repair tools in a loop.
2. Copy everything you can read off the drive first, and verify the copy with a second
   read. The read-only tools here can help with that even when macOS refuses to mount.
3. Only then think about repair, and rehearse any repair on an overlay or a copy before
   touching the real device.

Every tool here opens the device read-only unless it is explicitly a writer and is given
the device to write to. The writers are `omap_repair.py`, `bundle_patch.py`,
`spaceman_fix.py`, `repair2_device.py` and `realtest.sh mountrw`. Everything else only
reads.

## What is here

### `apfs-fuse/`

A patch against [sgan81/apfs-fuse](https://github.com/sgan81/apfs-fuse) and a folder of
added command-line tools built on its library. See `apfs-fuse/BUILD.md`.

| Tool | What it does |
|---|---|
| `apfs-ls` | Lists one folder of a volume without mounting it, with every error printed. Can use a fallback table of salvaged object-map entries. |
| `apfs-omapscan` | Walks the object map from its top node, reports pages that do not match their parent, and finds valid but unlinked older pages in the map's region of the disk. |
| `apfs-fsscan` | Decrypts a region of the disk and records every block that is a valid file-index node (object ID, version, block). |
| `apfs-rawscan` | The same for every kind of APFS object, for an image whose checkpoints are damaged. |
| `apfs-audit` | Walks the whole file index and reports anything out of place. |
| `apfs-copy` | Copies a volume's files out with dates, extended attributes, flags and hard links intact, naming every file it cannot read, resumable. |
| `apfs-verify` | Re-reads a sample of files from the drive and compares them with a copy. |
| `apfs-refs` | Dumps every reference the file system holds: index nodes, file extents, extent-tree records. Input for the ownership check. |
| `apfs-snaps`, `apfs-snapcheck` | Lists the snapshots of a volume and checks the index as seen from each one. |
| `apfs-reloc` | Decrypts a node at one block and re-encrypts it for another, for repairs that move pages on an encrypted volume. |

### `tools/`

Python, each file declares its dependencies inline and runs with `uv run`.

| Tool | What it does |
|---|---|
| `refcheck.py` | The ownership check. Reads the free-space bitmaps, both free queues, the object map, the index references and the extent trees, and insists that nothing in use is marked free, nothing in use sits in a free queue, and no block has two owners. Plain mode (`-`) works on unencrypted volumes without an `apfs-refs` dump. The `capture:` source keeps a local copy of every block read. |
| `refcheck_extra.py` | Further checks for a Time Machine image: pending reaper work, exact space accounting, every referenced block really stored in the sparse bundle, every backup's entry point readable, a random sample of index pages. |
| `omap_repair.py` | Plans, checks, applies and undoes an in-place rewrite of object-map pages from salvaged entries. Writer. |
| `omap_repair_mv.py` | The multi-version planner for a volume with snapshots. |
| `repair2_plan.py`, `repair2_device.py` | The second repair: place saved index pages into fresh blocks that sit in no free queue and point the map at them. Writer. |
| `reloc_plain.py` | Moves blocks that are in use but queued for release to free blocks, for an unencrypted volume inside a sparse bundle. |
| `spaceman_fix.py` | Marks under-allocated blocks as allocated in the bitmaps and chunk records. Writer. |
| `bundle_patch.py` | Checks, applies and undoes a block patch directly in a sparse bundle's band files, with the bundle detached. Writer. |
| `capimg_pack.py`, `capimg_apply.py` | Maintain the packed capture store and apply a patch to a local copy. |
| `write_workload.py`, `bigwrite.py`, `g3_compare.py` | The write tests and the before/after comparison of pre-existing index pages. |
| `native-compare.py` | Compares a sample of files on the mounted volume with a copy made earlier. |
| `e3_analyze.py`, `e3_beyond.py`, `leftover_scan.py`, `band_vs_device.py`, `mini_inspect.py` | One-off analyses of findings on the Time Machine image, kept for reference. |

### `overlay/`

A small FUSE pass-through file system that opens a device read-only and keeps every
write in memory. macOS's own shadow-file attach refuses disks above about 8 TB; this does
not. Build with fuse-t:

    clang++ -std=c++17 -O2 overlayfs.cpp -o overlayfs $(pkg-config --cflags --libs fuse-t)

### `scripts/`

Shell drivers used around the tools: mount the drive read-only or writable by UUID, run
the gate (ownership check, Apple's check, before/after compare), serve raw blocks from a
root helper so the tools can run unprivileged, watch a Time Machine run, and stop backups
that start by themselves. They read their identifiers from the environment:

| Variable | Meaning |
|---|---|
| `APFS_VOL_UUID` | UUID of the APFS volume (as shown by `diskutil info`) |
| `APFS_PART_UUID` | UUID of the partition that holds the container |
| `DRIVE_MOUNT_NAME` | the volume name as it appears under `/Volumes` |
| `USB_DRIVE_MATCH` | a string that identifies the drive in `ioreg -p IOUSB` output |

## Licence

GPL v2, the same as apfs-fuse, since the C++ tools are built on its library. See `LICENSE`.
