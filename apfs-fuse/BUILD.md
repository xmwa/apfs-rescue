# Building the patched apfs-fuse and the added tools

1. Clone upstream apfs-fuse (GPL v2) and apply the patch:

       git clone --recursive https://github.com/sgan81/apfs-fuse
       cd apfs-fuse
       git apply ../apfs-fuse-changes.diff
       cp -r ../ApfsLs .

   The patch adds the `ApfsLs` targets to `CMakeLists.txt`, a salvaged-mapping fallback and
   a level check to the B-tree lookup, hole logging to the macOS device layer, and a few
   warnings around crypto keys.

2. Build with Apple's Command Line Tools and fuse-t (https://www.fuse-t.org/):

       mkdir build && cd build
       DEVELOPER_DIR=/Library/Developer/CommandLineTools cmake .. -DUSE_FUSE3=OFF
       DEVELOPER_DIR=/Library/Developer/CommandLineTools make apfs-ls apfs-omapscan apfs-fsscan \
           apfs-audit apfs-copy apfs-verify apfs-refs apfs-reloc apfs-snapcheck apfs-snaps apfs-rawscan

   On some Command Line Tools versions the C++ standard headers need explicit SDK include
   flags; set `CXXFLAGS` to point at the SDK's `usr/include/c++/v1` if the build cannot find
   `<string>`.

3. Every tool opens the device read-only. The password for an encrypted volume is read from
   standard input, so pipe it from the keychain rather than typing it on a command line:

       security find-generic-password -a "$APFS_VOL_UUID" -s "$APFS_VOL_UUID" -w | xxd -r -p | apfs-ls /dev/rdiskNsM 1
