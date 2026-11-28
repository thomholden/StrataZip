// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11, stage 3: the mount's protocol, a core of its own with no Qt.
// (.)
//
// It speaks the Linux kernel's FUSE protocol directly on /dev/fuse, with the kernel's own
// header (<linux/fuse.h>) and no library: libfuse is a convenience over this protocol, and
// StrataZip prefers its own. lab/mnt.cpp is the reference it grew from.
//
// What is served is behind one interface (fsy): the archive side (the index, dirread, the
// journal, the staging store) implements it, so this file knows nothing of archives, and a
// socketpair can stand in for /dev/fuse in the self-test.
//
// Names, as everywhere in StrataZip, in threes:
//   mnt   the mount            fsy   the file system served       att   a node's attributes
//   den   a directory entry    sat   what a SETATTR changes       srv   the request loop
//   opn   mount (a descriptor) off   unmount

#ifndef STRATAZIP_MOUNT_H
#define STRATAZIP_MOUNT_H

#include <csignal>
#include <cstdint>
#include <string>
#include <vector>

namespace stratazip {
namespace mnt {

// A node's attributes, as the kernel sees them.
struct att {
    std::uint64_t                                           ino         = 0;
    std::uint8_t                                            knd         = 0;        // 0 file, 1 directory, 2 link
    std::uint32_t                                           mod         = 0;        // permission bits
    std::uint64_t                                           siz         = 0;        // a link: its target's length
    std::int64_t                                            mtm         = 0;        // ns since the epoch
    // owners (own false: not known, shown as the mounter's), the
    // names a node has (0: unlinked and still open; a directory: 2 and one a subdirectory), and
    // the other two times (0: as mtm).
    bool                                                    own         = false;
    std::uint32_t                                           uid         = 0;
    std::uint32_t                                           gid         = 0;
    std::uint32_t                                           nln         = 1;
    std::int64_t                                            atm         = 0;
    std::int64_t                                            ctm         = 0;
    std::uint8_t                                            spc         = 0;        //a file that is 1 a FIFO, 2 a socket, 3 a character device, 4 a block device
    std::uint64_t                                           rdv         = 0;        //     a device's number
};

// One entry of a directory listing ("." and ".." are added by the loop).
struct den {
    std::string                                             nam;
    std::uint64_t                                           ino         = 0;
    std::uint8_t                                            knd         = 0;
    std::uint8_t                                            spc         = 0;        //as att's
};

// What a SETATTR asks to change.
struct sat {
    bool                                                    hmod        = false;
    bool                                                    hsiz        = false;
    bool                                                    hmtm        = false;
    std::uint32_t                                           mod         = 0;
    std::uint64_t                                           siz         = 0;
    std::int64_t                                            mtm         = 0;        // ns; with hmtm
    bool                                                    huid        = false;    //chown
    bool                                                    hgid        = false;
    bool                                                    hatm        = false;
    std::uint32_t                                           uid         = 0;
    std::uint32_t                                           gid         = 0;
    std::int64_t                                            atm         = 0;
};

// The file system served. Every call returns 0 or an errno (positive). The read-only calls
// must be given; the writable ones answer EROFS unless wrt() says otherwise.
class fsy {
public:
    virtual                                                 ~fsy() = default;
    virtual int                                             lookup(std::uint64_t par, const std::string& nam, att& a) = 0;
    virtual int                                             getattr(std::uint64_t ino, att& a) = 0;
    virtual int                                             readlink(std::uint64_t ino, std::string& tgt) = 0;
    // flags: the open(2) flags; fh: a handle the reads and writes will name.
    virtual int                                             open(std::uint64_t ino, int flags, std::uint64_t& fh) = 0;
    virtual int                                             read(std::uint64_t fh, std::uint64_t off, std::uint32_t len, std::vector<std::uint8_t>& out) = 0;
    virtual void                                            release(std::uint64_t fh) = 0;
    // The children of a directory, and its parent (for "..").
    virtual int                                             readdir(std::uint64_t ino, std::vector<den>& es, std::uint64_t& par) = 0;
    virtual void                                            statfs(std::uint64_t& byt, std::uint64_t& fil) = 0;

    virtual bool                                            wrt() const { return false; }
    virtual int                                             create(std::uint64_t, const std::string&, std::uint32_t, int, att&, std::uint64_t&) { return 30; }  // EROFS
    //spc and rdv: a special file's (0: a plain file).
    virtual int                                             mknod(std::uint64_t, const std::string&, std::uint32_t, att&, std::uint8_t = 0, std::uint64_t = 0) { return 30; }
    virtual int                                             write(std::uint64_t, std::uint64_t, const std::uint8_t*, std::uint32_t) { return 30; }
    virtual int                                             setattr(std::uint64_t, const sat&, att&) { return 30; }
    virtual int                                             mkdir(std::uint64_t, const std::string&, std::uint32_t, att&) { return 30; }
    virtual int                                             unlink(std::uint64_t, const std::string&) { return 30; }
    virtual int                                             rmdir(std::uint64_t, const std::string&) { return 30; }
    // flags: renameat2's (RENAME_NOREPLACE; RENAME_EXCHANGE is answered EINVAL by the loop).
    virtual int                                             rename(std::uint64_t, const std::string&, std::uint64_t, const std::string&, unsigned) { return 30; }
    virtual int                                             symlink(std::uint64_t, const std::string&, const std::string&, att&) { return 30; }
    //a hard link: the node ino under a second name (par, nam).
    virtual int                                             link(std::uint64_t, std::uint64_t, const std::string&, att&) { return 30; }
    //who sends the request about to be served (its uid and gid), so what it makes is theirs.
    virtual void                                            who(std::uint32_t, std::uint32_t) {}
    // An application's fsync: returns only when what was written is safe.
    virtual int                                             fsync(std::uint64_t) { return 0; }
    // the fsyncs that arrived together (group commit); by default one by one.
    virtual int                                             fsyncs(const std::vector<std::uint64_t>& v) { int e = 0; for (const std::uint64_t i : v) { const int r = fsync(i); if (r) e = r; } return e; }
    // Called when no request has come for a while (about the loop's tick), and after each one.
    virtual void                                            tick() {}
    // stage 2, all optional: a descriptor of the file system's own
    // that the loop polls beside the kernel's (its control socket), and what to do when it is
    // ready; whether a handle is to be read past the kernel's page cache (a sealed file, whose
    // pages must not outlive its lock); whether the tree can change from outside the kernel (a
    // lock opened or shut), so replies are cached for a second, not an hour.
    virtual int                                             ctl() { return -1; }
    virtual void                                            onctl() {}
    virtual bool                                            dio(std::uint64_t) { return false; }
    virtual bool                                            chg() { return false; }
};

// A /dev/fuse descriptor mounted at mp: as root by mount(2), otherwise through fusermount3,
// which hands the descriptor back over a socket (SCM_RIGHTS), as libfuse does. -1 on failure,
// with the reason in err.
//aot, allow_other: users other than the mounter may enter, the kernel checking each one's
// permissions against the owners and modes served (default_permissions), as on ext4. Through
// fusermount3 it needs user_allow_other in /etc/fuse.conf.
int                                                         opn(const std::string& mp, bool rw, std::string& err, bool aot = false);

// Unmount mp: umount2 as root, fusermount3 -u otherwise. 0, or an errno (EBUSY: in use).
int                                                         off(const std::string& mp);

// Serve requests from fd until the file system is unmounted (returns 0), or *stp is set
// (returns 1: the caller unmounts, then serves again until the end), or the descriptor fails
// (returns -1, the reason in err). rw: the mount was made writable. A socketpair
// (SOCK_SEQPACKET) may stand in for /dev/fuse.
int                                                         srv(int fd, fsy& f, bool rw, const volatile std::sig_atomic_t* stp = nullptr, int tck = 1000, std::string* err = nullptr);

// What the loop has answered, for the mount's report.
struct stt {
    std::uint64_t                                           req         = 0;        // requests answered
    std::uint64_t                                           red         = 0;        // bytes read
    std::uint64_t                                           wrn         = 0;        // bytes written
};
const stt&                                                  sts();

} // namespace mnt
} // namespace stratazip

#endif
