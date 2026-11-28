// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Steven Thomas Holden
//
// This file is part of StrataZip. StrataZip is free software: you can redistribute it
// and/or modify it under the terms of the GNU Affero General Public License, version 3,
// as published by the Free Software Foundation. It is distributed WITHOUT ANY WARRANTY;
// see the LICENSE file. A commercial licence is also offered: see COMMERCIAL.md.
//
// format 11, stage 3: the mount's protocol (see the header). No Qt: the kernel's FUSE
// protocol on a descriptor, answered from an fsy.

#include "mount.h"

#include <linux/fuse.h>

#include <algorithm>
#include <functional>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <ctime>
#include <time.h>
#include <unistd.h>

namespace stratazip {
namespace mnt {

namespace {

stt                                                         gst;

// Whole seconds a reply may be cached by the kernel: an hour on a read-only mount, where
// nothing changes; a second on a writable one, where only this process changes anything and
// every change passes through the kernel anyway.
// stage 2: a mount whose tree can change from outside the kernel
// (a lock unlocked or locked on it) answers with a second too, read-only or not.
bool                                                        gch         = false;
std::uint64_t
ttl(bool rw) { return rw || gch ? 1 : 3600; }

void
fill(const att& n, bool rw, fuse_attr& a) {
    std::memset(&a, 0, sizeof a);
    a.ino = n.ino; a.size = n.siz; a.blocks = (n.siz + 511) / 512;
    auto tm = [](std::int64_t t, std::uint64_t& s, std::uint32_t& ns) { s = std::uint64_t(t / 1000000000); ns = std::uint32_t(t % 1000000000); };
    tm(n.mtm, a.mtime, a.mtimensec);
    tm(n.atm ? n.atm : n.mtm, a.atime, a.atimensec);
    tm(n.ctm ? n.ctm : n.mtm, a.ctime, a.ctimensec);
    // No write bit on a read-only mount: read-only by every route (the flags, the bits shown, EROFS).
    const std::uint32_t pm = n.knd == 2 ? 0777 : (n.mod & 07777 & (rw ? 07777u : ~0222u));
    a.mode = (n.knd == 1 ? S_IFDIR : n.knd == 2 ? S_IFLNK : n.spc == 1 ? S_IFIFO : n.spc == 2 ? S_IFSOCK : n.spc == 3 ? S_IFCHR : n.spc == 4 ? S_IFBLK : S_IFREG) | pm;
    a.rdev = std::uint32_t(n.rdv);
    a.nlink = n.knd == 1 ? std::max<std::uint32_t>(2, n.nln) : n.nln; a.blksize = 65536;
    a.uid = n.own ? n.uid : getuid(); a.gid = n.own ? n.gid : getgid();
}

int
reply(int fd, std::uint64_t unq, int err, const void* d = nullptr, size_t n = 0, const void* d2 = nullptr, size_t n2 = 0) {
    fuse_out_header h{}; h.len = std::uint32_t(sizeof h + n + n2); h.error = -err; h.unique = unq;
    iovec v[3] = {{&h, sizeof h}, {const_cast<void*>(d), n}, {const_cast<void*>(d2), n2}};
    const int nv = d2 ? 3 : d ? 2 : 1;
    ++gst.req;
    // ENOENT: the request was interrupted and the kernel no longer waits for it.
    if (writev(fd, v, nv) < 0 && errno != ENOENT) return errno;
    return 0;
}

int
entry(int fd, std::uint64_t unq, const att& a, bool rw, const fuse_open_out* oo = nullptr) {
    fuse_entry_out e{}; e.nodeid = a.ino; e.generation = 1; e.entry_valid = e.attr_valid = ttl(rw); fill(a, rw, e.attr);
    return oo ? reply(fd, unq, 0, &e, sizeof e, oo, sizeof *oo) : reply(fd, unq, 0, &e, sizeof e);
}

// The name(s) after a request's fixed part, NUL-terminated, checked to lie inside it.
bool
names(const char* p, const char* end, std::string& a, std::string* b = nullptr) {
    const char* z = static_cast<const char*>(std::memchr(p, 0, size_t(end - p)));
    if (!z) return false;
    a.assign(p, z);
    if (!b) return !a.empty();
    const char* z2 = static_cast<const char*>(std::memchr(z + 1, 0, size_t(end - z - 1)));
    if (!z2) return false;
    b->assign(z + 1, z2);
    return !a.empty() && !b->empty();
}

} // namespace

const stt&
sts() { return gst; }

int
opn(const std::string& mp, bool rw, std::string& err, bool aot) {
    const std::string o = std::string(rw ? "rw" : "ro") + ",nosuid,nodev,default_permissions,fsname=stratazip,subtype=stratazip" + (aot ? ",allow_other" : "");
    if (geteuid() == 0) {
        const int fd = ::open("/dev/fuse", O_RDWR | O_CLOEXEC);
        if (fd < 0) { err = std::string("cannot open /dev/fuse: ") + std::strerror(errno); return -1; }
        char opt[256];
        std::snprintf(opt, sizeof opt, "fd=%d,rootmode=40000,user_id=%u,group_id=%u,default_permissions%s", fd, getuid(), getgid(), aot ? ",allow_other" : "");
        if (mount("stratazip", mp.c_str(), "fuse.stratazip", MS_NOSUID | MS_NODEV | (rw ? 0ul : static_cast<unsigned long>(MS_RDONLY)), opt) != 0) {
            err = std::string("cannot mount at ") + mp + ": " + std::strerror(errno); ::close(fd); return -1;
        }
        return fd;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { err = std::strerror(errno); return -1; }
    const pid_t pid = fork();
    if (pid == 0) {
        ::close(sv[0]);
        char e[16]; std::snprintf(e, sizeof e, "%d", sv[1]); setenv("_FUSE_COMMFD", e, 1);
        execlp("fusermount3", "fusermount3", "-o", o.c_str(), "--", mp.c_str(), static_cast<char*>(nullptr));
        _exit(127);
    }
    ::close(sv[1]);
    char c; iovec v{&c, 1}; char ctl[CMSG_SPACE(sizeof(int))]; msghdr m{};
    m.msg_iov = &v; m.msg_iovlen = 1; m.msg_control = ctl; m.msg_controllen = sizeof ctl;
    int fd = -1;
    if (recvmsg(sv[0], &m, 0) > 0)
        for (cmsghdr* h = CMSG_FIRSTHDR(&m); h; h = CMSG_NXTHDR(&m, h))
            if (h->cmsg_type == SCM_RIGHTS) std::memcpy(&fd, CMSG_DATA(h), sizeof fd);
    int st = 0; waitpid(pid, &st, 0); ::close(sv[0]);
    if (fd < 0) err = WIFEXITED(st) && WEXITSTATUS(st) == 127 ? "fusermount3 not found (install fuse3)" : "fusermount3 could not mount " + mp;
    return fd;
}

int
off(const std::string& mp) {
    if (geteuid() == 0) return umount2(mp.c_str(), 0) == 0 ? 0 : errno;
    const pid_t pid = fork();
    if (pid == 0) {
        const int nul = ::open("/dev/null", O_WRONLY); if (nul >= 0) { dup2(nul, 2); }
        execlp("fusermount3", "fusermount3", "-u", "--", mp.c_str(), static_cast<char*>(nullptr)); _exit(127);
    }
    int st = 0; waitpid(pid, &st, 0);
    return WIFEXITED(st) && WEXITSTATUS(st) == 0 ? 0 : EBUSY;
}

int
srv(int fd, fsy& f, bool rw, const volatile std::sig_atomic_t* stp, int tck, std::string* err) {
    // The largest request: a write of max_write bytes and its header.
    std::vector<char> buf((1 << 20) + 4096);
    std::vector<std::uint8_t> dat;
    const bool w = rw && f.wrt();
    // group commit. An fsync's reply waits while more requests are queued (served
    // first, other writers' fsyncs among them); once none is, one commit answers every fsync held.
    // Each is answered only after a commit that holds everything written before it.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> pfs;   // (unique, node)
    auto flush = [&]() {
        if (pfs.empty()) return;
        std::vector<std::uint64_t> ids;
        for (const auto& [u, i] : pfs) if (std::find(ids.begin(), ids.end(), i) == ids.end()) ids.push_back(i);
        const int e = f.fsyncs(ids);
        for (const auto& [u, i] : pfs) reply(fd, u, e);
        pfs.clear();
    };
    struct fin { std::function<void()> g; ~fin() { g(); } } fl{flush};
    for (;;) {
        if (!pfs.empty()) { pollfd q{fd, POLLIN, 0}; if (pfs.size() >= 256 || poll(&q, 1, 0) <= 0 || !(q.revents & POLLIN)) flush(); }
        if (stp && *stp) return 1;
        // stage 2: the file system's own descriptor (its control socket), polled beside.
        const int cfd = f.ctl();
        pollfd p[2] = {{fd, POLLIN, 0}, {cfd, POLLIN, 0}};
        const int pr = poll(p, cfd >= 0 ? 2 : 1, tck);
        if (pr < 0) { if (errno == EINTR) continue; if (err) *err = std::strerror(errno); return -1; }
        if (cfd >= 0 && (p[1].revents & POLLIN)) { f.onctl(); if (!(p[0].revents & POLLIN)) continue; }
        if (pr == 0) { flush(); f.tick(); continue; }
        gch = f.chg();
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ENOENT) continue;
            if (errno == ENODEV) return 0;                  // unmounted
            if (err) *err = std::strerror(errno);
            return -1;
        }
        if (n == 0) return 0;                               // a socketpair's other end closed
        if (size_t(n) < sizeof(fuse_in_header)) continue;
        const fuse_in_header* in = reinterpret_cast<const fuse_in_header*>(buf.data());
        const char* arg = buf.data() + sizeof(fuse_in_header);
        const char* end = buf.data() + std::min<size_t>(size_t(n), in->len);
        const std::uint64_t id = in->nodeid, unq = in->unique;
        const size_t aln = size_t(end - arg);
        auto has = [&](size_t k) { return aln >= k; };
        f.who(in->uid, in->gid);
        switch (in->opcode) {
        case FUSE_INIT: {
            if (!has(sizeof(std::uint32_t) * 2)) { reply(fd, unq, EINVAL); break; }
            const fuse_init_in* ii = reinterpret_cast<const fuse_init_in*>(arg);
            fuse_init_out o{};
            o.major = FUSE_KERNEL_VERSION; o.minor = std::min<std::uint32_t>(ii->minor, FUSE_KERNEL_MINOR_VERSION);
            o.max_readahead = has(12) ? ii->max_readahead : 131072;
            o.flags = w ? FUSE_BIG_WRITES : 0;
            o.max_background = 16; o.congestion_threshold = 12; o.max_write = 1 << 17; o.time_gran = 1;
            reply(fd, unq, 0, &o, sizeof o); break; }
        case FUSE_DESTROY:
            reply(fd, unq, 0); return 0;
        case FUSE_FORGET: case FUSE_BATCH_FORGET: case FUSE_INTERRUPT:
            break;                                          // no reply
        case FUSE_LOOKUP: {
            std::string nm; att a;
            if (!names(arg, end, nm)) { reply(fd, unq, EINVAL); break; }
            const int e = f.lookup(id, nm, a);
            if (e) { reply(fd, unq, e); break; }
            entry(fd, unq, a, w); break; }
        case FUSE_GETATTR: {
            att a; const int e = f.getattr(id, a);
            if (e) { reply(fd, unq, e); break; }
            fuse_attr_out o{}; o.attr_valid = ttl(w); fill(a, w, o.attr); reply(fd, unq, 0, &o, sizeof o); break; }
        case FUSE_READLINK: {
            std::string t; const int e = f.readlink(id, t);
            if (e) reply(fd, unq, e); else reply(fd, unq, 0, t.data(), t.size());
            break; }
        case FUSE_OPEN: {
            if (!has(sizeof(fuse_open_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_open_in* oi = reinterpret_cast<const fuse_open_in*>(arg);
            if (!w && (oi->flags & O_ACCMODE) != O_RDONLY) { reply(fd, unq, EROFS); break; }
            std::uint64_t fh = 0; const int e = f.open(id, int(oi->flags), fh);
            if (e) { reply(fd, unq, e); break; }
            fuse_open_out o{}; o.fh = fh; o.open_flags = f.dio(fh) ? FOPEN_DIRECT_IO : w ? 0 : FOPEN_KEEP_CACHE;
            reply(fd, unq, 0, &o, sizeof o); break; }
        case FUSE_READ: {
            if (!has(sizeof(fuse_read_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_read_in* ri = reinterpret_cast<const fuse_read_in*>(arg);
            const int e = f.read(ri->fh, ri->offset, std::min<std::uint32_t>(ri->size, 1u << 20), dat);
            if (e) { reply(fd, unq, e); break; }
            gst.red += dat.size();
            reply(fd, unq, 0, dat.data(), dat.size()); break; }
        case FUSE_OPENDIR: {
            att a; const int e = f.getattr(id, a);
            if (e) { reply(fd, unq, e); break; }
            if (a.knd != 1) { reply(fd, unq, ENOTDIR); break; }
            fuse_open_out o{}; o.fh = id; reply(fd, unq, 0, &o, sizeof o); break; }
        case FUSE_READDIR: {
            if (!has(sizeof(fuse_read_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_read_in* ri = reinterpret_cast<const fuse_read_in*>(arg);
            std::vector<den> es; std::uint64_t par = 1;
            const int e = f.readdir(ri->fh, es, par);
            if (e) { reply(fd, unq, e); break; }
            es.insert(es.begin(), {den{".", ri->fh, 1}, den{"..", par, 1}});
            std::vector<char> out;
            for (size_t i = size_t(ri->offset); i < es.size(); ++i) {
                const size_t rec = FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + es[i].nam.size());
                if (out.size() + rec > ri->size) break;
                const size_t at = out.size(); out.resize(at + rec, 0);
                fuse_dirent* de = reinterpret_cast<fuse_dirent*>(out.data() + at);
                de->ino = es[i].ino; de->off = i + 1; de->namelen = std::uint32_t(es[i].nam.size());
                de->type = es[i].knd == 1 ? DT_DIR : es[i].knd == 2 ? DT_LNK : es[i].spc == 1 ? DT_FIFO : es[i].spc == 2 ? DT_SOCK : es[i].spc == 3 ? DT_CHR : es[i].spc == 4 ? DT_BLK : DT_REG;
                std::memcpy(out.data() + at + FUSE_NAME_OFFSET, es[i].nam.data(), es[i].nam.size());
            }
            reply(fd, unq, 0, out.data(), out.size()); break; }
        case FUSE_RELEASE: {
            if (has(sizeof(fuse_release_in))) f.release(reinterpret_cast<const fuse_release_in*>(arg)->fh);
            reply(fd, unq, 0); break; }
        case FUSE_RELEASEDIR: case FUSE_FLUSH:
            reply(fd, unq, 0); break;                       // closing does not commit, as on any file system
        case FUSE_FSYNC: case FUSE_FSYNCDIR:
            if (w) pfs.push_back({unq, id}); else reply(fd, unq, 0);   // answered by the next group commit
            break;
        case FUSE_STATFS: {
            fuse_statfs_out s{}; std::uint64_t byt = 0, fil = 0; f.statfs(byt, fil);
            s.st.bsize = s.st.frsize = 4096; s.st.blocks = (byt + 4095) / 4096; s.st.files = fil; s.st.namelen = 255;
            reply(fd, unq, 0, &s, sizeof s); break; }
        case FUSE_ACCESS: {
            const fuse_access_in* ai = reinterpret_cast<const fuse_access_in*>(arg);
            reply(fd, unq, has(sizeof *ai) && (ai->mask & W_OK) && !w ? EROFS : 0); break; }

        // ---- Writable: EROFS on a read-only mount ----
        case FUSE_CREATE: {
            if (!w) { reply(fd, unq, EROFS); break; }
            if (!has(sizeof(fuse_create_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_create_in* ci = reinterpret_cast<const fuse_create_in*>(arg);
            std::string nm; att a; std::uint64_t fh = 0;
            if (!names(arg + sizeof *ci, end, nm)) { reply(fd, unq, EINVAL); break; }
            const int e = f.create(id, nm, ci->mode & ~ci->umask, int(ci->flags), a, fh);
            if (e) { reply(fd, unq, e); break; }
            fuse_open_out o{}; o.fh = fh; o.open_flags = f.dio(fh) ? FOPEN_DIRECT_IO : 0;
            entry(fd, unq, a, w, &o); break; }
        case FUSE_MKNOD: {
            if (!w) { reply(fd, unq, EROFS); break; }
            if (!has(sizeof(fuse_mknod_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_mknod_in* mi = reinterpret_cast<const fuse_mknod_in*>(arg);
            std::string nm; att a;
            if (!names(arg + sizeof *mi, end, nm)) { reply(fd, unq, EINVAL); break; }
            //FIFOs, sockets and devices are kept as empty files the list marks (the kernel has
            // checked a device may be made: CAP_MKNOD); the nodev mount keeps devices from opening.
            const std::uint32_t ty = mi->mode & S_IFMT;
            const std::uint8_t sp = ty == S_IFIFO ? 1 : ty == S_IFSOCK ? 2 : ty == S_IFCHR ? 3 : ty == S_IFBLK ? 4 : 0;
            if (!sp && ty != S_IFREG && ty != 0) { reply(fd, unq, EINVAL); break; }
            const int e = f.mknod(id, nm, mi->mode & ~mi->umask, a, sp, sp >= 3 ? mi->rdev : 0);
            if (e) reply(fd, unq, e); else entry(fd, unq, a, w);
            break; }
        case FUSE_WRITE: {
            if (!w) { reply(fd, unq, EROFS); break; }
            if (!has(sizeof(fuse_write_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_write_in* wi = reinterpret_cast<const fuse_write_in*>(arg);
            if (aln < sizeof *wi + wi->size) { reply(fd, unq, EINVAL); break; }
            const int e = f.write(wi->fh, wi->offset, reinterpret_cast<const std::uint8_t*>(arg + sizeof *wi), wi->size);
            if (e) { reply(fd, unq, e); break; }
            gst.wrn += wi->size;
            fuse_write_out o{}; o.size = wi->size; reply(fd, unq, 0, &o, sizeof o); break; }
        case FUSE_SETATTR: {
            if (!has(sizeof(fuse_setattr_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_setattr_in* si = reinterpret_cast<const fuse_setattr_in*>(arg);
            sat s;
            if (si->valid & FATTR_MODE) { s.hmod = true; s.mod = si->mode & 07777; }
            if (si->valid & FATTR_SIZE) { s.hsiz = true; s.siz = si->size; }
            if (si->valid & FATTR_UID) { s.huid = true; s.uid = si->uid; }
            if (si->valid & FATTR_GID) { s.hgid = true; s.gid = si->gid; }
            if (si->valid & FATTR_ATIME_NOW) {
                timespec t; clock_gettime(CLOCK_REALTIME, &t); s.hatm = true; s.atm = std::int64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
            } else if (si->valid & FATTR_ATIME) { s.hatm = true; s.atm = std::int64_t(si->atime) * 1000000000 + si->atimensec; }
            if (si->valid & FATTR_MTIME_NOW) {
                timespec t; clock_gettime(CLOCK_REALTIME, &t); s.hmtm = true; s.mtm = std::int64_t(t.tv_sec) * 1000000000 + t.tv_nsec;
            } else if (si->valid & FATTR_MTIME) { s.hmtm = true; s.mtm = std::int64_t(si->mtime) * 1000000000 + si->mtimensec; }
            att a;
            int e = 0;
            if (s.hmod || s.hsiz || s.hmtm || s.huid || s.hgid || s.hatm) {
                if (!w) e = EROFS; else e = f.setattr(id, s, a);
            } else e = f.getattr(id, a);
            if (e) { reply(fd, unq, e); break; }
            fuse_attr_out o{}; o.attr_valid = ttl(w); fill(a, w, o.attr); reply(fd, unq, 0, &o, sizeof o); break; }
        case FUSE_MKDIR: {
            if (!w) { reply(fd, unq, EROFS); break; }
            if (!has(sizeof(fuse_mkdir_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_mkdir_in* mi = reinterpret_cast<const fuse_mkdir_in*>(arg);
            std::string nm; att a;
            if (!names(arg + sizeof *mi, end, nm)) { reply(fd, unq, EINVAL); break; }
            const int e = f.mkdir(id, nm, mi->mode & ~mi->umask, a);
            if (e) reply(fd, unq, e); else entry(fd, unq, a, w);
            break; }
        case FUSE_UNLINK: case FUSE_RMDIR: {
            if (!w) { reply(fd, unq, EROFS); break; }
            std::string nm;
            if (!names(arg, end, nm)) { reply(fd, unq, EINVAL); break; }
            reply(fd, unq, in->opcode == FUSE_UNLINK ? f.unlink(id, nm) : f.rmdir(id, nm)); break; }
        case FUSE_RENAME: case FUSE_RENAME2: {
            if (!w) { reply(fd, unq, EROFS); break; }
            std::uint64_t nd = 0; unsigned fl = 0; size_t hl = 0;
            if (in->opcode == FUSE_RENAME) { if (!has(sizeof(fuse_rename_in))) { reply(fd, unq, EINVAL); break; } nd = reinterpret_cast<const fuse_rename_in*>(arg)->newdir; hl = sizeof(fuse_rename_in); }
            else { if (!has(sizeof(fuse_rename2_in))) { reply(fd, unq, EINVAL); break; } const fuse_rename2_in* r = reinterpret_cast<const fuse_rename2_in*>(arg); nd = r->newdir; fl = r->flags; hl = sizeof *r; }
            std::string a, b;
            if (!names(arg + hl, end, a, &b)) { reply(fd, unq, EINVAL); break; }
            // RENAME_EXCHANGE (2): the format could, but nothing asks for it yet; RENAME_WHITEOUT (4): overlay only.
            if (fl & ~1u) { reply(fd, unq, EINVAL); break; }
            reply(fd, unq, f.rename(id, a, nd, b, fl)); break; }
        case FUSE_SYMLINK: {
            if (!w) { reply(fd, unq, EROFS); break; }
            std::string nm, tg; att a;
            if (!names(arg, end, nm, &tg)) { reply(fd, unq, EINVAL); break; }
            const int e = f.symlink(id, nm, tg, a);
            if (e) reply(fd, unq, e); else entry(fd, unq, a, w);
            break; }
        case FUSE_LINK: {                                   //the format keeps hard links
            if (!w) { reply(fd, unq, EROFS); break; }
            if (!has(sizeof(fuse_link_in))) { reply(fd, unq, EINVAL); break; }
            const fuse_link_in* li = reinterpret_cast<const fuse_link_in*>(arg);
            std::string nm; att a;
            if (!names(arg + sizeof *li, end, nm)) { reply(fd, unq, EINVAL); break; }
            const int e = f.link(li->oldnodeid, id, nm, a);
            if (e) reply(fd, unq, e); else entry(fd, unq, a, w);
            break; }
        case FUSE_FALLOCATE:
            reply(fd, unq, w ? EOPNOTSUPP : EROFS); break;
        default:
            reply(fd, unq, ENOSYS); break;
        }
        f.tick();
    }
}

} // namespace mnt
} // namespace stratazip
