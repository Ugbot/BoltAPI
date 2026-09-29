#pragma once
// Readiness wait shared by the wire-protocol servers (Bolt, Postgres, Flight
// SQL). poll(), not select(): a process holding many files (a large MarbleDB
// opens one per SST) hands out socket fds past FD_SETSIZE, where select()
// cannot be used at all and a listener would never accept again.

#include <cassert>

#if defined(_WIN32)
#include "boltapi/net/sys_compat.h"   // winsock, set up once
#else
#include <poll.h>
#endif

namespace bolt::api::proto::detail {

// 1 ready (readable, hung up or errored: the caller's read reports which),
// 0 timeout, -1 error.
inline int wait_readable(int fd, int timeout_ms) noexcept {
    assert(fd >= 0);
    assert(timeout_ms >= 0);
#if defined(_WIN32)
    WSAPOLLFD p{};
    p.fd = static_cast<SOCKET>(fd);
    p.events = POLLRDNORM;
    const int r = ::WSAPoll(&p, 1, timeout_ms);
#else
    pollfd p{};
    p.fd = fd;
    p.events = POLLIN;
    const int r = ::poll(&p, 1, timeout_ms);
#endif
    if (r < 0) return -1;
    return r > 0 ? 1 : 0;
}

}  // namespace bolt::api::proto::detail
