// bounded_proc.h — a HARD-BOUNDED, process-tree-killing subprocess runner for
// the WebRTC interop gtests (WM6). Header-only, no Bolt deps, no exceptions.
//
// ============================================================================
// WHY THIS EXISTS
// ============================================================================
// The interop legs shell out to `uv run --with aiortc python ...`, which spawns
// a TREE of children (uv -> python -> its own workers). A bare std::system()
// can hang FOREVER and, worse, leak that whole tree of orphaned uv/python
// processes if the test is killed. That has already cost a hung CI run. Every
// external-client leg MUST therefore be:
//   * pre-probed FAST (skip cleanly if `uv` is absent) — see uv_present(),
//   * run under a HARD WALL-CLOCK CAP, and
//   * on timeout, KILL THE WHOLE PROCESS TREE, never block, never leak.
//
// PLATFORM STRATEGY
//   Windows: CreateProcess into a Job Object with
//     JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE — closing the job handle (or
//     TerminateJobObject on timeout) kills the entire descendant tree. We
//     WaitForSingleObject on the process with a timeout; on timeout we
//     TerminateJobObject. The job is the bound: even uv's grandchildren die.
//   POSIX: fork + setpgid(0,0) so the child is its own process-group leader;
//     a timed waitpid loop; on timeout killpg(pgid, SIGKILL) reaps the group.
//
// RESULT MODEL
//   RunResult { kind, exit_code }:
//     kLaunchFailed — could not spawn (treat as skip-if it's a missing tool).
//     kExited       — finished within the cap; exit_code is its status.
//     kTimedOut     — exceeded the cap; the tree was killed. NEVER a hang.
//
// TigerStyle: bounded (an explicit ms cap; a bounded poll loop), >=2 asserts per
// function, noexcept-dense, no throw/try/catch, no heap on the wait path.

#pragma once

#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <string>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#else
#  include <csignal>
#  include <ctime>
#  include <sys/types.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace bolt::api::interop {

// The outcome of a bounded run. `kind` is the primary signal; `exit_code` is
// only meaningful when kind == kExited.
struct RunResult {
    enum class Kind { kLaunchFailed, kExited, kTimedOut };
    Kind kind = Kind::kLaunchFailed;
    int  exit_code = -1;

    bool exited_ok() const noexcept {
        assert(static_cast<int>(kind) >= 0 && "RunResult: kind range");
        assert(static_cast<int>(kind) <= 2 && "RunResult: kind range hi");
        return kind == Kind::kExited && exit_code == 0;
    }
};

// Is a tool callable at all? Probes "<tool> --version" with stdio silenced.
// Fast (a tiny child), bounded by the OS process spawn. Returns true iff the
// probe ran AND exited 0. Used to GTEST_SKIP cleanly when uv is absent.
inline bool tool_present(const char* tool) noexcept {
    assert(tool != nullptr && "tool_present: null tool");
    assert(tool[0] != '\0' && "tool_present: empty tool");
    std::string cmd(tool);
    cmd += " --version >";
#if defined(_WIN32)
    cmd += "NUL 2>&1";
#else
    cmd += "/dev/null 2>&1";
#endif
    const int rc = std::system(cmd.c_str());
    return rc == 0;
}

inline bool uv_present() noexcept { return tool_present("uv"); }

#if defined(_WIN32)

// Windows: run `command_line` under a Job Object so the WHOLE descendant tree is
// bound. On timeout we TerminateJobObject — uv, python and any grandchildren all
// die. Closing the job handle (KILL_ON_JOB_CLOSE) is the belt-and-braces reap.
inline RunResult run_bounded(const std::string& command_line,
                             std::uint32_t timeout_ms) noexcept {
    assert(!command_line.empty() && "run_bounded: empty command");
    assert(timeout_ms > 0 && "run_bounded: zero timeout");
    RunResult r{};

    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job == nullptr) { r.kind = RunResult::Kind::kLaunchFailed; return r; }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli{};
    jeli.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jeli,
                            sizeof(jeli));

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    // CREATE_SUSPENDED so we assign the job BEFORE the child can spawn helpers;
    // CREATE_BREAKAWAY would defeat the bound, so we do NOT pass it. Run through
    // `cmd /c` (mirrors the POSIX `/bin/sh -c`) so PATH resolution + any
    // redirection in `command_line` behave like a shell — the child cmd.exe and
    // ALL its descendants (uv -> python -> workers) are still bound to the job.
    std::string mutable_cmd = "cmd /c ";
    mutable_cmd += command_line;  // CreateProcessA needs a writable buffer
    const BOOL ok = CreateProcessA(
        nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (!ok) {
        CloseHandle(job);
        r.kind = RunResult::Kind::kLaunchFailed;
        return r;
    }
    // Bind the child (and its future descendants) to the job, then let it run.
    AssignProcessToJobObject(job, pi.hProcess);
    ResumeThread(pi.hThread);

    const DWORD wait = WaitForSingleObject(pi.hProcess, timeout_ms);
    if (wait == WAIT_OBJECT_0) {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        r.kind = RunResult::Kind::kExited;
        r.exit_code = static_cast<int>(code);
    } else {
        // Timed out (or wait failed): kill the WHOLE tree via the job.
        TerminateJobObject(job, 1u);
        r.kind = RunResult::Kind::kTimedOut;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(job);  // KILL_ON_JOB_CLOSE reaps any stragglers.
    assert(r.kind != RunResult::Kind::kLaunchFailed && "run_bounded: launched");
    return r;
}

#else  // POSIX

// POSIX: fork + setpgid so the child leads its own process group; a timed
// waitpid poll; on timeout killpg(SIGKILL) the whole group. argv is built from
// "/bin/sh -c <command_line>" so we keep one entrypoint with the Windows path.
inline RunResult run_bounded(const std::string& command_line,
                             std::uint32_t timeout_ms) noexcept {
    assert(!command_line.empty() && "run_bounded: empty command");
    assert(timeout_ms > 0 && "run_bounded: zero timeout");
    RunResult r{};

    const pid_t pid = ::fork();
    if (pid < 0) { r.kind = RunResult::Kind::kLaunchFailed; return r; }
    if (pid == 0) {
        // Child: become our own process-group leader so killpg reaps the tree.
        ::setpgid(0, 0);
        ::execl("/bin/sh", "sh", "-c", command_line.c_str(),
                static_cast<char*>(nullptr));
        ::_exit(127);  // exec failed
    }
    // Parent: also set the child's pgid (race-free: whichever wins, same value).
    ::setpgid(pid, pid);

    const std::uint32_t kPollMs = 50;
    std::uint32_t elapsed = 0;
    for (;;) {
        int status = 0;
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) {
            r.kind = RunResult::Kind::kExited;
            r.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
            return r;
        }
        if (w < 0) { r.kind = RunResult::Kind::kLaunchFailed; return r; }
        if (elapsed >= timeout_ms) {
            ::killpg(pid, SIGKILL);   // kill the WHOLE group (uv + python + kids)
            int dump = 0;
            ::waitpid(pid, &dump, 0); // reap the leader so it's not a zombie
            r.kind = RunResult::Kind::kTimedOut;
            return r;
        }
        timespec ts{};
        ts.tv_sec = 0;
        ts.tv_nsec = static_cast<long>(kPollMs) * 1000L * 1000L;
        ::nanosleep(&ts, nullptr);
        elapsed += kPollMs;
    }
}

#endif

}  // namespace bolt::api::interop
