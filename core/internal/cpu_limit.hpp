#pragma once

// Internal to bdk_core and its tests. Not installed with the core headers
// (core/bdk-core-recipe.cmake leaves core/internal/ out of the install list)
// and not part of any language binding.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include <expected.h>

namespace bsv::internal
{

    enum class CgroupVersion : uint8_t
    {
        V1,
        V2
    };

    // The cgroup whose CPU limit applies to this process.
    struct CpuCgroup
    {
        CgroupVersion version;
        std::string path; // relative to its hierarchy's root, starts with '/'

        bool operator==(const CpuCgroup&) const = default;
    };

    // Why a cgroup file was rejected or could not be read.
    // In Go, each is err followed by its name (ErrNoCgroup for NoCgroup).
    enum class CgroupError : uint8_t
    {
        NoCgroup,       // no cpu cgroup listed, or no mount holding it; also a
                        // proc file that doesn't exist
        MalformedFile,  // a file doesn't parse, or holds a period of zero or less;
                        // also a value file of 64 bytes or more
        InvalidEscape,  // a bad \ooo escape in a mountinfo path
        IncompleteLine, // a proc/self/cgroup line without its '\n', with no cgroup v1
                        // cpu line before it
        SyscallFailed,  // a proc file that exists but doesn't open or read, or a
                        // value file that doesn't open or read
    };

    // From the contents of proc/self/cgroup: the v1 hierarchy with the cpu
    // controller, else the v2 hierarchy (ID 0). NoCgroup when there is neither;
    // IncompleteLine for a line without its '\n', and MalformedFile for any other
    // malformed line, up to the v1 match. Mirrors Go's parseCPUCgroup.
    tl::expected<CpuCgroup, CgroupError> FindCpuCgroup(std::string_view cgroupFile);

    // From the contents of proc/self/mountinfo: the directory holding `cgroup`'s
    // files, under the first cgroup2 mount, or cgroup mount with the cpu super
    // option, whose root contains the cgroup. NoCgroup when there is none;
    // InvalidEscape for a bad \ooo escape in a root that is unescaped or in the
    // selected mount point, and MalformedFile for a malformed line, up to the
    // match. Mirrors Go's parseCPUMount.
    tl::expected<std::string, CgroupError> FindCpuCgroupDir(std::string_view mountinfo,
                                                            const CpuCgroup& cgroup);

    // From the contents of cgroup v2 cpu.max, "<quota> <period>\n": quota / period
    // in CPUs, where quota "max" is no limit and gives +Inf. MalformedFile for
    // anything else, or a period of zero or less. Mirrors Go's parseV2Limit.
    tl::expected<double, CgroupError> ParseV2Limit(std::string_view cpuMax);

    // From the contents of cgroup v1 cpu.cfs_quota_us and cpu.cfs_period_us, each
    // "<value>\n": quota / period in CPUs, where a negative quota is no limit and
    // gives +Inf. MalformedFile for anything else, or a period of zero or less;
    // the quota's error first. Mirrors Go's parseV1Number and ReadCPULimit.
    tl::expected<double, CgroupError> ParseV1Limit(std::string_view quota,
                                                   std::string_view period);

    // Cgroup value files (cpu.max, cpu.cfs_quota_us, cpu.cfs_period_us) hold one
    // or two integers and a newline. A file of this many bytes or more is not a
    // value file: ReadLimit reads no further and reports MalformedFile.
    constexpr size_t VALUE_FILE_SIZE_LIMIT = 64;

    // The directory holding a cgroup's CPU limit files, and the cgroup's
    // version, which says which files those are.
    struct CgroupDir
    {
        CgroupVersion version;
        std::filesystem::path path;

        bool operator==(const CgroupDir&) const = default;
    };

    // The directory under `root` ("/" on a live system) holding the CPU limit
    // files of the cgroup this process is in, located through the cgroup and
    // mountinfo files of proc/self, or of proc/thread-self when
    // proc/self/mountinfo does not read (once the main thread has exited); both
    // from the same directory. mountinfo is read first; when neither reads, the
    // error is proc/self's. NoCgroup for a proc file that does not exist,
    // SyscallFailed for one that does not open or read; otherwise the parsers'
    // errors. Mirrors Go's FindCPUCgroup and FindCPUMountPoint.
    tl::expected<CgroupDir, CgroupError> FindCgroupDir(const std::filesystem::path& root);

    // The CPU bandwidth limit (quota / period, in CPUs) in `dir`: cgroup v2
    // cpu.max, or cgroup v1 cpu.cfs_quota_us / cpu.cfs_period_us, the quota's
    // error first. +Inf when there is no limit; a zero or negative quota is a
    // limit. MalformedFile for a file of VALUE_FILE_SIZE_LIMIT bytes or more,
    // SyscallFailed for one that does not open or read; otherwise the parsers'
    // errors. Mirrors Go's OpenCPU and ReadCPULimit.
    tl::expected<double, CgroupError> ReadLimit(const CgroupDir& dir);

    // The CPU bandwidth limit of the cgroup this process is in: ReadLimit of
    // FindCgroupDir(root), with the first error of either.
    tl::expected<double, CgroupError> CgroupCpuLimit(const std::filesystem::path& root);

    // The fewest CPUs a cgroup limit lowers the count to. One would leave the
    // pool no parallelism, and a quota under one CPU usually marks a bursty
    // workload, which can use more for short spells.
    constexpr size_t MIN_LIMITED_CPUS = 2;

    // Lowers a CPU count to a cgroup limit: the limit is rounded up to a whole
    // CPU and to at least MIN_LIMITED_CPUS, and only ever lowers `cpus`. -Inf
    // gives MIN_LIMITED_CPUS; +Inf (no limit) and NaN leave `cpus` unchanged.
    // Mirrors Go's adjustCgroupGOMAXPROCS.
    size_t LimitCpuCount(size_t cpus, double cgroupLimit);

    // The CPU count EffectiveCpuCount returns, from what it read: the CPUs in the
    // affinity mask (nullopt where there is none or it cannot be read), else
    // `hardwareConcurrency`, lowered by LimitCpuCount to `cgroupLimit`; at least 1.
    size_t CpuCountFrom(std::optional<size_t> affinityCpus,
                        size_t hardwareConcurrency,
                        double cgroupLimit);

    // CPUs this process may use: on Linux the CPUs in the process's
    // sched_getaffinity mask (the main thread's, whichever thread calls; once the
    // main thread has exited, its mask as it was then), else
    // hardware_concurrency(); lowered by LimitCpuCount to the cgroup limit read
    // under `cgroupRoot` ("/" on a live system; tests pass a temporary root):
    // the main thread's cgroup. Any CgroupCpuLimit error applies no limit. Once
    // the main thread has exited, the cgroup is the calling thread's while the
    // mask stays the main thread's, so a thread moved to a cpu cgroup of its own
    // then gets a count of its own. At least 1. Reads the system on every call,
    // so callers that need it often should keep the result. Reading the mask
    // allocates nothing; reading the cgroup files throws std::bad_alloc when out
    // of memory. Throws nothing else.
    size_t EffectiveCpuCount(const std::filesystem::path& cgroupRoot = "/");

}
