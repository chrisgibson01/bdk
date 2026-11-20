#pragma once

// Internal to bdk_core and its tests. Not installed with the core headers
// (core/bdk-core-recipe.cmake leaves core/internal/ out of the install list)
// and not part of any language binding.

#include <cstddef>
#include <cstdint>
#include <expected.h>
#include <filesystem>
#include <iosfwd>
#include <string>
#include <string_view>
#include <variant>

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
                        // file that doesn't exist
        MalformedFile,  // a file doesn't parse, or holds a negative quota or a
                        // period of zero or less; also a value file of 64 bytes
                        // or more
        InvalidEscape,  // a bad \ooo escape in a mountinfo path
        IncompleteLine, // a proc/self/cgroup line without its '\n', with no cgroup v1
                        // cpu line before it
        SyscallFailed,  // a file that exists but doesn't open or read
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

    // A CPU quota with no limit: cgroup v2's "max", v1's -1.
    struct Unlimited
    {
        bool operator==(const Unlimited&) const = default;
    };

    // Microseconds of CPU time, or Unlimited.
    using CpuQuota = std::variant<int64_t, Unlimited>;

    // Up to Quota() of CPU time in every Period() microseconds, as a cgroup's
    // files hold them. The quota is not negative and the period is above zero.
    class CpuBandwidth
    {
    public:
        // MalformedFile for a negative quota, which the kernel does not write,
        // or a period of zero or less; the kernel's minimum is 1 ms.
        static tl::expected<CpuBandwidth, CgroupError> Make(CpuQuota quota,
                                                            int64_t period);

        [[nodiscard]] const CpuQuota& Quota() const { return quota_; }

        [[nodiscard]] int64_t Period() const { return period_; }

        [[nodiscard]] bool IsUnlimited() const
        {
            return std::holds_alternative<Unlimited>(quota_);
        }

        // The fewest CPUs that can use all of the bandwidth: quota / period
        // rounded up, exactly. Requires !IsUnlimited().
        [[nodiscard]] uint64_t CpusNeeded() const;

        bool operator==(const CpuBandwidth&) const = default;

    private:
        CpuBandwidth(CpuQuota quota, int64_t period);

        CpuQuota quota_;
        int64_t period_;
    };

    // From the contents of cgroup v2 cpu.max, "<quota> <period>\n", where quota
    // "max" is Unlimited. MalformedFile for anything else, a negative quota, or
    // a period of zero or less. Mirrors Go's parseV2Limit up to its division.
    tl::expected<CpuBandwidth, CgroupError> ParseCpuMax(std::string_view cpuMax);

    // From the contents of cgroup v1 cpu.cfs_quota_us and cpu.cfs_period_us, each
    // "<value>\n", where a negative quota is Unlimited. MalformedFile for
    // anything else, or a period of zero or less; the quota's error first.
    // Mirrors Go's parseV1Number and ReadCPULimit up to its division.
    tl::expected<CpuBandwidth, CgroupError> ParseCfsBandwidth(std::string_view quota,
                                                              std::string_view period);

    // Cgroup value files (cpu.max, cpu.cfs_quota_us, cpu.cfs_period_us) hold one
    // or two integers and a newline. A file of this many bytes or more is not a
    // value file: ReadCpuLimit reads no further and reports MalformedFile.
    constexpr size_t VALUE_FILE_SIZE_LIMIT = 64;

    // `version` says which limit files `path` holds.
    struct CgroupDir
    {
        CgroupVersion version;
        std::filesystem::path path;

        bool operator==(const CgroupDir&) const = default;
    };

    // The directory under `root` ("/" on a live system) holding the CPU limit
    // files of the cgroup this process is in, located through the cgroup and
    // mountinfo files of proc/self, or of proc/thread-self when either of
    // proc/self's does not read (its mountinfo does not once the main thread
    // has exited); both from the same directory. The cgroup file is read first;
    // when neither directory's files read, the error is proc/self's. NoCgroup
    // for a proc file that does not exist, SyscallFailed for one that does not
    // open or read; otherwise the parsers' errors. Mirrors Go's FindCPUCgroup
    // and FindCPUMountPoint.
    tl::expected<CgroupDir, CgroupError> FindCgroupDir(const std::filesystem::path& root);

    // The CPU bandwidth in `dir`: cgroup v2 cpu.max, or cgroup v1
    // cpu.cfs_quota_us and cpu.cfs_period_us, with read errors before parse
    // errors and the quota's first in each. NoCgroup for a file that does not
    // exist, MalformedFile for one of VALUE_FILE_SIZE_LIMIT bytes or more,
    // SyscallFailed for one that does not open or read; otherwise the parsers'
    // errors. Mirrors Go's OpenCPU and ReadCPULimit up to its division.
    tl::expected<CpuBandwidth, CgroupError> ReadCpuLimit(const CgroupDir&);

    // A CgroupError prints as its enumerator's name; a CpuCgroup or CgroupDir
    // as "v1 " or "v2 " and its path; a CpuBandwidth as "<quota> <period>",
    // with "max" for Unlimited.
    std::ostream& operator<<(std::ostream&, CgroupError);
    std::ostream& operator<<(std::ostream&, const CpuCgroup&);
    std::ostream& operator<<(std::ostream&, const CgroupDir&);
    std::ostream& operator<<(std::ostream&, const CpuBandwidth&);
}
