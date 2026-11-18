// CPUs available to this process, for sizing the input verification pool: the
// affinity mask, lowered to the CPU bandwidth limit of the process's cgroup.
// FindCpuCgroup, FindCpuCgroupDir, ParseV2Limit and ParseV1Limit take file
// contents; FindCgroupDir and ReadLimit read the files. The lookup takes the
// first mount whose root contains the cgroup, strips that root, and skips
// cgroups outside the namespace's view of the mount.
// The cgroup parsing and the rounding were checked against Go 1.26's runtime
// with a differential test. Known differences:
// - a period of zero or less, which the kernel does not write (its minimum is
//   1 ms): Go divides by it; BDK reports MalformedFile, so no limit applies.
// - a quota that is no limit next to a period that is malformed or does not
//   read: Go returns no limit without reading the period; BDK reports the
//   period's error, which also applies no limit. A v1 value file that does not
//   read is MalformedFile in Go and SyscallFailed in BDK.
// - Go reads proc/self/cgroup before mountinfo, so its errors come first; BDK
//   reads mountinfo first, as it decides which cgroup file to read.
// - a limit above 2^31 CPUs: Go converts it to int32, which is
//   platform-specific; BDK leaves the count unchanged, as such a limit could
//   not lower it anyway.
// - Go's fixed buffers: lines over 64 KiB and paths over PATH_MAX, which the
//   kernel does not write.
// - a mount point with stray backslashes, which Go's parser indexes out of
//   range on; the kernel writes '\' as \134.
// - once the main thread has exited, proc/self/mountinfo no longer opens; BDK
//   then reads the cgroup and mountinfo files of proc/thread-self, the calling
//   thread's (see FindCgroupDir).
// - Go reads the cgroup files once and re-reads the limit and the affinity
//   mask periodically; BDK reads them on every EffectiveCpuCount call.

#include <internal/cpu_limit.hpp>

#include <internal/file_io.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <unistd.h>

#if defined(__linux__) && !defined(__EMSCRIPTEN__)
#include <sched.h>
#endif

#include <utilstrencodings.h>

namespace bsv::internal
{

    // The affinity mask is Linux's; elsewhere it is not read. The cgroup files
    // are read on every platform; off Linux they are not there, and no limit
    // applies.
#if defined(__linux__) && !defined(__EMSCRIPTEN__)

    // The main thread's mask, whichever thread calls. Once the main thread has
    // exited, its mask no longer changes: cpuset updates skip exiting tasks
    // (cpuset_update_tasks_cpumask). MAX_AFFINITY_CPUS is above nr_cpu_ids,
    // which CONFIG_NR_CPUS caps at 8192 on x86-64 and 4096 on arm64. Mirrors
    // Go's getCPUCount.
    static std::optional<size_t> AffinityCpuCount()
    {
        constexpr size_t MAX_AFFINITY_CPUS = 65'536;
        std::array<cpu_set_t, MAX_AFFINITY_CPUS / CPU_SETSIZE> mask{};
        static_assert(sizeof(mask) * CHAR_BIT == MAX_AFFINITY_CPUS);
        if(sched_getaffinity(getpid(), sizeof(mask), mask.data()) != 0)
            return std::nullopt;

        int count = 0;
        for(const cpu_set_t& set : mask)
            count += CPU_COUNT(&set);

        return count > 0 ? std::optional<size_t>(static_cast<size_t>(count))
                         : std::nullopt;
    }

#else
    static std::optional<size_t> AffinityCpuCount() { return std::nullopt; }
#endif

    namespace
    {

        struct Line
        {
            std::string_view text; // without its '\n'
            bool complete;         // false for a last line with no '\n'
        };

    }

    static std::vector<Line> Lines(std::string_view content)
    {
        std::vector<Line> lines;
        while(!content.empty())
        {
            const size_t newline = content.find('\n');
            if(newline == std::string_view::npos)
            {
                lines.push_back(Line{.text = content, .complete = false});
                break;
            }
            lines.push_back(Line{.text = content.substr(0, newline), .complete = true});
            content.remove_prefix(newline + 1);
        }
        return lines;
    }

    static bool ContainsCpu(const std::string_view commaSeparated)
    {
        static constexpr std::string_view CPU{"cpu"};
        return std::ranges::any_of(std::views::split(commaSeparated, ','),
                                   [](auto item)
                                   { return std::ranges::equal(item, CPU); });
    }

    // `root` starts with '/'.
    static bool HasPathPrefix(const std::string_view path, const std::string_view root)
    {
        if(root.size() == 1)
            return true;

        return path.starts_with(root)
            && (path.size() == root.size() || path[root.size()] == '/');
    }

    // mountinfo escapes space, tab, newline and backslash as \ooo.
    static tl::expected<std::string, CgroupError> UnescapeMountPath(
        const std::string_view text)
    {
        constexpr int MAX_ESCAPED_BYTE = 0xFF;
        std::string out;
        for(size_t i = 0; i < text.size(); ++i)
        {
            if(text[i] != '\\')
            {
                out.push_back(text[i]);
                continue;
            }
            if(i + 3 >= text.size())
                return tl::unexpected{CgroupError::InvalidEscape};

            int value = 0;
            for(size_t k = 1; k <= 3; ++k)
            {
                const char c = text[i + k];
                if(c < '0' || c > '7')
                    return tl::unexpected{CgroupError::InvalidEscape};

                value = (value * 8) + (c - '0');
            }
            if(value > MAX_ESCAPED_BYTE)
                return tl::unexpected{CgroupError::InvalidEscape};

            out.push_back(static_cast<char>(value));
            i += 3;
        }
        return out;
    }

    // Lines are "hierarchy-ID:controller-list:cgroup-path".
    tl::expected<CpuCgroup, CgroupError> FindCpuCgroup(const std::string_view cgroupFile)
    {
        std::optional<CpuCgroup> v2;
        for(const auto& [line, complete] : Lines(cgroupFile))
        {
            if(!complete)
                return tl::unexpected{CgroupError::IncompleteLine};

            const size_t first = line.find(':');
            const size_t second = first == std::string_view::npos
                                    ? first
                                    : line.find(':', first + 1);
            if(second == std::string_view::npos)
                return tl::unexpected{CgroupError::MalformedFile};

            const std::string_view hierarchy = line.substr(0, first);
            const std::string_view controllers = line.substr(first + 1,
                                                             second - first - 1);
            const std::string_view path = line.substr(second + 1);
            if(path.empty() || path[0] != '/')
                return tl::unexpected{CgroupError::MalformedFile};

            if(hierarchy == "0")
                v2 = CpuCgroup{.version = CgroupVersion::V2, .path = std::string(path)};
            else if(ContainsCpu(controllers))
                return CpuCgroup{.version = CgroupVersion::V1, .path = std::string(path)};
        }
        if(!v2)
            return tl::unexpected{CgroupError::NoCgroup};

        return *v2;
    }

    // A line is
    //   ID parent-ID major:minor root mount-point options [optional...] - type source
    //   super-options
    // Every line up to the match needs a root starting with '/', a " - "
    // separator and a type followed by a space; a cgroup mount also needs its
    // source. Roots are unescaped on mounts of the wanted type, and the mount
    // point on the match only.
    tl::expected<std::string, CgroupError> FindCpuCgroupDir(
        const std::string_view mountinfo,
        const CpuCgroup& cgroup)
    {
        for(const auto& entry : Lines(mountinfo))
        {
            std::string_view line = entry.text;
            // The field before the next space, which the line then starts
            // after.
            const auto next = [&line]() -> std::optional<std::string_view>
            {
                const size_t space = line.find(' ');
                if(space == std::string_view::npos)
                    return std::nullopt;

                const std::string_view field = line.substr(0, space);
                line.remove_prefix(space + 1);
                return field;
            };
            if(!next() || !next() || !next()) // ID, parent ID, major:minor
                return tl::unexpected{CgroupError::MalformedFile};

            const auto root = next();
            if(!root || root->empty() || (*root)[0] != '/')
                return tl::unexpected{CgroupError::MalformedFile};

            const auto mountPoint = next();
            if(!mountPoint)
                return tl::unexpected{CgroupError::MalformedFile};

            for(;;)
            { // options and optional fields, up to " - "
                const size_t space = line.find(' ');
                if(space == std::string_view::npos || space + 3 >= line.size())
                    return tl::unexpected{CgroupError::MalformedFile};

                if(line.substr(space, 3) == " - ")
                {
                    line.remove_prefix(space + 3);
                    break;
                }
                line.remove_prefix(space + 1);
            }
            const auto fsType = next();
            if(!fsType)
                return tl::unexpected{CgroupError::MalformedFile};

            if(cgroup.version == CgroupVersion::V1)
            {
                if(*fsType != "cgroup")
                    continue;
                if(!next()) // source
                    return tl::unexpected{CgroupError::MalformedFile};

                if(!ContainsCpu(line)) // super options, the rest of the line
                    continue;
            }
            else if(*fsType != "cgroup2")
            {
                continue;
            }

            const auto rootPath = UnescapeMountPath(*root);
            if(!rootPath)
                return tl::unexpected{rootPath.error()};

            if(!HasPathPrefix(cgroup.path, *rootPath))
                continue;
            std::string_view rel = std::string_view(cgroup.path).substr(rootPath->size());
            if(rootPath->size() == 1 && cgroup.path.size() > 1)
                rel = cgroup.path;
            if(HasPathPrefix(rel, "/.."))
                continue; // outside this cgroup namespace's view of the mount

            // Concatenated, not joined with operator/: the matching above is
            // byte-wise and lexical, and so is the result.
            return UnescapeMountPath(*mountPoint)
                .transform([rel](const std::string& mountPath)
                           { return mountPath + std::string(rel); });
        }
        return tl::unexpected{CgroupError::NoCgroup};
    }

    namespace
    {

        // A cgroup's CPU bandwidth: `quota` microseconds of CPU time in every
        // `period`. A quota of +Inf is no limit.
        struct Bandwidth
        {
            double quota;
            int64_t period;
        };

    }

    static tl::expected<std::string_view, CgroupError> SingleLine(
        const std::string_view content)
    {
        const size_t newline = content.find('\n');
        if(newline == std::string_view::npos)
            return tl::unexpected{CgroupError::MalformedFile};

        return content.substr(0, newline);
    }

    static tl::expected<int64_t, CgroupError> ParseInteger(const std::string_view text)
    {
        int64_t value{};
        if(!ParseInt64(std::string(text), &value))
            return tl::unexpected{CgroupError::MalformedFile};

        return value;
    }

    static double ToDouble(const int64_t value) { return static_cast<double>(value); }

    static tl::expected<Bandwidth, CgroupError> ToBandwidth(
        const tl::expected<double, CgroupError>& quota,
        const tl::expected<int64_t, CgroupError>& period)
    {
        if(!quota)
            return tl::unexpected{quota.error()};

        if(!period)
            return tl::unexpected{period.error()};

        return Bandwidth{.quota = *quota, .period = *period};
    }

    // The kernel's minimum period is 1 ms.
    static tl::expected<Bandwidth, CgroupError> CheckPeriod(const Bandwidth& bandwidth)
    {
        if(bandwidth.period <= 0)
            return tl::unexpected{CgroupError::MalformedFile};

        return bandwidth;
    }

    static double Cpus(const Bandwidth& bandwidth)
    {
        return bandwidth.quota / static_cast<double>(bandwidth.period);
    }

    static tl::expected<double, CgroupError> ParseV2Quota(const std::string_view field)
    {
        if(field == "max")
            return std::numeric_limits<double>::infinity();

        return ParseInteger(field).transform(ToDouble);
    }

    static tl::expected<Bandwidth, CgroupError> ParseCpuMaxLine(
        const std::string_view line)
    {
        const size_t space = line.find(' ');
        if(space == std::string_view::npos)
            return tl::unexpected{CgroupError::MalformedFile};

        return ToBandwidth(ParseV2Quota(line.substr(0, space)),
                           ParseInteger(line.substr(space + 1)));
    }

    tl::expected<double, CgroupError> ParseV2Limit(const std::string_view cpuMax)
    {
        return SingleLine(cpuMax)
            .and_then(ParseCpuMaxLine)
            .and_then(CheckPeriod)
            .transform(Cpus);
    }

    // The kernel writes -1 to cpu.cfs_quota_us for no limit.
    static double NoLimitIfNegative(const int64_t quota)
    {
        return quota < 0 ? std::numeric_limits<double>::infinity() : ToDouble(quota);
    }

    static tl::expected<double, CgroupError> ParseV1Quota(const std::string_view content)
    {
        return SingleLine(content).and_then(ParseInteger).transform(NoLimitIfNegative);
    }

    static tl::expected<int64_t, CgroupError> ParseV1Period(
        const std::string_view content)
    {
        return SingleLine(content).and_then(ParseInteger);
    }

    // NOLINTBEGIN(bugprone-easily-swappable-parameters): the two files, by name
    tl::expected<double, CgroupError> ParseV1Limit(const std::string_view quota,
                                                   const std::string_view period)
    // NOLINTEND(bugprone-easily-swappable-parameters)
    {
        return ToBandwidth(ParseV1Quota(quota), ParseV1Period(period))
            .and_then(CheckPeriod)
            .transform(Cpus);
    }

    // Only open()'s errno tells a missing proc file from one that does not
    // open, which is why these are read with ReadFile, not a stream.
    static CgroupError ToCgroupError(const std::errc error)
    {
        return error == std::errc::no_such_file_or_directory ? CgroupError::NoCgroup
                                                             : CgroupError::SyscallFailed;
    }

    static tl::expected<std::string, CgroupError> ReadLimitFile(
        const std::filesystem::path& path)
    {
        return ReadSmallFile(path, VALUE_FILE_SIZE_LIMIT)
            .transform_error(
                [](const std::errc error)
                {
                    return error == std::errc::file_too_large
                             ? CgroupError::MalformedFile
                             : CgroupError::SyscallFailed;
                });
    }

    static tl::expected<CgroupDir, CgroupError> FindCgroupDirWith(
        const std::filesystem::path& root,
        const std::filesystem::path& proc,
        const std::string_view mountinfo)
    {
        const auto cgroup = ReadFile(proc / "cgroup")
                                .transform_error(ToCgroupError)
                                .and_then(FindCpuCgroup);

        // The directory is absolute; operator/ would let it replace `root`.
        return cgroup
            .and_then([mountinfo](const CpuCgroup& found)
                      { return FindCpuCgroupDir(mountinfo, found); })
            .transform(
                [&root, &cgroup](const std::string& dir)
                {
                    return CgroupDir{.version = cgroup->version,
                                     .path = root
                                           / std::filesystem::path(dir).relative_path()};
                });
    }

    // Once the main thread has exited, proc/self is that exited thread's, and
    // its mountinfo no longer opens (EINVAL, as exit_task_namespaces has
    // cleared its nsproxy, which mounts_open_common requires). On a cgroup v1
    // hierarchy its cgroup then reads as "/" (proc_cgroup_show prints that for
    // an exiting task), so the cgroup file must come from the same directory as
    // mountinfo. thread-self's files are the process's unless the calling
    // thread has its own mount namespace or was moved to another cgroup on its
    // own. Kernels before 3.17 have no thread-self.
    tl::expected<CgroupDir, CgroupError> FindCgroupDir(const std::filesystem::path& root)
    {
        using Found = tl::expected<CgroupDir, CgroupError>;

        // Found with `proc`'s files, nested in the result of reading `proc`'s
        // mountinfo: only that read's failure falls back to thread-self.
        const auto findWith = [&root](const std::filesystem::path& proc)
        {
            return ReadFile(proc / "mountinfo")
                .transform([&root, &proc](const std::string& mountinfo)
                           { return FindCgroupDirWith(root, proc, mountinfo); });
        };

        return findWith(root / "proc/self")
            .or_else(
                [&findWith, &root](const std::errc selfError)
                {
                    return findWith(root / "proc/thread-self")
                        .or_else([selfError](const std::errc /*threadSelfError*/)
                                     -> tl::expected<Found, std::errc>
                                 { return tl::unexpected{selfError}; });
                })
            .transform_error(ToCgroupError)
            .and_then([](const Found& found) { return found; });
    }

    static tl::expected<Bandwidth, CgroupError> ReadV1Bandwidth(
        const std::filesystem::path& dir)
    {
        return ToBandwidth(ReadLimitFile(dir / "cpu.cfs_quota_us").and_then(ParseV1Quota),
                           ReadLimitFile(dir / "cpu.cfs_period_us")
                               .and_then(ParseV1Period));
    }

    tl::expected<double, CgroupError> ReadLimit(const CgroupDir& dir)
    {
        if(dir.version == CgroupVersion::V2)
            return ReadLimitFile(dir.path / "cpu.max").and_then(ParseV2Limit);

        return ReadV1Bandwidth(dir.path).and_then(CheckPeriod).transform(Cpus);
    }

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters): a count and a limit, by name
    size_t LimitCpuCount(const size_t cpus, const double cgroupLimit)
    {
        // Past here `rounded` is below `cpus`, so the conversion is in range.
        const double rounded = std::ceil(cgroupLimit);
        if(std::isnan(rounded) || rounded >= static_cast<double>(cpus))
            return cpus;

        const size_t count = rounded > 0 ? static_cast<size_t>(rounded) : 0;
        return std::min(std::max(count, MIN_LIMITED_CPUS), cpus);
    }

    size_t AvailableCpuCount(const std::optional<size_t> affinityCpus,
                             const size_t hardwareConcurrency)
    {
        return affinityCpus.value_or(std::max<size_t>(hardwareConcurrency, 1));
    }

    size_t EffectiveCpuCount(const std::filesystem::path& cgroupRoot)
    {
        return LimitCpuCount(AvailableCpuCount(AffinityCpuCount(),
                                               std::thread::hardware_concurrency()),
                             FindCgroupDir(cgroupRoot)
                                 .and_then(ReadLimit)
                                 .value_or(std::numeric_limits<double>::infinity()));
    }

}
