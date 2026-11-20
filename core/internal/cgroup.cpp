// Locates the cgroup whose CPU limit applies to this process and reads that
// limit. ParseCpuCgroup, ParseCpuCgroupDir, ParseCpuMax and ParseCfsBandwidth
// take file contents; FindCgroupDir and ReadCpuBandwidth read the files. The
// lookup takes the first mount whose root contains the cgroup, strips that
// root, and skips cgroups outside the namespace's view of the mount.
// The parsing was checked against Go 1.26's runtime with a differential test.
// Known differences:
// - a period of zero or less, which the kernel does not write (its minimum is
//   1 ms): Go divides by it; BDK reports MalformedFile.
// - a negative cpu.max quota, which the kernel does not write: Go's limit is
//   negative; BDK reports MalformedFile.
// - a quota that is no limit next to a period that is malformed or does not
//   read: Go returns no limit without reading the period; BDK reports the
//   period's error. A v1 value file that does not read is MalformedFile in Go
//   and SyscallFailed in BDK.
// - Go's fixed buffers: lines over 64 KiB and paths over PATH_MAX, which the
//   kernel does not write.
// - a mount point with stray backslashes, which Go's parser indexes out of
//   range on; the kernel writes '\' as \134.
// - once the main thread has exited, proc/self/mountinfo no longer opens; BDK
//   then reads the cgroup and mountinfo files of proc/thread-self, the calling
//   thread's (see FindCgroupDir).

#include <internal/cgroup.hpp>

#include <internal/file_io.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ostream>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

#include <utilstrencodings.h>

using namespace bsv::internal;

namespace
{
    struct Line
    {
        std::string_view text; // without its '\n'
        bool terminated;       // false for a last line with no '\n'
    };
}

std::ostream& bsv::internal::operator<<(std::ostream& os, const CgroupError error)
{
    switch(error)
    {
    case CgroupError::NoCgroup:
        return os << "NoCgroup";
    case CgroupError::MalformedFile:
        return os << "MalformedFile";
    case CgroupError::InvalidEscape:
        return os << "InvalidEscape";
    case CgroupError::IncompleteLine:
        return os << "IncompleteLine";
    case CgroupError::SyscallFailed:
        return os << "SyscallFailed";
    }
    return os << "CgroupError " << static_cast<int>(error);
}

std::ostream& bsv::internal::operator<<(std::ostream& os, const CpuCgroup& cgroup)
{
    return os << (cgroup.version == CgroupVersion::V1 ? "v1 " : "v2 ") << cgroup.path;
}

std::ostream& bsv::internal::operator<<(std::ostream& os, const CgroupDir& dir)
{
    return os << (dir.version == CgroupVersion::V1 ? "v1 " : "v2 ") << dir.path;
}

std::ostream& bsv::internal::operator<<(std::ostream& os, const CpuBandwidth& bandwidth)
{
    if(bandwidth.IsUnlimited())
        os << "max";
    else
        os << std::get<int64_t>(bandwidth.Quota());
    return os << ' ' << bandwidth.Period();
}

static std::vector<Line> Lines(std::string_view content)
{
    std::vector<Line> lines;
    while(!content.empty())
    {
        const size_t newline = content.find('\n');
        if(newline == std::string_view::npos)
        {
            lines.push_back(Line{.text = content, .terminated = false});
            break;
        }
        lines.push_back(Line{.text = content.substr(0, newline), .terminated = true});
        content.remove_prefix(newline + 1);
    }
    return lines;
}

static bool ContainsCpu(const std::string_view commaSeparated)
{
    static constexpr std::string_view CPU{"cpu"};
    return std::ranges::any_of(std::views::split(commaSeparated, ','),
                               [](auto item) { return std::ranges::equal(item, CPU); });
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
tl::expected<CpuCgroup, CgroupError> bsv::internal::ParseCpuCgroup(
    const std::string_view cgroupFile)
{
    std::optional<CpuCgroup> v2;
    for(const auto& [line, terminated] : Lines(cgroupFile))
    {
        if(!terminated)
            return tl::unexpected{CgroupError::IncompleteLine};

        const size_t first = line.find(':');
        const size_t second = first == std::string_view::npos ? first
                                                              : line.find(':', first + 1);
        if(second == std::string_view::npos)
            return tl::unexpected{CgroupError::MalformedFile};

        const std::string_view hierarchy = line.substr(0, first);
        const std::string_view controllers = line.substr(first + 1, second - first - 1);
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
tl::expected<CgroupDir, CgroupError> bsv::internal::ParseCpuCgroupDir(
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
            .transform(
                [&cgroup, rel](const std::string& mountPath)
                {
                    return CgroupDir{.version = cgroup.version,
                                     .path = mountPath + std::string(rel)};
                });
    }
    return tl::unexpected{CgroupError::NoCgroup};
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

bsv::internal::CpuBandwidth::CpuBandwidth(const CpuQuota quota, const int64_t period):
    quota_{quota},
    period_{period}
{
}

tl::expected<CpuBandwidth, CgroupError> bsv::internal::CpuBandwidth::Make(
    const CpuQuota quota,
    const int64_t period)
{
    const bool negative{std::holds_alternative<int64_t>(quota)
                        && std::get<int64_t>(quota) < 0};
    if(negative || period <= 0)
        return tl::unexpected{CgroupError::MalformedFile};

    return CpuBandwidth{quota, period};
}

uint64_t bsv::internal::CpuBandwidth::CpusNeeded() const
{
    const auto quota{std::get<int64_t>(quota_)};
    return static_cast<uint64_t>((quota / period_) + (quota % period_ > 0 ? 1 : 0));
}

static tl::expected<CpuQuota, CgroupError> ParseCpuMaxQuota(const std::string_view field)
{
    if(field == "max")
        return Unlimited{};

    return ParseInteger(field).transform([](const int64_t quota)
                                         { return CpuQuota{quota}; });
}

static tl::expected<CpuBandwidth, CgroupError> ParseCpuMaxLine(
    const std::string_view line)
{
    const size_t space = line.find(' ');
    if(space == std::string_view::npos)
        return tl::unexpected{CgroupError::MalformedFile};

    return ParseCpuMaxQuota(line.substr(0, space))
        .and_then(
            [period = line.substr(space + 1)](const CpuQuota quotaValue)
            {
                return ParseInteger(period).and_then(
                    [quotaValue](const int64_t periodValue)
                    { return CpuBandwidth::Make(quotaValue, periodValue); });
            });
}

tl::expected<CpuBandwidth, CgroupError> bsv::internal::ParseCpuMax(
    const std::string_view cpuMax)
{
    return SingleLine(cpuMax).and_then(ParseCpuMaxLine);
}

// The kernel writes -1 to cpu.cfs_quota_us for no limit.
static CpuQuota UnlimitedIfNegative(const int64_t quota)
{
    if(quota < 0)
        return Unlimited{};

    return quota;
}

static tl::expected<CpuQuota, CgroupError> ParseCfsQuota(const std::string_view content)
{
    return SingleLine(content).and_then(ParseInteger).transform(UnlimitedIfNegative);
}

static tl::expected<int64_t, CgroupError> ParseCfsPeriod(const std::string_view content)
{
    return SingleLine(content).and_then(ParseInteger);
}

// NOLINTBEGIN(bugprone-easily-swappable-parameters): the two files, by name
tl::expected<CpuBandwidth, CgroupError> bsv::internal::ParseCfsBandwidth(
    const std::string_view quota,
    const std::string_view period)
// NOLINTEND(bugprone-easily-swappable-parameters)
{
    return ParseCfsQuota(quota).and_then(
        [period](const CpuQuota quotaValue)
        {
            return ParseCfsPeriod(period).and_then(
                [quotaValue](const int64_t periodValue)
                { return CpuBandwidth::Make(quotaValue, periodValue); });
        });
}

// Only open()'s errno tells a missing file from one that does not open,
// which is why the files are read with file_io, not a stream.
static CgroupError ToCgroupError(const std::errc error)
{
    switch(error)
    {
    case std::errc::no_such_file_or_directory:
        return CgroupError::NoCgroup;
    case std::errc::file_too_large:
        return CgroupError::MalformedFile;
    default:
        return CgroupError::SyscallFailed;
    }
}

// Cgroup value files (cpu.max, cpu.cfs_quota_us, cpu.cfs_period_us) hold one
// or two integers and a newline. A file of this many bytes or more is not a
// value file: ReadCpuBandwidth reads no further and reports MalformedFile.
constexpr size_t VALUE_FILE_SIZE_LIMIT = 64;

static tl::expected<std::string, CgroupError> ReadLimitFile(
    const std::filesystem::path& path)
{
    return ReadSmallFile(path, VALUE_FILE_SIZE_LIMIT).transform_error(ToCgroupError);
}

namespace
{
    // The contents of one proc directory's files, self's or thread-self's.
    struct ProcFiles
    {
        std::string cgroup;
        std::string mountinfo;
    };
}

static tl::expected<ProcFiles, std::errc> ReadProcFiles(const std::filesystem::path& dir)
{
    return ReadFile(dir / "cgroup")
        .and_then(
            [&dir](const std::string& cgroup)
            {
                return ReadFile(dir / "mountinfo")
                    .transform(
                        [&cgroup](const std::string& mountinfo)
                        { return ProcFiles{.cgroup = cgroup, .mountinfo = mountinfo}; });
            });
}

static tl::expected<CgroupDir, CgroupError> LocateCgroupDir(const ProcFiles& files)
{
    return ParseCpuCgroup(files.cgroup)
        .and_then([&files](const CpuCgroup& cgroup)
                  { return ParseCpuCgroupDir(files.mountinfo, cgroup); });
}

// Once the main thread has exited, proc/self is that exited thread's, and
// its mountinfo no longer opens (EINVAL, as exit_task_namespaces has
// cleared its nsproxy, which mounts_open_common requires). On a cgroup v1
// hierarchy its cgroup then reads as "/" (proc_cgroup_show prints that for
// an exiting task), so the cgroup file must come from the same directory as
// mountinfo. thread-self's files are the process's unless the calling
// thread has its own mount namespace or was moved to another cgroup on its
// own. Kernels before 3.17 have no thread-self.
tl::expected<CgroupDir, CgroupError> bsv::internal::FindCgroupDir(
    const std::filesystem::path& root)
{
    return ReadProcFiles(root / "proc/self")
        .or_else(
            [&root](const std::errc selfError)
            {
                return ReadProcFiles(root / "proc/thread-self")
                    .or_else([selfError](const std::errc /*threadSelfError*/)
                                 -> tl::expected<ProcFiles, std::errc>
                             { return tl::unexpected{selfError}; });
            })
        .transform_error(ToCgroupError)
        .and_then(LocateCgroupDir)
        // The directory is absolute; operator/ would let it replace `root`.
        .transform(
            [&root](const CgroupDir& dir)
            {
                return CgroupDir{.version = dir.version,
                                 .path = root / dir.path.relative_path()};
            });
}

static tl::expected<CpuBandwidth, CgroupError> ReadCfsBandwidth(
    const std::filesystem::path& dir)
{
    return ReadLimitFile(dir / "cpu.cfs_quota_us")
        .and_then(
            [&dir](const std::string& quota)
            {
                return ReadLimitFile(dir / "cpu.cfs_period_us")
                    .and_then([&quota](const std::string& period)
                              { return ParseCfsBandwidth(quota, period); });
            });
}

tl::expected<CpuBandwidth, CgroupError> bsv::internal::ReadCpuBandwidth(
    const CgroupDir& dir)
{
    if(dir.version == CgroupVersion::V2)
        return ReadLimitFile(dir.path / "cpu.max").and_then(ParseCpuMax);

    return ReadCfsBandwidth(dir.path);
}
