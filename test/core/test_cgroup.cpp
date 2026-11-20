#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <limits>
#include <optional>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#ifdef NDEBUG
#define BOOST_TEST_MODULE test_cgroup
#else
#define BOOST_TEST_MODULE test_cgroupd
#endif

#include <boost/test/unit_test.hpp>

#include "temp_root.h"

#include <internal/cgroup.hpp>

#include <expected.h>
#include <utilstrencodings.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

// How cgroup results print when a check fails. In bsv::internal, where
// Boost.Test finds them by argument-dependent lookup.
namespace bsv::internal
{
    template<typename T>
    static std::ostream& operator<<(std::ostream& os,
                                    const tl::expected<T, CgroupError>& result)
    {
        if(!result)
            return os << result.error();

        if constexpr(std::is_same_v<T, std::string>)
        {
            os << '\'' << *result << '\'';
        }
        else
        {
            os << *result;
        }
        return os;
    }

    static std::ostream& operator<<(std::ostream& os,
                                    const tl::unexpected<CgroupError>& error)
    {
        // Through expected, as tl::unexpected names its error value() and
        // std::unexpected error().
        return os << tl::expected<void, CgroupError>{error}.error();
    }
}

// On Linux a container's CPU limit comes from its cgroup. The parsers take
// file contents, so their cases are string tables; FindCgroupDir and
// ReadCpuBandwidth, which read the files, are checked on a temporary tree.
BOOST_AUTO_TEST_SUITE(cgroup)

using namespace bsv::internal;
using namespace bsv::test;
using enum CgroupError;

// mountinfo lines as the kernel writes them.
constexpr std::string_view
    ROOT_MOUNT = "22 1 259:1 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p1 rw\n";
constexpr std::string_view
    CGROUP2_MOUNT = "30 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime "
                    "shared:4 - cgroup2 "
                    "cgroup2 rw,nsdelegate,memory_recursiveprot\n";
constexpr std::string_view
    V1_MOUNTS = "40 30 0:35 /kubepods/burstable/pod1/ctr /sys/fs/cgroup/memory "
                "ro,nosuid,nodev,noexec,relatime master:16 - cgroup cgroup "
                "rw,memory\n"
                "41 30 0:36 /kubepods/burstable/pod1/ctr /sys/fs/cgroup/cpu,cpuacct "
                "ro,nosuid,nodev,noexec,relatime master:17 - cgroup "
                "cgroup rw,cpu,cpuacct\n"
                "42 30 0:37 /kubepods/burstable/pod1/ctr /sys/fs/cgroup/cpuset "
                "ro,nosuid,nodev,noexec,relatime master:18 - cgroup cgroup "
                "rw,cpuset\n";
constexpr std::string_view
    V1_CPU_MOUNT = "41 30 0:36 / /sys/fs/cgroup/cpu,cpuacct rw,relatime master:17 - "
                   "cgroup cgroup rw,cpu,cpuacct\n";

// The parsers stop at the newline, so the padding is never parsed.
static std::string PaddedTo(const std::string& content, const size_t size)
{
    return content + std::string(size - content.size(), '0');
}

static std::string Concat(std::initializer_list<std::string_view> parts)
{
    std::string out;
    for(const std::string_view part : parts)
        out += part;
    return out;
}

// Each proc/self/cgroup and the cgroup ParseCpuCgroup finds in it.
BOOST_AUTO_TEST_CASE(parse_cpu_cgroup)
{
    const std::vector<std::pair<std::string, tl::expected<CpuCgroup, CgroupError>>> cases{
        {"0::/\n", CpuCgroup{CgroupVersion::V2, "/"}},
        {"0::/system.slice/node.service\n",
         CpuCgroup{CgroupVersion::V2, "/system.slice/node.service"}},
        // Outside the cgroup namespace: ParseCpuCgroupDir rejects it, not this.
        {"0::/../../other\n", CpuCgroup{CgroupVersion::V2, "/../../other"}},
        {"12:memory:/kubepods/burstable/pod1/ctr\n11:cpu,cpuacct:/kubepods/burstable/"
         "pod1/ctr\n"
         "10:cpuset:/kubepods/burstable/pod1/ctr\n0::/\n",
         CpuCgroup{CgroupVersion::V1, "/kubepods/burstable/pod1/ctr"}},
        // Only a controller list containing exactly "cpu" counts.
        {"10:cpuset:/kubepods/pod1/ctr\n11:cpu,cpuacct:/kubepods/pod1/ctr\n0::/\n",
         CpuCgroup{CgroupVersion::V1, "/kubepods/pod1/ctr"}},
        {"10:cpuacct:/a\n0::/b\n", CpuCgroup{CgroupVersion::V2, "/b"}},
        // The v1 cpu hierarchy wins over v2 wherever it is listed, and the
        // first one counts.
        {"0::/b\n11:cpu,cpuacct:/a\n", CpuCgroup{CgroupVersion::V1, "/a"}},
        {"11:cpu,cpuacct:/a\n12:cpu:/b\n", CpuCgroup{CgroupVersion::V1, "/a"}},
        // v2 is hierarchy 0 exactly; other hierarchies without cpu don't count,
        // and neither does an empty file.
        {"5::/x\n", tl::unexpected{NoCgroup}},
        {"10:cpuacct:/a\n", tl::unexpected{NoCgroup}},
        {"0123:cpuacct:/a\n", tl::unexpected{NoCgroup}},
        {"", tl::unexpected{NoCgroup}},
        // Malformed: a line without two colons, a blank line, a path not
        // starting with '/'. Each rejects the file even when a valid line
        // follows.
        {"not a cgroup line\n", tl::unexpected{MalformedFile}},
        {"/a/b\n0::/\n", tl::unexpected{MalformedFile}},
        {"0:cpu\n0::/\n", tl::unexpected{MalformedFile}},
        {"\n0::/\n", tl::unexpected{MalformedFile}},
        {"0::relative\n", tl::unexpected{MalformedFile}},
        {"0::relative\n0::/\n", tl::unexpected{MalformedFile}},
        // A last line without its newline is incomplete, whatever it holds,
        // unless the v1 cpu hierarchy comes first.
        {"0::/", tl::unexpected{IncompleteLine}},
        {"0:cpu", tl::unexpected{IncompleteLine}},
        {"11:cpu:/a\n0::/", CpuCgroup{CgroupVersion::V1, "/a"}},
    };
    for(const auto& [cgroupFile, expected] : cases)
    {
        BOOST_TEST_CONTEXT("cgroup file '" << cgroupFile << "'")
        {
            BOOST_CHECK_EQUAL(expected, ParseCpuCgroup(cgroupFile));
        }
    }
}

// Each proc/self/mountinfo and cgroup, and the directory ParseCpuCgroupDir
// builds from them.
BOOST_AUTO_TEST_CASE(parse_cpu_cgroup_dir)
{
    const CpuCgroup v2Root{CgroupVersion::V2, "/"};
    const std::vector<
        std::tuple<std::string, CpuCgroup, tl::expected<std::string, CgroupError>>>
        cases{
            {Concat({ROOT_MOUNT, CGROUP2_MOUNT}), v2Root, "/sys/fs/cgroup"},
            {Concat({ROOT_MOUNT, CGROUP2_MOUNT}),
             {CgroupVersion::V2, "/system.slice/node.service"},
             "/sys/fs/cgroup/system.slice/node.service"},
            // A space in the mount point is escaped as \040.
            {Concat({ROOT_MOUNT,
                     "30 23 0:26 / /sys/fs/cgroup\\040unified "
                     "rw,nosuid,nodev,noexec,relatime shared:4 - cgroup2 cgroup2 rw\n"}),
             v2Root,
             "/sys/fs/cgroup unified"},
            // A cgroup shown as /../.. lies outside the mount this namespace sees.
            {Concat({ROOT_MOUNT, CGROUP2_MOUNT}),
             {CgroupVersion::V2, "/../../other"},
             tl::unexpected{NoCgroup}},
            // A mount rooted at /kubepods/podA does not contain /kubepods/podAB/ctr;
            // the next mount, rooted at /, does.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 /kubepods/podA /sys/fs/cgroup-a rw,relatime shared:5 - "
                     "cgroup2 cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             {CgroupVersion::V2, "/kubepods/podAB/ctr"},
             "/sys/fs/cgroup/kubepods/podAB/ctr"},
            // A mount rooted at the cgroup itself.
            {Concat({ROOT_MOUNT, V1_MOUNTS}),
             {CgroupVersion::V1, "/kubepods/burstable/pod1/ctr"},
             "/sys/fs/cgroup/cpu,cpuacct"},
            // v1: only a cgroup mount whose super options contain "cpu" counts.
            {Concat({ROOT_MOUNT,
                     "42 30 0:37 /kubepods/pod1/ctr /sys/fs/cgroup/cpuset "
                     "ro,nosuid,nodev,noexec,relatime master:18 - cgroup cgroup "
                     "rw,cpuset\n"
                     "41 30 0:36 /kubepods/pod1/ctr /sys/fs/cgroup/cpu,cpuacct "
                     "ro,nosuid,nodev,noexec,relatime master:17 - cgroup "
                     "cgroup rw,cpu,cpuacct\n"}),
             {CgroupVersion::V1, "/kubepods/pod1/ctr"},
             "/sys/fs/cgroup/cpu,cpuacct"},
            {Concat({ROOT_MOUNT, CGROUP2_MOUNT}),
             {CgroupVersion::V1, "/"},
             tl::unexpected{NoCgroup}},
            // A malformed line (no " - " separator, or no filesystem type after
            // it), a blank line, a bad \ooo escape in the selected mount point, or
            // an escape above \377 in the root of a cgroup2 mount makes the file
            // unreadable even when a valid cgroup2 mount follows.
            {Concat({ROOT_MOUNT, "31 23 0:27 / /mnt/broken rw\n", CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{MalformedFile}},
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 / /sys/fs/cgroup-t rw,relatime shared:5 - cgroup2\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{MalformedFile}},
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 / /sys/fs/cgroup\\09x rw,relatime shared:5 - cgroup2 "
                     "cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{InvalidEscape}},
            {Concat({ROOT_MOUNT, "\n", CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{MalformedFile}},
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 /x\\777 /sys/fs/cgroup-x rw,relatime shared:5 - cgroup2 "
                     "cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{InvalidEscape}},
            // A mount whose root does not start with '/', cgroup or not, rejects
            // the file; an nsfs bind mount is enough, with or without a cgroup2
            // mount after it.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 kubepods /sys/fs/cgroup-k rw,relatime shared:5 - "
                     "cgroup2 cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{MalformedFile}},
            {Concat({ROOT_MOUNT,
                     "41 25 0:4 net:[4026532296] /run/netns/ns1 rw shared:12 - nsfs nsfs "
                     "rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{MalformedFile}},
            {Concat({ROOT_MOUNT,
                     "41 25 0:4 net:[4026532296] /run/netns/ns1 rw shared:12 - nsfs nsfs "
                     "rw\n"}),
             v2Root,
             tl::unexpected{MalformedFile}},
            // Only the selected mount's mount point is unescaped: a bad escape on
            // a cgroup2 mount whose root does not contain the cgroup is not read.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 /elsewhere /mnt/bad\\09x rw,relatime shared:5 - cgroup2 "
                     "cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             {CgroupVersion::V2, "/kubepods/ctr"},
             "/sys/fs/cgroup/kubepods/ctr"},
            // A cgroup2 mount needs its filesystem type and the space after it,
            // not the source or super options. The last line needs no newline.
            {"22 1 259:1 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p1\n"
             "30 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:4 - "
             "cgroup2 cgroup2\n",
             v2Root,
             "/sys/fs/cgroup"},
            {Concat({ROOT_MOUNT, CGROUP2_MOUNT.substr(0, CGROUP2_MOUNT.size() - 1)}),
             v2Root,
             "/sys/fs/cgroup"},
            {std::string(ROOT_MOUNT), v2Root, tl::unexpected{NoCgroup}},
            // A V2 cgroup with v1 cgroup mounts listed first (a hybrid host).
            {Concat({ROOT_MOUNT, V1_CPU_MOUNT, CGROUP2_MOUNT}),
             {CgroupVersion::V2, "/x"},
             "/sys/fs/cgroup/x"},
            // A v1 cgroup mount needs its source; without one the file is
            // malformed, even when the mount is not the cpu one.
            {Concat({ROOT_MOUNT,
                     "40 30 0:35 / /sys/fs/cgroup/z rw - cgroup\n",
                     V1_CPU_MOUNT}),
             {CgroupVersion::V1, "/x"},
             tl::unexpected{MalformedFile}},
            {Concat({ROOT_MOUNT,
                     "40 30 0:35 / /sys/fs/cgroup/z rw - cgroup cgroup\n",
                     V1_CPU_MOUNT}),
             {CgroupVersion::V1, "/x"},
             tl::unexpected{MalformedFile}},
            // Roots are unescaped only on mounts of the wanted type: a bad escape
            // on an ext4 root is not read.
            {Concat({"22 1 259:1 /a\\777 / rw - ext4 /dev/x rw\n", CGROUP2_MOUNT}),
             v2Root,
             "/sys/fs/cgroup"},
            // A mount that can only reach the cgroup through /.. is skipped, and
            // the next one matches.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 /x /m1 rw - cgroup2 cgroup2 rw\n32 23 0:28 / /m2 rw - "
                     "cgroup2 cgroup2 rw\n"}),
             {CgroupVersion::V2, "/x/../../y"},
             "/m2/x/../../y"},
            // /.. is matched on a path boundary: a directory named ..foo is inside.
            {Concat({ROOT_MOUNT, "31 23 0:27 /x /m1 rw - cgroup2 cgroup2 rw\n"}),
             {CgroupVersion::V2, "/x/..foo"},
             "/m1/..foo"},
            // The first matching mount wins.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 / /m1 rw - cgroup2 cgroup2 rw\n32 23 0:28 / /m2 rw - "
                     "cgroup2 cgroup2 rw\n"}),
             {CgroupVersion::V2, "/c"},
             "/m1/c"},
            // A root matches as a prefix of the cgroup, not by its length alone.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 /aaa /m1 rw - cgroup2 cgroup2 rw\n32 23 0:28 / /m2 rw - "
                     "cgroup2 cgroup2 rw\n"}),
             {CgroupVersion::V2, "/bbb/ctr"},
             "/m2/bbb/ctr"},
            // \ooo escapes: octal digits only, at most \377.
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 / /m\\089 rw - cgroup2 cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{InvalidEscape}},
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 / /m\\0/0 rw - cgroup2 cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{InvalidEscape}},
            {Concat({ROOT_MOUNT,
                     "31 23 0:27 /x\\400 /m rw - cgroup2 cgroup2 rw\n",
                     CGROUP2_MOUNT}),
             v2Root,
             tl::unexpected{InvalidEscape}},
            {Concat({ROOT_MOUNT, "31 23 0:27 / /m\\377 rw - cgroup2 cgroup2 rw\n"}),
             v2Root,
             "/m\xff"},
            // An escaped root that contains the cgroup: \134 is a backslash.
            {Concat({ROOT_MOUNT, "31 23 0:27 /a\\134b /m rw - cgroup2 cgroup2 rw\n"}),
             {CgroupVersion::V2, "/a\\b/ctr"},
             "/m/ctr"},
    };
    for(const auto& [mountinfo, cgroup, expected] : cases)
    {
        BOOST_TEST_CONTEXT(
            "cgroup " << cgroup.path << ", mountinfo '" << mountinfo << "'")
        {
            const auto expectedDir{
                expected.transform([&cgroup](const std::string& path)
                                   { return CgroupDir{cgroup.version, path}; })};
            BOOST_CHECK_EQUAL(expectedDir, ParseCpuCgroupDir(mountinfo, cgroup));
        }
    }
}

// Each cpu.max and the bandwidth ParseCpuMax reads from it.
BOOST_AUTO_TEST_CASE(parse_cpu_max)
{
    const std::vector<std::pair<std::string, tl::expected<CpuBandwidth, CgroupError>>>
        cases{
            {"250000 100000\n", CpuBandwidth::Make(250000, 100000)},
            // "max" is Unlimited. The period and the newline are still checked,
            // and a file without the space is malformed.
            {"max 100000\n", CpuBandwidth::Make(Unlimited{}, 100000)},
            {"max 100000", tl::unexpected{MalformedFile}},
            {"max\n", tl::unexpected{MalformedFile}},
            {"two and a half\n", tl::unexpected{MalformedFile}},
            // A zero quota reads as it is. A negative one, and a period of zero
            // or less, are malformed; the kernel writes neither. Go accepts
            // both, and divides by the period.
            {"0 100000\n", CpuBandwidth::Make(0, 100000)},
            {"-1 100000\n", tl::unexpected{MalformedFile}},
            {"250000 0\n", tl::unexpected{MalformedFile}},
            {"250000 -100000\n", tl::unexpected{MalformedFile}},
            {"max 0\n", tl::unexpected{MalformedFile}},
            // The period ends at its newline; anything after it is not parsed.
            // ReadCpuBandwidth applies VALUE_FILE_SIZE_LIMIT (see
            // read_cpu_bandwidth_reads_cpu_max).
            {"250000 100000\n00000000000000000000000000000000000000000000000000\n",
             CpuBandwidth::Make(250000, 100000)},
            {"250000 100000", tl::unexpected{MalformedFile}},
            {"250000 100000\r\n", tl::unexpected{MalformedFile}},
            {"250000  100000\n", tl::unexpected{MalformedFile}},
            {"+250000 +100000\n", CpuBandwidth::Make(250000, 100000)},
            {"", tl::unexpected{MalformedFile}},
    };
    for(const auto& [cpuMax, expected] : cases)
    {
        BOOST_TEST_CONTEXT("cpu.max '" << cpuMax << "'")
        {
            BOOST_CHECK_EQUAL(expected, ParseCpuMax(cpuMax));
        }
    }
}

// Each cpu.cfs_quota_us and cpu.cfs_period_us, and the bandwidth
// ParseCfsBandwidth reads from them.
BOOST_AUTO_TEST_CASE(parse_cfs_bandwidth)
{
    const std::vector<
        std::tuple<std::string, std::string, tl::expected<CpuBandwidth, CgroupError>>>
        cases{
            {"200000\n", "100000\n", CpuBandwidth::Make(200000, 100000)},
            // A negative quota, usually -1, is Unlimited. The period is still
            // checked.
            {"-1\n", "100000\n", CpuBandwidth::Make(Unlimited{}, 100000)},
            {"-5\n", "100000\n", CpuBandwidth::Make(Unlimited{}, 100000)},
            {"-1\n", "garbage", tl::unexpected{MalformedFile}},
            {"-1\n", "0\n", tl::unexpected{MalformedFile}},
            {"0\n", "100000\n", CpuBandwidth::Make(0, 100000)},
            // A period of zero or less is malformed. Go accepts it, and
            // divides by it.
            {"200000\n", "0\n", tl::unexpected{MalformedFile}},
            {"200000\n", "-100000\n", tl::unexpected{MalformedFile}},
            {"200000", "100000\n", tl::unexpected{MalformedFile}},
            {"-1", "100000\n", tl::unexpected{MalformedFile}},
            {"200000\n", "100000", tl::unexpected{MalformedFile}},
            {"200000\r\n", "100000\n", tl::unexpected{MalformedFile}},
            {"max\n", "100000\n", tl::unexpected{MalformedFile}},
    };
    for(const auto& [quota, period, expected] : cases)
    {
        BOOST_TEST_CONTEXT("quota '" << quota << "', period '" << period << "'")
        {
            BOOST_CHECK_EQUAL(expected, ParseCfsBandwidth(quota, period));
        }
    }
}

// FindCgroupDir joins the cgroup's directory, found from proc/self/cgroup and
// proc/self/mountinfo, below the root it is given.
BOOST_AUTO_TEST_CASE(find_cgroup_dir_reads_the_proc_files,
                     *boost::unit_test::label("integration"))
{
    const TempRoot root;
    root.Write("proc/self/cgroup", "0::/ctr\n");
    root.Write("proc/self/mountinfo", Concat({ROOT_MOUNT, CGROUP2_MOUNT}));
    BOOST_CHECK_EQUAL((CgroupDir{CgroupVersion::V2, root.Path() / "sys/fs/cgroup/ctr"}),
                      FindCgroupDir(root.Path()));
    root.Write("proc/self/cgroup", "11:cpu,cpuacct:/ctr\n0::/\n");
    root.Write("proc/self/mountinfo", Concat({ROOT_MOUNT, V1_CPU_MOUNT}));
    BOOST_CHECK_EQUAL((CgroupDir{CgroupVersion::V1,
                                 root.Path() / "sys/fs/cgroup/cpu,cpuacct/ctr"}),
                      FindCgroupDir(root.Path()));

    // A proc file that is missing is no cgroup; one that does not open or read
    // is SyscallFailed. The parsers' errors come through.
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, FindCgroupDir(root.Path() / "missing"));
    std::filesystem::remove(root.Path() / "proc/self/cgroup");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, FindCgroupDir(root.Path()));
    std::filesystem::create_directory(root.Path() / "proc/self/cgroup");
    BOOST_CHECK_EQUAL(tl::unexpected{SyscallFailed}, FindCgroupDir(root.Path()));
    std::filesystem::remove(root.Path() / "proc/self/cgroup");
    root.Write("proc/self/cgroup", "0::/ctr");
    BOOST_CHECK_EQUAL(tl::unexpected{IncompleteLine}, FindCgroupDir(root.Path()));
    root.Write("proc/self/cgroup", "0::/ctr\n");
    root.Write("proc/self/mountinfo", "garbage\n");
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, FindCgroupDir(root.Path()));
    std::filesystem::remove(root.Path() / "proc/self/mountinfo");
    std::filesystem::create_directory(root.Path() / "proc/self/mountinfo");
    BOOST_CHECK_EQUAL(tl::unexpected{SyscallFailed}, FindCgroupDir(root.Path()));

    // The cgroup file is read and parsed before mountinfo is.
    std::filesystem::remove(root.Path() / "proc/self/cgroup");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, FindCgroupDir(root.Path()));
    std::filesystem::remove(root.Path() / "proc/self/mountinfo");
    root.Write("proc/self/mountinfo", "garbage\n");
    root.Write("proc/self/cgroup", "0::/ctr");
    BOOST_CHECK_EQUAL(tl::unexpected{IncompleteLine}, FindCgroupDir(root.Path()));
}

// FindCgroupDir reads the cgroup and mountinfo files of proc/self, or, when
// either does not read (its mountinfo does not once the main thread has
// exited), both of proc/thread-self. It never takes one file from each.
BOOST_AUTO_TEST_CASE(find_cgroup_dir_reads_self_else_thread_self,
                     *boost::unit_test::label("integration"))
{
    const TempRoot root;
    root.Write("proc/self/cgroup", "0::/process\n");
    root.Write("proc/self/mountinfo",
               Concat(
                   {ROOT_MOUNT, "31 23 0:26 / /mnt/cgroup rw - cgroup2 cgroup2 rw\n"}));
    root.Write("proc/thread-self/cgroup", "0::/thread\n");
    root.Write("proc/thread-self/mountinfo", Concat({ROOT_MOUNT, CGROUP2_MOUNT}));
    const CgroupDir self{CgroupVersion::V2, root.Path() / "mnt/cgroup/process"};
    const CgroupDir threadSelf{CgroupVersion::V2, root.Path() / "sys/fs/cgroup/thread"};
    BOOST_CHECK_EQUAL(self, FindCgroupDir(root.Path()));

    // When either of proc/self's files does not read, proc/thread-self's are
    // the ones.
    std::filesystem::remove(root.Path() / "proc/self/cgroup");
    BOOST_CHECK_EQUAL(threadSelf, FindCgroupDir(root.Path()));
    root.Write("proc/self/cgroup", "0::/process\n");
    std::filesystem::remove(root.Path() / "proc/self/mountinfo");
    BOOST_CHECK_EQUAL(threadSelf, FindCgroupDir(root.Path()));
    std::filesystem::remove(root.Path() / "proc/self/cgroup");
    BOOST_CHECK_EQUAL(threadSelf, FindCgroupDir(root.Path()));
    root.Write("proc/self/cgroup", "0::/process\n");
    std::filesystem::remove(root.Path() / "proc/thread-self/cgroup");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, FindCgroupDir(root.Path()));
    root.Write("proc/thread-self/cgroup", "0::/thread\n");

    // When neither directory's files read, the error is proc/self's.
    std::filesystem::remove(root.Path() / "proc/thread-self/mountinfo");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, FindCgroupDir(root.Path()));
    std::filesystem::create_directory(root.Path() / "proc/self/mountinfo");
    BOOST_CHECK_EQUAL(tl::unexpected{SyscallFailed}, FindCgroupDir(root.Path()));
}

// ReadCpuBandwidth reads cpu.max from a cgroup v2 directory. A missing file is
// no cgroup, as in the root cgroup or one without the cpu controller; one of
// VALUE_FILE_SIZE_LIMIT bytes or more is MalformedFile; one that does not open
// or read is SyscallFailed.
BOOST_AUTO_TEST_CASE(read_cpu_bandwidth_reads_cpu_max,
                     *boost::unit_test::label("integration"))
{
    const TempRoot root;
    const CgroupDir dir{CgroupVersion::V2, root.Path()};
    root.Write("cpu.max", PaddedTo("150000 100000\n", VALUE_FILE_SIZE_LIMIT - 1));
    BOOST_CHECK_EQUAL(CpuBandwidth::Make(150000, 100000), ReadCpuBandwidth(dir));
    root.Write("cpu.max", PaddedTo("150000 100000\n", VALUE_FILE_SIZE_LIMIT));
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, ReadCpuBandwidth(dir));
    std::filesystem::remove(root.Path() / "cpu.max");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, ReadCpuBandwidth(dir));
    std::filesystem::create_directory(root.Path() / "cpu.max");
    BOOST_CHECK_EQUAL(tl::unexpected{SyscallFailed}, ReadCpuBandwidth(dir));
}

// ReadCpuBandwidth reads cpu.cfs_quota_us and cpu.cfs_period_us from a cgroup
// v1 directory. Each file has the size limit, and its errors are its own, the
// quota's first; the period is read even next to a quota that is no limit.
BOOST_AUTO_TEST_CASE(read_cpu_bandwidth_reads_the_v1_files,
                     *boost::unit_test::label("integration"))
{
    const TempRoot root;
    const CgroupDir dir{CgroupVersion::V1, root.Path()};
    root.Write("cpu.cfs_quota_us", "50000\n");
    root.Write("cpu.cfs_period_us", "100000\n");
    BOOST_CHECK_EQUAL(CpuBandwidth::Make(50000, 100000), ReadCpuBandwidth(dir));
    root.Write("cpu.cfs_quota_us", PaddedTo("50000\n", VALUE_FILE_SIZE_LIMIT));
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, ReadCpuBandwidth(dir));
    root.Write("cpu.cfs_quota_us", "50000\n");
    root.Write("cpu.cfs_period_us", PaddedTo("100000\n", VALUE_FILE_SIZE_LIMIT));
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, ReadCpuBandwidth(dir));

    // Read errors come before parse errors, the quota's first.
    root.Write("cpu.cfs_period_us", "garbage\n");
    std::filesystem::remove(root.Path() / "cpu.cfs_quota_us");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, ReadCpuBandwidth(dir));
    root.Write("cpu.cfs_quota_us", "garbage\n");
    std::filesystem::remove(root.Path() / "cpu.cfs_period_us");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, ReadCpuBandwidth(dir));

    root.Write("cpu.cfs_quota_us", "-1\n");
    BOOST_CHECK_EQUAL(tl::unexpected{NoCgroup}, ReadCpuBandwidth(dir));
}

#if defined(__linux__)
static std::string ReadText(const std::filesystem::path& path)
{
    const std::ifstream in(path, std::ios::binary);
    std::ostringstream content;
    content << in.rdbuf();
    return content.str();
}

// 'Z' once the main thread has exited while other threads run.
static char ProcessState()
{
    const std::string stat = ReadText("/proc/self/stat");
    const size_t paren = stat.rfind(')');
    return paren != std::string::npos && paren + 2 < stat.size() ? stat[paren + 2] : '?';
}

// What the child below reports through its exit status.
constexpr int DIR_FOUND = 0;
constexpr int NO_DIR = 1;
constexpr int OTHER_DIR = 2;
constexpr int MAIN_THREAD_RUNNING = 3;

// The cgroup directory found from another thread after the main thread has
// exited: proc/self is then the exited thread's, and its mountinfo no longer
// opens, so FindCgroupDir reads proc/thread-self's files. The root's proc is the
// live one.
BOOST_AUTO_TEST_CASE(find_cgroup_dir_after_the_main_thread_exits,
                     *boost::unit_test::label("integration"))
{
    const auto found = ParseCpuCgroup(ReadText("/proc/self/cgroup"));
    const auto dir = found.and_then(
        [](const CpuCgroup& cgroup)
        { return ParseCpuCgroupDir(ReadText("/proc/self/mountinfo"), cgroup); });
    if(!dir)
    {
        BOOST_TEST_MESSAGE("no cgroup directory with a cpu controller here: " << dir);
        return;
    }

    const TempRoot root;
    std::filesystem::create_directory_symlink("/proc", root.Path() / "proc");
    const CgroupDir expected{dir->version, root.Path() / dir->path.relative_path()};
    BOOST_REQUIRE_EQUAL(expected, FindCgroupDir(root.Path()));

    const pid_t child = fork();
    BOOST_REQUIRE_NE(-1, child);
    if(child == 0)
    {
        // The child's only thread is its main thread. A second thread waits
        // for it to exit, finds the directory and exits the child with the
        // result.
        std::thread(
            [path = root.Path(), expected]
            {
                for(int i = 0; i < 1000 && ProcessState() != 'Z'; ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                if(ProcessState() != 'Z')
                    _exit(MAIN_THREAD_RUNNING);
                const auto other = FindCgroupDir(path);
                if(!other)
                    _exit(NO_DIR);
                _exit(*other == expected ? DIR_FOUND : OTHER_DIR);
            })
            .detach();
        // The exit system call ends only the calling thread; pthread_exit
        // would unwind the test runner's stack.
        syscall(SYS_exit, 0);
    }
    int status = 0;
    BOOST_REQUIRE_EQUAL(child, waitpid(child, &status, 0));
    BOOST_REQUIRE(WIFEXITED(status));
    BOOST_CHECK_EQUAL(DIR_FOUND, WEXITSTATUS(status));
}
#endif

// cgroup integers are whole-string base 10 with an optional sign, as ParseInt64
// parses them: anything after the digits, and any surrounding whitespace,
// rejects the value.
BOOST_AUTO_TEST_CASE(cgroup_integers_parse_the_whole_string)
{
    constexpr int64_t max = std::numeric_limits<int64_t>::max();
    constexpr int64_t min = std::numeric_limits<int64_t>::min();
    const std::vector<std::pair<std::string, std::optional<int64_t>>> cases{
        {"100000", 100'000},
        {"0", 0},
        {"-1", -1},
        {"+5", 5},
        {"9223372036854775807", max},
        {"+9223372036854775807", max},
        {"-9223372036854775808", min},
        // Trailing characters
        {"250000x", std::nullopt},
        {"100000 ", std::nullopt},
        {"100000\n", std::nullopt},
        {"1 2", std::nullopt},
        {"12.5", std::nullopt},
        {"0x10", std::nullopt},
        {std::string("5\0", 2), std::nullopt},
        // Leading characters, signs alone or doubled, out of range
        {"", std::nullopt},
        {" 5", std::nullopt},
        {"\t5", std::nullopt},
        {"\xff"
         "5",
         std::nullopt},
        {"+", std::nullopt},
        {"-", std::nullopt},
        {"+-5", std::nullopt},
        {"-+5", std::nullopt},
        {"++5", std::nullopt},
        {"x1", std::nullopt},
        {"9223372036854775808", std::nullopt},
        {"-9223372036854775809", std::nullopt},
    };
    for(const auto& [text, expected] : cases)
    {
        BOOST_TEST_CONTEXT("text '" << text << "'")
        {
            int64_t actual{};
            BOOST_CHECK_EQUAL(expected.has_value(), ParseInt64(text, &actual));
            if(expected)
                BOOST_CHECK_EQUAL(*expected, actual);
        }
    }
}

// The CPUs a bandwidth needs: quota / period rounded up, exactly.
BOOST_AUTO_TEST_CASE(cpu_bandwidth_cpus_needed_rounds_up)
{
    constexpr int64_t maxQuota = std::numeric_limits<int64_t>::max();
    constexpr int64_t twoTo60 = 1'152'921'504'606'846'976;
    const std::vector<std::pair<tl::expected<CpuBandwidth, CgroupError>, uint64_t>> cases{
        {CpuBandwidth::Make(400000, 100000), 4},
        // Rounded up, not to nearest.
        {CpuBandwidth::Make(250000, 100000), 3},
        {CpuBandwidth::Make(220000, 100000), 3},
        {CpuBandwidth::Make(200001, 100000), 3},
        {CpuBandwidth::Make(1550000, 100000), 16},
        {CpuBandwidth::Make(50000, 100000), 1},
        {CpuBandwidth::Make(0, 100000), 0},
        {CpuBandwidth::Make(maxQuota, 1), maxQuota},
        {CpuBandwidth::Make(1, maxQuota), 1},
        // Exact where a double is not: 3 * 2^60 + 1 rounds to 3 * 2^60 as one,
        // so Go, which divides doubles, gets 3.
        {CpuBandwidth::Make((3 * twoTo60) + 1, twoTo60), 4},
    };
    for(const auto& [bandwidth, expected] : cases)
    {
        BOOST_TEST_CONTEXT("bandwidth " << bandwidth)
        {
            BOOST_CHECK_EQUAL(expected, bandwidth.value().CpusNeeded());
        }
    }

    // A precondition broken fails loudly.
    BOOST_CHECK_THROW(std::ignore = CpuBandwidth::Make(Unlimited{}, 100000)
                                        .value()
                                        .CpusNeeded(),
                      std::bad_variant_access);
}

// A bandwidth's quota is not negative and its period is above zero.
BOOST_AUTO_TEST_CASE(cpu_bandwidth_rejects_a_negative_quota_or_a_period_of_zero_or_less)
{
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, CpuBandwidth::Make(-1, 100000));
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile},
                      CpuBandwidth::Make(std::numeric_limits<int64_t>::min(), 1));
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, CpuBandwidth::Make(100000, 0));
    BOOST_CHECK_EQUAL(tl::unexpected{MalformedFile}, CpuBandwidth::Make(Unlimited{}, -1));
    BOOST_CHECK(CpuBandwidth::Make(0, 1).has_value());
    const CpuBandwidth bandwidth = CpuBandwidth::Make(50000, 1).value();
    BOOST_CHECK(bandwidth.Quota() == CpuQuota{50000});
    BOOST_CHECK_EQUAL(1, bandwidth.Period());
}

BOOST_AUTO_TEST_SUITE_END()
