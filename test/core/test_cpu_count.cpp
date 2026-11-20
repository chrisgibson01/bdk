#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#ifdef NDEBUG
#define BOOST_TEST_MODULE test_cpu_count
#else
#define BOOST_TEST_MODULE test_cpu_countd
#endif

#include <boost/test/unit_test.hpp>

#include "temp_root.h"

#include <internal/cgroup.hpp>
#include <internal/cpu_count.hpp>

#include <expected.h>

#if defined(__linux__)
#include <sched.h>
#endif

// The helper pool sizes itself from the CPUs this process may use: the
// affinity mask, lowered to the cgroup's CPU limit. LimitedCpuCount is checked
// on a table, and EffectiveCpuCount on a temporary tree and on the live system.
// Both were checked against Go 1.26's runtime with a differential test; rows
// where BDK differs say so.
BOOST_AUTO_TEST_SUITE(cpu_count)

using namespace bsv::internal;
using namespace bsv::test;

// EffectiveCpuCount applies the cgroup limit under the root it is given.
BOOST_AUTO_TEST_CASE(effective_cpu_count_applies_the_cgroup_limit,
                     *boost::unit_test::label("integration"))
{
    const TempRoot root;
    root.Write("proc/self/cgroup", "0::/ctr\n");
    root.Write("proc/self/mountinfo",
               "30 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:4 "
               "- cgroup2 cgroup2 rw,nsdelegate,memory_recursiveprot\n");
    root.Write("sys/fs/cgroup/ctr/cpu.max", "150000 100000\n");
    const size_t unlimited = EffectiveCpuCount(root.Path() / "missing");
    BOOST_CHECK_EQUAL(LimitedCpuCount(unlimited,
                                      CpuBandwidth::Make(150000, 100000).value()),
                      EffectiveCpuCount(root.Path()));
}

// On this machine, whatever its cgroup: at least one CPU. On Linux this reads
// the live affinity mask and cgroup, which hardware_concurrency() need not
// bound (musl counts the calling thread's mask, and only up to 1024 CPUs);
// elsewhere it is hardware_concurrency().
BOOST_AUTO_TEST_CASE(effective_cpu_count_of_this_machine,
                     *boost::unit_test::label("integration"))
{
    const size_t effective = EffectiveCpuCount();
    const size_t hardware = std::thread::hardware_concurrency();
    const auto bandwidth = FindCgroupDir("/").and_then(ReadCpuBandwidth);
    std::ostringstream cgroup;
    if(bandwidth)
        cgroup << *bandwidth;
    else
        cgroup << bandwidth.error();
    BOOST_TEST_MESSAGE("effective="
                       << effective
                       << " hardware_concurrency="
                       << hardware
                       << " cgroup_bandwidth="
                       << cgroup.str());
    BOOST_CHECK_GE(effective, 1U);
#if !defined(__linux__)
    BOOST_CHECK_EQUAL(std::max<size_t>(hardware, 1), effective);
#endif
}

#if defined(__linux__)
// EffectiveCpuCount respects the process's affinity mask, which
// hardware_concurrency() ignores. On Linux that is the main thread's mask, and
// Boost.Test runs test cases on the main thread, so pinning it here narrows
// the mask EffectiveCpuCount reads.
BOOST_AUTO_TEST_CASE(effective_cpu_count_applies_the_affinity_mask,
                     *boost::unit_test::label("integration"))
{
    cpu_set_t original;
    CPU_ZERO(&original);
    BOOST_REQUIRE_EQUAL(0, sched_getaffinity(0, sizeof(original), &original));
    int pinned = -1;
    for(int cpu = 0; cpu < CPU_SETSIZE && pinned < 0; ++cpu)
        if(CPU_ISSET(cpu, &original))
            pinned = cpu;
    BOOST_REQUIRE_GE(pinned, 0);
    cpu_set_t one;
    CPU_ZERO(&one);
    CPU_SET(pinned, &one);

    class RestoreAffinity
    {
    public:
        explicit RestoreAffinity(const cpu_set_t& mask): mask_{mask} {}

        ~RestoreAffinity() { sched_setaffinity(0, sizeof(mask_), &mask_); }

        RestoreAffinity(const RestoreAffinity&) = delete;
        RestoreAffinity& operator=(const RestoreAffinity&) = delete;
        RestoreAffinity(RestoreAffinity&&) = delete;
        RestoreAffinity& operator=(RestoreAffinity&&) = delete;

    private:
        cpu_set_t mask_;
    };

    const RestoreAffinity restore{original};
    BOOST_REQUIRE_EQUAL(0, sched_setaffinity(0, sizeof(one), &one));
    BOOST_CHECK_EQUAL(1U, EffectiveCpuCount());
}

// A thread pinned to one CPU still sees the process's CPUs: the count does not
// depend on which thread asks.
BOOST_AUTO_TEST_CASE(effective_cpu_count_ignores_the_calling_threads_mask,
                     *boost::unit_test::label("integration"))
{
    const size_t process = EffectiveCpuCount();
    int pinResult = -1;
    size_t fromPinnedThread = 0;
    std::thread pinned(
        [&pinResult, &fromPinnedThread]
        {
            cpu_set_t mask;
            CPU_ZERO(&mask);
            if(sched_getaffinity(0, sizeof(mask), &mask) != 0)
                return;

            int first = 0;
            while(first < CPU_SETSIZE && !CPU_ISSET(first, &mask))
                ++first;
            CPU_ZERO(&mask);
            CPU_SET(first, &mask);
            pinResult = sched_setaffinity(0, sizeof(mask), &mask);
            fromPinnedThread = EffectiveCpuCount();
        });
    pinned.join();
    BOOST_REQUIRE_EQUAL(0, pinResult);
    if(process <= 1)
        BOOST_TEST_MESSAGE(
            "only " << process << " CPU: pinning a thread cannot lower the count here");
    BOOST_CHECK_EQUAL(process, fromPinnedThread);
}
#endif

// The CPUs available to the process, lowered to the CPUs the cgroup's
// bandwidth needs, and never below the minimum because of the limit.
BOOST_AUTO_TEST_CASE(limited_cpu_count_never_goes_below_min_cgroup_cpus)
{
    constexpr size_t maxCpus = std::numeric_limits<size_t>::max();
    constexpr int64_t maxQuota = std::numeric_limits<int64_t>::max();
    // LimitedCpuCount's documented minimum.
    constexpr size_t minCgroupCpus = 2;
    // {CPUs, cgroup bandwidth, expected count}
    const std::vector<std::tuple<size_t, tl::expected<CpuBandwidth, CgroupError>, size_t>>
        cases{
            {16, CpuBandwidth::Make(400000, 100000), 4},
            {16, CpuBandwidth::Make(250000, 100000), 3},
            // Never below the minimum, whatever the quota.
            {16, CpuBandwidth::Make(101000, 100000), minCgroupCpus},
            {16, CpuBandwidth::Make(0, 100000), minCgroupCpus},
            // Unlimited, and limits too large for a CPU count, leave the count
            // unchanged.
            {16, CpuBandwidth::Make(Unlimited{}, 100000), 16},
            // Go converts a limit above 2^31 CPUs to int32, which is
            // platform-specific.
            {16, CpuBandwidth::Make(maxQuota, 1), 16},
            {maxCpus, CpuBandwidth::Make(Unlimited{}, 100000), maxCpus},
            {maxCpus, CpuBandwidth::Make(2'000'000'001, 2), 1'000'000'001},
            // The limit only lowers the count, the minimum included.
            {4, CpuBandwidth::Make(800000, 100000), 4},
            {1, CpuBandwidth::Make(50000, 100000), 1},
            {0, CpuBandwidth::Make(50000, 100000), 0},
    };
    for(const auto& [cpus, bandwidth, expected] : cases)
    {
        BOOST_TEST_CONTEXT("cpus " << cpus << ", bandwidth " << bandwidth.value())
        {
            BOOST_CHECK_EQUAL(expected, LimitedCpuCount(cpus, bandwidth.value()));
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
