#include <internal/cpu_count.hpp>

#include <internal/cgroup.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <filesystem>
#include <numeric>
#include <optional>
#include <thread>

#if defined(__linux__)
#include <sched.h>
#include <unistd.h>
#endif

using namespace bsv::internal;

// The fewest CPUs a cgroup limit lowers the count to. One would leave the
// pool no parallelism, and a quota under one CPU usually marks a bursty
// workload, which can use more for short spells.
constexpr size_t MIN_CGROUP_CPUS = 2;

#if defined(__linux__)

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

    const int count{std::accumulate(mask.begin(),
                                    mask.end(),
                                    0,
                                    [](const int sum, const cpu_set_t& set)
                                    { return sum + CPU_COUNT(&set); })};
    if(count <= 0)
        return std::nullopt;

    return static_cast<size_t>(count);
}

#else
static std::optional<size_t> AffinityCpuCount() { return std::nullopt; }
#endif

// Mirrors Go's adjustCgroupGOMAXPROCS.
size_t bsv::internal::LimitedCpuCount(const size_t availableCpus,
                                      const CpuBandwidth& bandwidth)
{
    if(bandwidth.IsUnlimited())
        return availableCpus;

    const auto cgroupCpus{std::max<uint64_t>(bandwidth.CpusNeeded(), MIN_CGROUP_CPUS)};
    return static_cast<size_t>(std::min<uint64_t>(cgroupCpus, availableCpus));
}

// The mask is the main thread's, whichever thread calls; where there is none,
// hardware_concurrency() stands in. Once the main thread has exited, the mask
// stays as it was then, but FindCgroupDir finds the calling thread's cgroup.
// Off Linux the cgroup files are not there, and no limit applies.
size_t bsv::internal::EffectiveCpuCount(const std::filesystem::path& cgroupRoot)
{
    const size_t availableCpus{
        std::max<size_t>(AffinityCpuCount().value_or(std::thread::hardware_concurrency()),
                         1)};
    return FindCgroupDir(cgroupRoot)
        .and_then(ReadCpuLimit)
        .transform([availableCpus](const CpuBandwidth& bandwidth)
                   { return LimitedCpuCount(availableCpus, bandwidth); })
        .value_or(availableCpus);
}
