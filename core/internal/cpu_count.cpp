// CPUs available to this process, for sizing the input verification pool: the
// affinity mask, lowered to the CPU bandwidth limit of the process's cgroup.
// The rounding was checked against Go 1.26's runtime with a differential test.
// Known differences:
// - a cgroup limit that cgroup.cpp reports as an error (see its differences):
//   BDK applies no limit, where Go may apply one.
// - a quota / period whose double rounds to a whole number, which needs a
//   period above the kernel's maximum of 1 s or a limit above 2^31 CPUs: Go
//   rounds the double up; BDK divides the integers exactly.
// - a limit above 2^31 CPUs: Go converts it to int32, which is
//   platform-specific; BDK leaves the count unchanged, as such a limit could
//   not lower it anyway.
// - Go reads the cgroup files once and re-reads the limit and the affinity
//   mask periodically; BDK reads them on every EffectiveCpuCount call.

#include <internal/cpu_count.hpp>

#include <internal/cgroup.hpp>

#include <algorithm>
#include <array>
#include <climits>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <thread>

#include <unistd.h>

#if defined(__linux__) && !defined(__EMSCRIPTEN__)
#include <sched.h>
#endif

using namespace bsv::internal;

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

    return count > 0 ? std::optional<size_t>(static_cast<size_t>(count)) : std::nullopt;
}

#else
static std::optional<size_t> AffinityCpuCount() { return std::nullopt; }
#endif

size_t bsv::internal::LimitedCpuCount(const size_t availableCpus,
                                      const CpuBandwidth& bandwidth)
{
    if(bandwidth.IsUnlimited())
        return availableCpus;

    const auto cgroupCpus{std::max<uint64_t>(bandwidth.CpusNeeded(), MIN_CGROUP_CPUS)};
    return static_cast<size_t>(std::min<uint64_t>(cgroupCpus, availableCpus));
}

size_t bsv::internal::AvailableCpuCount(const std::optional<size_t> affinityCpus,
                                        const size_t hardwareConcurrency)
{
    return affinityCpus.value_or(std::max<size_t>(hardwareConcurrency, 1));
}

size_t bsv::internal::EffectiveCpuCount(const std::filesystem::path& cgroupRoot)
{
    const size_t availableCpus = AvailableCpuCount(AffinityCpuCount(),
                                                   std::thread::hardware_concurrency());
    return FindCgroupDir(cgroupRoot)
        .and_then(ReadCpuLimit)
        .transform([availableCpus](const CpuBandwidth& bandwidth)
                   { return LimitedCpuCount(availableCpus, bandwidth); })
        .value_or(availableCpus);
}
