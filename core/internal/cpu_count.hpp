#pragma once

// Internal to bdk_core and its tests. Not installed with the core headers
// (core/bdk-core-recipe.cmake leaves core/internal/ out of the install list)
// and not part of any language binding.

#include <internal/cgroup.hpp>

#include <cstddef>
#include <filesystem>
#include <optional>

namespace bsv::internal
{
    // The fewest CPUs a cgroup limit lowers the count to. One would leave the
    // pool no parallelism, and a quota under one CPU usually marks a bursty
    // workload, which can use more for short spells.
    constexpr size_t MIN_CGROUP_CPUS = 2;

    // `availableCpus` lowered to the CPUs `bandwidth` needs, but never below
    // MIN_CGROUP_CPUS by the limit; unchanged when `bandwidth` is unlimited.
    // Mirrors Go's adjustCgroupGOMAXPROCS.
    size_t LimitedCpuCount(size_t availableCpus, const CpuBandwidth& bandwidth);

    // CPUs before any cgroup limit: `affinityCpus`, else `hardwareConcurrency`;
    // at least 1.
    size_t AvailableCpuCount(std::optional<size_t> affinityCpus,
                             size_t hardwareConcurrency);

    // CPUs this process may use: on Linux the CPUs in the process's
    // sched_getaffinity mask (the main thread's, whichever thread calls; once
    // the main thread has exited, its mask as it was then), else
    // hardware_concurrency(); lowered by LimitedCpuCount to the cgroup limit
    // read under `cgroupRoot` ("/" on a live system; tests pass a temporary
    // root): the main thread's cgroup. Any FindCgroupDir or ReadCpuLimit error
    // applies no limit. Once the main thread has exited, the cgroup is the
    // calling thread's while the mask stays the main thread's, so a thread
    // moved to a cpu cgroup of its own then gets a count of its own.
    // At least 1. Reads the system on every call, so callers that need it often
    // should keep the result. Reading the mask allocates nothing; reading the
    // cgroup files throws std::bad_alloc when out of memory. Throws nothing else.
    size_t EffectiveCpuCount(const std::filesystem::path& cgroupRoot = "/");
}
