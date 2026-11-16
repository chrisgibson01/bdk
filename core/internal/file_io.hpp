#pragma once

// Internal to bdk_core and its tests, like cpu_limit.hpp. Reads and writes
// through a file descriptor, with a failure as its errno, so each caller
// decides what it means.

#include <cstddef>
#include <filesystem>
#include <string>

#include <cfile_util.h>
#include <expected.h>

namespace bsv::internal
{
    tl::expected<UniqueFileDescriptor, int> OpenReadOnly(const std::filesystem::path&);
    tl::expected<std::string, int> ReadToEnd(const UniqueFileDescriptor&);
    tl::expected<std::string, int> ReadUpTo(const UniqueFileDescriptor&, size_t size);
}
