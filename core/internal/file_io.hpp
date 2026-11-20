#pragma once

// Reads and writes through a file descriptor, with a failure as its errno, as
// std::errc, so each caller decides what it means.

#include <cstddef>
#include <filesystem>
#include <string>
#include <system_error>

#include <cfile_util.h>
#include <expected.h>

namespace bsv::internal
{
    tl::expected<UniqueFileDescriptor, std::errc> OpenReadOnly(
        const std::filesystem::path&);
    tl::expected<std::string, std::errc> ReadToEnd(const UniqueFileDescriptor&);
    tl::expected<std::string, std::errc> ReadUpTo(const UniqueFileDescriptor&,
                                                  size_t size);
    tl::expected<std::string, std::errc> ReadFile(const std::filesystem::path&);

    // file_too_large when the file is `limit` bytes or more.
    tl::expected<std::string, std::errc> ReadSmallFile(const std::filesystem::path&,
                                                       size_t limit);
}
