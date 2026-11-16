#include <internal/file_io.hpp>

#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <string>

#include <fcntl.h>
#include <unistd.h>

#include <cfile_util.h>
#include <expected.h>

tl::expected<UniqueFileDescriptor, int> bsv::internal::OpenReadOnly(
    const std::filesystem::path& path)
{
    const int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if(fd < 0)
        return tl::unexpected{errno};

    return UniqueFileDescriptor{fd};
}

tl::expected<std::string, int> bsv::internal::ReadToEnd(const UniqueFileDescriptor& file)
{
    constexpr size_t CHUNK_SIZE = 4096;
    std::string content;
    for(;;)
    {
        const size_t size = content.size();
        content.resize(size + CHUNK_SIZE);
        const ssize_t bytes = read(file.Get(), content.data() + size, CHUNK_SIZE);
        if(bytes < 0)
            return tl::unexpected{errno};

        content.resize(size + static_cast<size_t>(bytes));
        if(bytes == 0)
            return content;
    }
}

tl::expected<std::string, int> bsv::internal::ReadUpTo(const UniqueFileDescriptor& file,
                                                       const size_t size)
{
    std::string content(size, '\0');
    const ssize_t bytes = pread(file.Get(), content.data(), size, 0);
    if(bytes < 0)
        return tl::unexpected{errno};

    content.resize(static_cast<size_t>(bytes));
    return content;
}
