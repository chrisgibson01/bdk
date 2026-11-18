#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <system_error>

#ifdef NDEBUG
#define BOOST_TEST_MODULE test_file_io
#else
#define BOOST_TEST_MODULE test_file_iod
#endif

#include <boost/test/unit_test.hpp>

#include <internal/file_io.hpp>

#include <expected.h>

namespace
{

    // A directory under the system's temporary directory, removed with it.
    class TempDir
    {
    public:
        TempDir()
        {
            std::random_device random;
            do
                path_ = std::filesystem::temp_directory_path()
                      / ("bdk_test_file_io_" + std::to_string(random()));
            while(!std::filesystem::create_directory(path_));
        }

        ~TempDir()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }

        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        TempDir(TempDir&&) = delete;
        TempDir& operator=(TempDir&&) = delete;

        [[nodiscard]] const std::filesystem::path& Path() const { return path_; }

        [[nodiscard]] std::filesystem::path Write(const std::filesystem::path& name,
                                                  const std::string& content) const
        {
            const std::filesystem::path file = path_ / name;
            std::ofstream(file, std::ios::binary) << content;
            return file;
        }

    private:
        std::filesystem::path path_;
    };

}

// The errno of a failed read, 0 for one that succeeded.
static int ErrorOf(const tl::expected<std::string, int>& result)
{
    return result ? 0 : result.error();
}

BOOST_AUTO_TEST_SUITE(file_io)

using bsv::internal::ReadFile;
using bsv::internal::ReadSmallFile;

// ReadFile reads past its first chunk to the end, and fails with open()'s or
// read()'s errno.
BOOST_AUTO_TEST_CASE(read_file_reads_to_the_end)
{
    const TempDir dir;
    const std::string large(10'000, 'x');
    BOOST_CHECK(large == ReadFile(dir.Write("large", large)).value_or(""));
    BOOST_CHECK_EQUAL("", ReadFile(dir.Write("empty", "")).value_or("error"));

    BOOST_CHECK_EQUAL(ENOENT, ErrorOf(ReadFile(dir.Path() / "missing")));
    std::filesystem::create_symlink("loop", dir.Path() / "loop");
    BOOST_CHECK_EQUAL(ELOOP, ErrorOf(ReadFile(dir.Path() / "loop")));
    // A directory opens, and its read fails.
    BOOST_CHECK_EQUAL(EISDIR, ErrorOf(ReadFile(dir.Path())));
}

// ReadSmallFile reads a file under its limit, and fails with EFBIG for one of
// the limit or more.
BOOST_AUTO_TEST_CASE(read_small_file_rejects_a_file_of_its_limit)
{
    constexpr size_t limit = 8;
    const TempDir dir;
    BOOST_CHECK_EQUAL("1234567",
                      ReadSmallFile(dir.Write("under", "1234567"), limit).value_or(""));
    BOOST_CHECK_EQUAL("", ReadSmallFile(dir.Write("empty", ""), limit).value_or("error"));
    BOOST_CHECK_EQUAL(EFBIG, ErrorOf(ReadSmallFile(dir.Write("at", "12345678"), limit)));
    BOOST_CHECK_EQUAL(EFBIG,
                      ErrorOf(ReadSmallFile(dir.Write("over", "123456789"), limit)));

    BOOST_CHECK_EQUAL(ENOENT, ErrorOf(ReadSmallFile(dir.Path() / "missing", limit)));
    BOOST_CHECK_EQUAL(EISDIR, ErrorOf(ReadSmallFile(dir.Path(), limit)));
}

BOOST_AUTO_TEST_SUITE_END()
