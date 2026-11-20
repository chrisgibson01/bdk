#pragma once

// A temporary directory for tests that read files by path, such as a fake
// filesystem root.

#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <system_error>

namespace bsv::test
{
    // A new, empty directory under temp_directory_path(), removed with
    // everything below it on destruction.
    class TempRoot
    {
    public:
        TempRoot()
        {
            std::random_device random;
            do
                path_ = std::filesystem::temp_directory_path()
                      / ("bdk_test_" + std::to_string(random()));
            while(!std::filesystem::create_directory(path_));
        }

        ~TempRoot()
        {
            std::error_code ignored;
            std::filesystem::remove_all(path_, ignored);
        }

        TempRoot(const TempRoot&) = delete;
        TempRoot& operator=(const TempRoot&) = delete;
        TempRoot(TempRoot&&) = delete;
        TempRoot& operator=(TempRoot&&) = delete;

        [[nodiscard]] const std::filesystem::path& Path() const { return path_; }

        // Creates any missing parent directories.
        void Write(const std::filesystem::path& relative,
                   const std::string& content) const
        {
            const std::filesystem::path file = path_ / relative;
            std::filesystem::create_directories(file.parent_path());
            std::ofstream(file, std::ios::binary) << content;
        }

    private:
        std::filesystem::path path_;
    };
}
