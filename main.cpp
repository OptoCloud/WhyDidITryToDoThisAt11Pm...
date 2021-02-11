#include <iostream>

#include <vector>
#include <thread>
#include <filesystem>
#include <atomic>
#include <chrono>
#include <fstream>
#include <istream>
#include <cstring>

#include "openssl/sha.h"
#include "concurrentqueue/concurrentqueue.h"

void getFilesRecurse(const std::filesystem::path& rootPath, std::vector<std::filesystem::path>& pathsOut) {
    std::filesystem::directory_iterator directoryIterator(rootPath, std::filesystem::directory_options::skip_permission_denied);

    std::cout << "Scanning " << rootPath << "..." << std::endl;

    for (auto& directoryEntry : directoryIterator) {
        if (directoryEntry.is_directory()) {
            getFilesRecurse(directoryEntry.path(), pathsOut);
        }
        else if (directoryEntry.is_regular_file()) {
            try {
                pathsOut.push_back(directoryEntry.path());
            } catch (...) {}
        }
    }
}

struct FileInfo {
    std::filesystem::path path;
    std::size_t size;
    std::array<std::uint8_t, SHA256_DIGEST_LENGTH> hash;
};

std::atomic<std::size_t> accumSize = 0;
std::atomic<unsigned long> finishedThreadCount = 0;
moodycamel::ConcurrentQueue<FileInfo> results;

void sha256_hash_string (const std::array<std::uint8_t, SHA256_DIGEST_LENGTH>& hash, std::array<char, 65>& outputBuffer)
{
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(&outputBuffer[i * 2], "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

void hashFile(const std::filesystem::path& path, std::array<std::uint8_t, SHA256_DIGEST_LENGTH>& sha256Out)
{
    memset(sha256Out.data(), 0, sha256Out.size());

    auto size = std::filesystem::file_size(path);
    std::fstream file(path, std::ios::in | std::ios::binary);

    if (!file.is_open()) {
        throw std::string("Failed to open: ") + path.string();
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    std::array<std::uint8_t, 1024 * 1024 * 16> buffer;
    while (size != 0) {
        auto readSize = std::min(buffer.size(), size);

        file.read((char*)buffer.data(), readSize);
        SHA256_Update(&ctx, buffer.data(), readSize);

        size -= readSize;
    }

    SHA256_Final(sha256Out.data(), &ctx);
}

void hashingWorker(std::vector<std::filesystem::path> paths) {
    moodycamel::ProducerToken token(results);

    for (const auto& path : paths) {
        FileInfo fileInfo;
        fileInfo.path = path;
        fileInfo.size = std::filesystem::file_size(path);
        hashFile(path, fileInfo.hash);

        while (!results.enqueue(token, fileInfo)) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); }
    }

    finishedThreadCount.fetch_add(1, std::memory_order::relaxed);
}

int main(int argc, char** argv)
{
    /*
    if (argc != 2) {
        std::cout << "Invalid arg count" << std::endl;
        return EXIT_FAILURE;
    }
    */

    std::filesystem::path rootPath(".");//argv[1]);

    if (!std::filesystem::exists(rootPath)) {
        std::cout << "Invalid root directory" << std::endl;
        return EXIT_FAILURE;
    }

    unsigned int nproc = std::thread::hardware_concurrency() * 2;

    std::vector<std::filesystem::path> paths;
    getFilesRecurse(rootPath, paths);
    std::cout << "Found " << paths.size() << " files" << std::endl;

    auto filesPerThread = paths.size() / nproc;
    std::cout << "Allocating " << filesPerThread << " files per thread" << std::endl;

    std::vector<std::thread> workers;
    while (true) {
        auto pathsToInsert = (paths.size() < filesPerThread) ? paths.size() : filesPerThread;

        if (pathsToInsert == 0) {
            break;
        }

        auto it = paths.rbegin();
        workers.push_back(std::thread(hashingWorker, std::vector<std::filesystem::path>(it, it + pathsToInsert)));
        paths.resize(paths.size() - pathsToInsert);
    }

    FileInfo info;
    moodycamel::ConsumerToken token(results);
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (results.try_dequeue(info)) {
            std::array<char, 65> hashStr;
            sha256_hash_string(info.hash, hashStr);

            printf("name: %s\nsize: %lu\nhash: %s\n\n\n", info.path.c_str(), info.size, hashStr.data());

        } else if (finishedThreadCount.load(std::memory_order::relaxed) != workers.size()) {
            break;
        }
    }

    std::cout << "Stopping..." << std::endl;
    for (auto& worker : workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }

    return 0;
}
