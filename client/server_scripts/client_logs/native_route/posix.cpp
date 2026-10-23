#include "route.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <poll.h>
#include <openssl/evp.h>
#include <set>
#include <signal.h>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
namespace collector_route
{
    namespace
    {
        struct Fd
        {
            int n { -1 };
            explicit Fd(int v) : n(v)
            {
                if (n < 0)
                    throw Failure("file open refused");
            }
            ~Fd()
            {
                if (n >= 0)
                    ::close(n);
            }
            Fd(const Fd &) = delete;
            Fd &operator=(const Fd &) = delete;
        };
        void metadata(int fd, unsigned uid, bool directory = false)
        {
            struct stat s { };
            if (fstat(fd, &s) || s.st_uid != uid || (s.st_mode & 0077)
                || (directory ? !S_ISDIR(s.st_mode) : !S_ISREG(s.st_mode)))
                throw Failure("metadata ownership");
        }
        std::string readBound(int fd)
        {
            std::string b(4097, '\0');
            std::size_t n = 0;
            while (n < b.size()) {
                ssize_t k = ::read(fd, b.data() + n, b.size() - n);
                if (k < 0) {
                    if (errno == EINTR)
                        continue;
                    throw Failure("metadata read");
                }
                if (!k)
                    break;
                n += std::size_t(k);
            }
            b.resize(n);
            if (n > 4096)
                throw Failure("metadata size");
            return b;
        }
        void writeAll(int fd, const std::string &s)
        {
            std::size_t n = 0;
            while (n < s.size()) {
                auto k = ::write(fd, s.data() + n, s.size() - n);
                if (k < 0 && errno == EINTR)
                    continue;
                if (k <= 0)
                    throw Failure("binding write");
                n += std::size_t(k);
            }
        }
    }
    Result PosixAdapter::run(const Args &args)
    {
        if (args.empty())
            throw Failure("empty Docker command");
        struct stat binary { };
        if (stat("/usr/bin/docker", &binary) || !S_ISREG(binary.st_mode) || binary.st_uid != 0 || (binary.st_mode & 0022))
            throw Failure("Docker executable ownership");
        int fds[2];
        if (pipe2(fds, O_CLOEXEC))
            throw Failure("command pipe");
        Fd input(fds[0]), output(fds[1]);
        pid_t child = fork();
        if (child < 0)
            throw Failure("command fork");
        if (child == 0) {
            int null = open("/dev/null", O_RDONLY);
            if (null < 0 || dup2(null, STDIN_FILENO) < 0 || dup2(output.n, STDOUT_FILENO) < 0
                || dup2(output.n, STDERR_FILENO) < 0)
                _exit(126);
            close(input.n);
            close(output.n);
            if (null > 2)
                close(null);
            std::vector<char *> argv;
            argv.push_back(const_cast<char *>("/usr/bin/docker"));
            for (const auto &x : args)
                argv.push_back(const_cast<char *>(x.c_str()));
            argv.push_back(nullptr);
            execv(argv[0], argv.data());
            _exit(127);
        }
        ::close(output.n);
        output.n = -1;
        int flags = fcntl(input.n, F_GETFL);
        if (flags < 0 || fcntl(input.n, F_SETFL, flags | O_NONBLOCK) < 0) {
            kill(child, SIGKILL);
            waitpid(child, nullptr, 0);
            throw Failure("command flags");
        }
        const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        std::string out;
        bool eof = false, done = false;
        int status = 0;
        try {
            while (!eof || !done) {
                if (std::chrono::steady_clock::now() >= end)
                    throw Failure("Docker timeout");
                char b[8192];
                for (;;) {
                    auto n = ::read(input.n, b, sizeof b);
                    if (n > 0) {
                        out.append(b, std::size_t(n));
                        if (out.size() > 1024 * 1024)
                            throw Failure("Docker output bound");
                    } else if (n == 0) {
                        eof = true;
                        break;
                    } else if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                    else if (errno != EINTR)
                        throw Failure("Docker pipe read");
                }
                if (!done) {
                    auto n = waitpid(child, &status, WNOHANG);
                    if (n == child)
                        done = true;
                    else if (n < 0 && errno != EINTR)
                        throw Failure("Docker wait");
                }
                if (!done || !eof) {
                    pollfd p { input.n, POLLIN, 0 };
                    poll(&p, 1, 20);
                }
            }
        } catch (...) {
            if (!done) {
                kill(child, SIGKILL);
                while (waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
                }
            }
            throw;
        }
        return { WIFEXITED(status) ? WEXITSTATUS(status) : 128, out };
    }
    std::string PosixAdapter::netns(const Container &c)
    {
        if (!c.running || c.pid <= 0)
            return { };
        auto path = procRoot_ + "/" + std::to_string(c.pid) + "/ns/net";
        std::array<char, 256> b { };
        auto n = readlink(path.c_str(), b.data(), b.size());
        if (n <= 0 || std::size_t(n) >= b.size())
            throw Failure("namespace read");
        return std::string(b.data(), std::size_t(n));
    }
    bool PosixAdapter::listener(const Container &c)
    {
        if (!c.running || c.pid <= 0)
            return false;
        const auto prefix = procRoot_ + "/" + std::to_string(c.pid);
        auto readFile = [](const std::string &path, std::size_t limit) {
            Fd f(open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
            std::string result;
            char buf[8192];
            for (;;) {
                auto n = read(f.n, buf, sizeof buf);
                if (n < 0 && errno == EINTR)
                    continue;
                if (n < 0)
                    throw Failure("proc read");
                if (!n)
                    break;
                result.append(buf, std::size_t(n));
                if (result.size() > limit)
                    throw Failure("proc size");
            }
            return result;
        };
        const auto command = readFile(prefix + "/cmdline", 65536);
        if (c.nativeProcess) {
            const std::string expected = std::string("/data/amnezia-client-logs-collector") + '\0' + "--root" + '\0' + "/data" + '\0';
            if (command != expected)
                return false;
            // /proc/PID/exe is a kernel-provided reference to the loaded inode,
            // deliberately followed even after an atomic replacement of the data file.
            Fd executable(open((prefix + "/exe").c_str(), O_RDONLY | O_CLOEXEC));
            struct stat before {}, after {};
            if (fstat(executable.n, &before) || !S_ISREG(before.st_mode) || before.st_size <= 0 || before.st_size > 64 * 1024 * 1024)
                return false;
            std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            if (!digest || EVP_DigestInit_ex(digest.get(), EVP_sha256(), nullptr) != 1)
                throw Failure("binary hash init");
            char bytes[65536];
            for (;;) {
                auto n = read(executable.n, bytes, sizeof bytes);
                if (n < 0 && errno == EINTR) continue;
                if (n < 0) throw Failure("binary hash read");
                if (!n) break;
                if (EVP_DigestUpdate(digest.get(), bytes, std::size_t(n)) != 1)
                    throw Failure("binary hash update");
            }
            unsigned char value[EVP_MAX_MD_SIZE]; unsigned length = 0;
            if (EVP_DigestFinal_ex(digest.get(), value, &length) != 1 || length != 32
                || fstat(executable.n, &after) || before.st_size != after.st_size
                || before.st_mtim.tv_sec != after.st_mtim.tv_sec || before.st_mtim.tv_nsec != after.st_mtim.tv_nsec
                || before.st_ctim.tv_sec != after.st_ctim.tv_sec || before.st_ctim.tv_nsec != after.st_ctim.tv_nsec)
                return false;
            std::string actual;
            for (unsigned i = 0; i < length; ++i) {
                actual += "0123456789abcdef"[value[i] >> 4];
                actual += "0123456789abcdef"[value[i] & 15];
            }
            if (actual != c.nativeSha256) return false;
        }
        bool owned = c.nativeProcess;
        std::size_t offset = 0;
        while (offset < command.size()) {
            auto end = command.find('\0', offset);
            if (end == std::string::npos)
                return false;
            if (command.substr(offset, end - offset) == "/data/collector.py")
                owned = true;
            offset = end + 1;
        }
        if (!owned)
            return false;
        std::set<std::string> sockets;
        std::size_t count = 0;
        for (const auto &entry : std::filesystem::directory_iterator(prefix + "/fd")) {
            if (++count > 16384)
                throw Failure("proc fd bound");
            const auto name = entry.path().filename().string();
            if (name.empty()
                || !std::all_of(name.begin(), name.end(), [](unsigned char x) { return x >= '0' && x <= '9'; }))
                continue;
            char link[256];
            auto size = readlink(entry.path().c_str(), link, sizeof link);
            if (size < 0) {
                if (errno == ENOENT)
                    continue;
                throw Failure("proc fd read");
            }
            if (std::size_t(size) >= sizeof link)
                throw Failure("proc fd size");
            std::string value(link, std::size_t(size));
            if (value.size() > 9 && value.compare(0, 8, "socket:[") == 0 && value.back() == ']') {
                auto inode = value.substr(8, value.size() - 9);
                if (std::all_of(inode.begin(), inode.end(), [](unsigned char x) { return x >= '0' && x <= '9'; }))
                    sockets.insert(inode);
            }
        }
        std::istringstream tcp(readFile(prefix + "/net/tcp", 1024 * 1024));
        std::string line;
        std::getline(tcp, line);
        while (std::getline(tcp, line)) {
            std::istringstream row(line);
            std::vector<std::string> fields;
            std::string x;
            while (row >> x) {
                if (fields.size() >= 32)
                    throw Failure("proc tcp fields");
                fields.push_back(x);
            }
            if (fields.size() > 9 && fields[1] == "00000000:45CA" && fields[3] == "0A" && sockets.count(fields[9]))
                return true;
        }
        return false;
    }
    void PosixAdapter::pause()
    {
        sleep(1);
    }
    void cli(Adapter &a, const Args &args, const std::string &root, unsigned trustedUid)
    {
        if (geteuid() != trustedUid || args.empty() || args.size() > 2)
            throw Failure("scope");
        Binding seed { args[0], std::string(64, 'a'), std::string(64, 'b') };
        binding(canonical(seed));
        if (args.size() == 2 && args[1] == "--publication-preflight") {
            publicationPreflight(a, args[0], root);
            return;
        }
        bool bind = args.size() == 2;
        if (bind && args[1] != "--bind")
            throw Failure("operation");
        Fd directory(open(root.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW));
        metadata(directory.n, trustedUid, true);
        const auto stem = "route-" + args[0];
        Fd lock(openat(directory.n, (stem + ".lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600));
        metadata(lock.n, trustedUid);
        if (flock(lock.n, LOCK_EX | LOCK_NB))
            throw Failure("already locked");
        if (bind) {
            auto source = a.run({ "inspect", args[0] }),
                 collector = a.run({ "inspect", collectorName(args[0]) });
            if (source.code || collector.code)
                throw Failure("binding inspect");
            auto s = inspectDocument(source.output, args[0], root), c = inspectDocument(collector.output, args[0], root);
            Binding b { args[0], s.id, c.id };
            validate(s, c, b);
            reconcile(a, b, root);
            const auto tmp = stem + ".tmp", file = stem + ".json";
            Fd f(openat(directory.n, tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
            try {
                writeAll(f.n, canonical(b));
                if (fsync(f.n))
                    throw Failure("binding fsync");
                if (renameat(directory.n, tmp.c_str(), directory.n, file.c_str()))
                    throw Failure("binding replace");
                if (fsync(directory.n))
                    throw Failure("directory fsync");
            } catch (...) {
                unlinkat(directory.n, tmp.c_str(), 0);
                throw;
            }
        } else {
            Fd f(openat(directory.n, (stem + ".json").c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
            metadata(f.n, trustedUid);
            const auto stored = binding(readBound(f.n));
            if (stored.scope != args[0])
                throw Failure("binding scope mismatch");
            reconcile(a, stored, root);
        }
    }
}
