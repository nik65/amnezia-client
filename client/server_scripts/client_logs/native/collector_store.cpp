#include "collector_store.h"
#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <sstream>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>
namespace amnezia::collector
{
    namespace
    {
        namespace fs = std::filesystem;
        using Clock = std::chrono::system_clock;
        std::int64_t now_seconds()
        {
            return std::chrono::duration_cast<std::chrono::seconds>(Clock::now().time_since_epoch()).count();
        }
        double steady()
        {
            return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
        }
        void require(bool condition, const char *message)
        {
            if (!condition)
                throw std::runtime_error(message);
        }
        struct Fd
        {
            int value = -1;
            explicit Fd(int v) : value(v)
            {
                require(v >= 0, "file open failed");
            }
            ~Fd()
            {
                if (value >= 0)
                    ::close(value);
            }
            Fd(const Fd &) = delete;
            Fd &operator=(const Fd &) = delete;
        };
        void check_path(const fs::path &path, bool missing = false)
        {
            fs::path current;
            for (const auto &part : fs::absolute(path)) {
                current /= part;
                struct stat st { };
                if (::lstat(current.c_str(), &st) != 0) {
                    if (missing && errno == ENOENT)
                        return;
                    throw std::runtime_error("path unavailable");
                }
                require(!S_ISLNK(st.st_mode), "symlink path rejected");
            }
        }
        void directory(const fs::path &path)
        {
            check_path(path, true);
            fs::create_directories(path);
            check_path(path);
            require(fs::is_directory(path), "directory required");
            require(::chmod(path.c_str(), 0700) == 0, "directory mode failed");
        }
        void sync_directory(const fs::path &path)
        {
            check_path(path);
            Fd fd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            require(::fsync(fd.value) == 0, "directory fsync failed");
        }
        struct FileLock
        {
            Fd fd;
            explicit FileLock(const fs::path &path)
                : fd((check_path(path, true), ::open(path.c_str(), O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600)))
            {
                struct stat st { };
                require(::fstat(fd.value, &st) == 0 && S_ISREG(st.st_mode), "regular lock file required");
                require(::fchmod(fd.value, 0600) == 0, "lock mode failed");
                require(::flock(fd.value, LOCK_EX) == 0, "filesystem lock failed");
            }
            ~FileLock()
            {
                ::flock(fd.value, LOCK_UN);
            }
        };
        std::string random_hex(std::size_t n = 16)
        {
            std::vector<unsigned char> bytes(n);
            require(RAND_bytes(bytes.data(), int(n)) == 1, "secure randomness failed");
            std::ostringstream out;
            for (auto b : bytes)
                out << std::hex << std::setw(2) << std::setfill('0') << unsigned(b);
            return out.str();
        }
        std::string random_token()
        {
            std::array<unsigned char, 36> bytes { };
            require(RAND_bytes(bytes.data(), bytes.size()) == 1, "secure randomness failed");
            std::array<unsigned char, 49> encoded { };
            require(EVP_EncodeBlock(encoded.data(), bytes.data(), bytes.size()) == 48, "token encoding failed");
            std::string token(reinterpret_cast<char *>(encoded.data()), 48);
            std::replace(token.begin(), token.end(), '+', '-');
            std::replace(token.begin(), token.end(), '/', '_');
            return token;
        }
        std::string sha256(const std::string &bytes)
        {
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int size = 0;
            require(EVP_Digest(bytes.data(), bytes.size(), hash, &size, EVP_sha256(), nullptr) == 1 && size == 32,
                    "digest failed");
            std::ostringstream out;
            for (unsigned i = 0; i < size; ++i)
                out << std::hex << std::setw(2) << std::setfill('0') << unsigned(hash[i]);
            return out.str();
        }
        bool digest_id(const std::string &value)
        {
            return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == std::string::npos;
        }
        bool safe_installation(const std::string &s)
        {
            return !s.empty() && s.size() <= 80 && std::all_of(s.begin(), s.end(), [](unsigned char c) {
                return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'
                        || c == '.' || c == '-';
            });
        }
        bool token_valid(const std::string &s)
        {
            return !s.empty() && s.size() <= 512
                    && std::all_of(s.begin(), s.end(), [](unsigned char c) { return c > 0 && c < 128; });
        }
        bool equal_secret(const std::string &a, const std::string &b)
        {
            return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
        }
        std::string header(const HttpRequest &request, const std::string &key, const std::string &fallback = "")
        {
            auto i = request.headers.find(key);
            return i == request.headers.end() ? fallback : i->second;
        }
        std::vector<std::string> split(const std::string &s, char delimiter)
        {
            std::vector<std::string> fields;
            std::size_t at = 0;
            for (;;) {
                auto end = s.find(delimiter, at);
                fields.push_back(s.substr(at, end == std::string::npos ? end : end - at));
                if (end == std::string::npos)
                    return fields;
                at = end + 1;
            }
        }
        std::string read_stable(const fs::path &path, bool missing = false)
        {
            for (int attempt = 0; attempt < 3; ++attempt) {
                check_path(path, missing);
                struct stat before { };
                if (::lstat(path.c_str(), &before) != 0) {
                    if (missing && errno == ENOENT)
                        return { };
                    throw std::runtime_error("input unavailable");
                }
                require(S_ISREG(before.st_mode) && before.st_size <= 16 * 1024 * 1024, "regular bounded input required");
                Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
                struct stat opened { };
                require(::fstat(fd.value, &opened) == 0, "stat failed");
                if (opened.st_ino != before.st_ino || opened.st_dev != before.st_dev)
                    continue;
                std::string result;
                std::array<char, 65536> buffer { };
                for (;;) {
                    ssize_t n = ::read(fd.value, buffer.data(), buffer.size());
                    if (n < 0 && errno == EINTR)
                        continue;
                    require(n >= 0, "read failed");
                    if (!n)
                        break;
                    result.append(buffer.data(), std::size_t(n));
                    require(result.size() <= 16 * 1024 * 1024, "input too large");
                }
                struct stat after { }, current { };
                require(::fstat(fd.value, &after) == 0, "stat failed");
                if (::lstat(path.c_str(), &current) == 0 && before.st_ino == current.st_ino
                    && before.st_dev == current.st_dev && before.st_size == after.st_size
                    && after.st_size == current.st_size && before.st_mtim.tv_sec == after.st_mtim.tv_sec
                    && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && after.st_mtim.tv_sec == current.st_mtim.tv_sec
                    && after.st_mtim.tv_nsec == current.st_mtim.tv_nsec)
                    return result;
            }
            throw std::runtime_error("input changed while reading");
        }
        std::pair<std::string, std::int64_t> file_metadata(const fs::path &path, std::uint64_t maximum)
        {
            check_path(path);
            struct stat before { }, opened { }, after { }, current { };
            require(::lstat(path.c_str(), &before) == 0 && S_ISREG(before.st_mode) && before.st_size > 0
                            && std::uint64_t(before.st_size) <= maximum,
                    "bounded log required");
            Fd fd(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
            require(::fstat(fd.value, &opened) == 0 && S_ISREG(opened.st_mode) && before.st_dev == opened.st_dev
                            && before.st_ino == opened.st_ino,
                    "log identity changed");
            std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            require(context && EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr) == 1, "digest init failed");
            std::array<char, 65536> buffer { };
            std::uint64_t size = 0;
            for (;;) {
                auto count = ::read(fd.value, buffer.data(), buffer.size());
                if (count < 0 && errno == EINTR)
                    continue;
                require(count >= 0, "log read failed");
                if (!count)
                    break;
                size += std::uint64_t(count);
                require(size <= maximum && EVP_DigestUpdate(context.get(), buffer.data(), count) == 1,
                        "log digest failed");
            }
            require(::fstat(fd.value, &after) == 0 && ::lstat(path.c_str(), &current) == 0 && S_ISREG(current.st_mode)
                            && before.st_dev == current.st_dev && before.st_ino == current.st_ino
                            && before.st_size == after.st_size && after.st_size == current.st_size
                            && size == std::uint64_t(after.st_size) && before.st_mtim.tv_sec == after.st_mtim.tv_sec
                            && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec
                            && after.st_mtim.tv_sec == current.st_mtim.tv_sec
                            && after.st_mtim.tv_nsec == current.st_mtim.tv_nsec,
                    "log changed while hashing");
            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned length = 0;
            require(EVP_DigestFinal_ex(context.get(), digest, &length) == 1 && length == 32, "digest failed");
            std::ostringstream hex;
            for (unsigned i = 0; i < length; ++i)
                hex << std::hex << std::setw(2) << std::setfill('0') << unsigned(digest[i]);
            return { hex.str(), std::int64_t(size) };
        }
        void write_atomic(const fs::path &target, const std::string &bytes)
        {
            check_path(target, true);
            auto temp = target.string() + ".tmp-" + random_hex();
            try {
                Fd fd(::open(temp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600));
                std::size_t offset = 0;
                while (offset < bytes.size()) {
                    auto n = ::write(fd.value, bytes.data() + offset, bytes.size() - offset);
                    if (n < 0 && errno == EINTR)
                        continue;
                    require(n > 0, "write failed");
                    offset += std::size_t(n);
                }
                require(::fsync(fd.value) == 0, "file fsync failed");
                check_path(target, true);
                require(::rename(temp.c_str(), target.c_str()) == 0, "atomic rename failed");
                sync_directory(target.parent_path());
            } catch (...) {
                ::unlink(temp.c_str());
                throw;
            }
        }
        std::vector<std::vector<std::string>> rows(const fs::path &p, bool missing = true)
        {
            std::vector<std::vector<std::string>> result;
            std::istringstream lines(read_stable(p, missing));
            std::string line;
            while (std::getline(lines, line))
                result.push_back(split(line, '\t'));
            return result;
        }
        std::map<std::string, std::string> tokens(const fs::path &root, bool strict = false)
        {
            std::map<std::string, std::string> result;
            for (const auto &row : rows(root / "tokens.tsv", !strict)) {
                if (row.size() == 1 && row[0].empty())
                    continue;
                if (strict)
                    require(row.size() == 2 && digest_id(row[0]) && token_valid(row[1]), "invalid token map");
                if (row.size() >= 2 && !row[0].empty() && !row[1].empty())
                    result[row[0]] = row[1];
            }
            return result;
        }
        // Authentication must not materialize an operator-controlled token map per
        // request. Keep only three bounded fields, even for a single 16 MiB row.
        template<class State, class Visit>
        State scan_auth_rows(const fs::path &path, Visit visit, bool missing = true)
        {
            constexpr std::size_t maximum = 16 * 1024 * 1024;
            for (int attempt = 0; attempt < 3; ++attempt) {
                check_path(path, missing);
                struct stat before { }, opened { }, after { }, current { };
                if (::lstat(path.c_str(), &before) != 0) {
                    if (missing && errno == ENOENT)
                        return State { };
                    throw std::runtime_error("input unavailable");
                }
                require(S_ISREG(before.st_mode) && before.st_size >= 0
                                && std::uint64_t(before.st_size) <= maximum, "regular bounded input required");
                Fd fd(::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC));
                require(::fstat(fd.value, &opened) == 0, "stat failed");
                require(S_ISREG(opened.st_mode) && opened.st_size >= 0
                                && std::uint64_t(opened.st_size) <= maximum, "regular bounded input required");
                if (opened.st_ino != before.st_ino || opened.st_dev != before.st_dev)
                    continue;
                State result { };
                std::array<std::string, 3> fields;
                std::size_t column = 0, size = 0;
                bool pending = false;
                auto row = [&] {
                    visit(result, fields, column + 1);
                    for (auto &field : fields)
                        field.clear();
                    column = 0;
                    pending = false;
                };
                std::array<char, 65536> buffer { };
                for (;;) {
                    auto n = ::read(fd.value, buffer.data(), buffer.size());
                    if (n < 0 && errno == EINTR)
                        continue;
                    require(n >= 0, "read failed");
                    if (!n)
                        break;
                    size += std::size_t(n);
                    require(size <= maximum, "input too large");
                    for (ssize_t i = 0; i < n; ++i) {
                        char c = buffer[std::size_t(i)];
                        if (c == '\n') {
                            row();
                        } else {
                            pending = true;
                            if (c == '\t')
                                column = std::min<std::size_t>(column + 1, 3);
                            else if (column < fields.size() && fields[column].size() < 513)
                                fields[column] += c;
                        }
                    }
                }
                if (pending)
                    row();
                require(::fstat(fd.value, &after) == 0, "stat failed");
                if (::lstat(path.c_str(), &current) == 0 && S_ISREG(current.st_mode)
                    && before.st_ino == current.st_ino && before.st_dev == current.st_dev
                    && before.st_size == after.st_size && after.st_size == current.st_size
                    && size == std::uint64_t(after.st_size)
                    && before.st_mtim.tv_sec == after.st_mtim.tv_sec
                    && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec
                    && after.st_mtim.tv_sec == current.st_mtim.tv_sec
                    && after.st_mtim.tv_nsec == current.st_mtim.tv_nsec
                    && before.st_ctim.tv_sec == after.st_ctim.tv_sec
                    && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec
                    && after.st_ctim.tv_sec == current.st_ctim.tv_sec
                    && after.st_ctim.tv_nsec == current.st_ctim.tv_nsec)
                    return result;
            }
            throw std::runtime_error("input changed while reading");
        }
        std::string json_escape(const std::string &s)
        {
            std::ostringstream o;
            for (unsigned char c : s) {
                if (c == '"' || c == '\\')
                    o << '\\' << char(c);
                else if (c < 0x20 || c > 0x7e)
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << unsigned(c);
                else
                    o << char(c);
            }
            return o.str();
        }
        struct Db
        {
            sqlite3 *db = nullptr;
            explicit Db(const fs::path &root)
            {
                auto path = root / "batch-receipts.sqlite3";
                check_path(path, true);
                int opened = sqlite3_open_v2(
                        path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
                if (opened != SQLITE_OK) {
                    if (db)
                        sqlite3_close(db);
                    db = nullptr;
                    throw std::runtime_error("receipt database open failed");
                }
                try {
                    sqlite3_busy_timeout(db, 30000);
                    exec("PRAGMA synchronous=FULL");
                    exec("BEGIN IMMEDIATE");
                    exec("CREATE TABLE IF NOT EXISTS batch_receipts(client_id TEXT NOT NULL,batch_id TEXT NOT "
                         "NULL,accepted_at INTEGER NOT NULL,body_sha256 TEXT,body_length INTEGER,PRIMARY "
                         "KEY(client_id,batch_id))");
                    sqlite3_stmt *s = nullptr;
                    require(sqlite3_prepare_v2(db, "PRAGMA table_info(batch_receipts)", -1, &s, nullptr) == SQLITE_OK,
                            "schema inspect failed");
                    bool hash = false, length = false;
                    while (sqlite3_step(s) == SQLITE_ROW) {
                        std::string name = reinterpret_cast<const char *>(sqlite3_column_text(s, 1));
                        hash |= name == "body_sha256";
                        length |= name == "body_length";
                    }
                    sqlite3_finalize(s);
                    if (!hash)
                        exec("ALTER TABLE batch_receipts ADD COLUMN body_sha256 TEXT");
                    if (!length)
                        exec("ALTER TABLE batch_receipts ADD COLUMN body_length INTEGER");
                    exec("CREATE TABLE IF NOT EXISTS collector_health(singleton INTEGER PRIMARY KEY "
                         "CHECK(singleton=1),touched_at INTEGER NOT NULL)");
                    exec("CREATE INDEX IF NOT EXISTS batch_receipts_age ON batch_receipts(accepted_at)");
                    exec("CREATE INDEX IF NOT EXISTS batch_receipts_client_age ON batch_receipts(client_id,accepted_at "
                         "DESC)");
                    exec("COMMIT");
                    require(::chmod(path.c_str(), 0600) == 0, "database mode failed");
                    sync_directory(root);
                } catch (...) {
                    sqlite3_close(db);
                    db = nullptr;
                    throw;
                }
            }
            ~Db()
            {
                if (db)
                    sqlite3_close(db);
            }
            void exec(const std::string &sql)
            {
                char *message = nullptr;
                int rc = sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &message);
                sqlite3_free(message);
                require(rc == SQLITE_OK, "receipt database operation failed");
            }
        };
        struct Statement
        {
            sqlite3_stmt *s = nullptr;
            Statement(Db &db, const char *sql)
            {
                require(sqlite3_prepare_v2(db.db, sql, -1, &s, nullptr) == SQLITE_OK, "receipt statement failed");
            }
            ~Statement()
            {
                sqlite3_finalize(s);
            }
            void text(int i, const std::string &v)
            {
                require(sqlite3_bind_text(s, i, v.c_str(), int(v.size()), SQLITE_TRANSIENT) == SQLITE_OK,
                        "receipt binding failed");
            }
            void integer(int i, std::int64_t v)
            {
                require(sqlite3_bind_int64(s, i, v) == SQLITE_OK, "receipt binding failed");
            }
            void done()
            {
                require(sqlite3_step(s) == SQLITE_DONE, "receipt commit failed");
            }
        };
        struct Metadata
        {
            bool found = false, bound = false;
            std::string hash;
            std::int64_t size = 0;
        };
        Metadata receipt(Db &db, const std::string &client, const std::string &batch)
        {
            Statement s(db,
                        "SELECT body_sha256,body_length FROM batch_receipts WHERE client_id=? AND batch_id=? LIMIT 1");
            s.text(1, client);
            s.text(2, batch);
            int rc = sqlite3_step(s.s);
            require(rc == SQLITE_ROW || rc == SQLITE_DONE, "receipt lookup failed");
            Metadata m;
            if (rc == SQLITE_ROW) {
                m.found = true;
                m.bound = sqlite3_column_type(s.s, 0) != SQLITE_NULL && sqlite3_column_type(s.s, 1) != SQLITE_NULL;
                if (m.bound) {
                    m.hash = reinterpret_cast<const char *>(sqlite3_column_text(s.s, 0));
                    m.size = sqlite3_column_int64(s.s, 1);
                }
            }
            return m;
        }
        void record(Db &db, const CollectorOptions &o, const std::string &client, const std::string &batch,
                    const std::string &hash, std::size_t size)
        {
            db.exec("BEGIN IMMEDIATE");
            try {
                Statement s(
                        db, "INSERT OR IGNORE INTO batch_receipts(client_id,batch_id,accepted_at,body_sha256,body_length) VALUES(?,?,?,?,?)");
                s.text(1, client);
                s.text(2, batch);
                s.integer(3, now_seconds());
                s.text(4, hash);
                s.integer(5, size);
                s.done();
                Statement u(db,
                            "UPDATE batch_receipts SET body_sha256=?,body_length=? WHERE client_id=? AND batch_id=? "
                            "AND(body_sha256 IS NULL OR body_length IS NULL)");
                u.text(1, hash);
                u.integer(2, size);
                u.text(3, client);
                u.text(4, batch);
                u.done();
                Statement p(db,
                            "DELETE FROM batch_receipts WHERE rowid IN(SELECT rowid FROM batch_receipts WHERE "
                            "client_id=? ORDER BY accepted_at DESC,rowid DESC LIMIT -1 OFFSET ?)");
                p.text(1, client);
                p.integer(2, o.client_receipts);
                p.done();
                db.exec("COMMIT");
            } catch (...) {
                db.exec("ROLLBACK");
                throw;
            }
            static std::atomic<unsigned> receipt_records { 0 };
            if ((receipt_records.fetch_add(1) + 1) % 256 == 0) {
                db.exec("BEGIN IMMEDIATE");
                try {
                    Statement age(db, "DELETE FROM batch_receipts WHERE accepted_at<?");
                    age.integer(1, now_seconds() - o.receipt_age);
                    age.done();
                    Statement cap(db,
                                  "DELETE FROM batch_receipts WHERE rowid IN(SELECT rowid FROM batch_receipts ORDER BY "
                                  "accepted_at DESC,rowid DESC LIMIT -1 OFFSET ?)");
                    cap.integer(1, o.total_receipts);
                    cap.done();
                    db.exec("COMMIT");
                } catch (...) {
                    db.exec("ROLLBACK");
                    throw;
                }
            }
        }
        struct Entry
        {
            std::int64_t sec, nsec;
            fs::path path;
            std::uint64_t size;
        };
        std::vector<Entry> log_files(const fs::path &dir, bool recurse)
        {
            std::vector<Entry> result;
            check_path(dir, true);
            if (!fs::exists(dir))
                return result;
            for (const auto &e : fs::directory_iterator(dir)) {
                auto status = e.symlink_status();
                if (fs::is_symlink(status))
                    continue;
                if (recurse && fs::is_directory(status)) {
                    auto child = log_files(e.path(), false);
                    result.insert(result.end(), child.begin(), child.end());
                } else if (fs::is_regular_file(status) && e.path().extension() == ".log") {
                    struct stat st { };
                    if (::lstat(e.path().c_str(), &st) == 0)
                        result.push_back({ st.st_mtim.tv_sec, st.st_mtim.tv_nsec, e.path(), std::uint64_t(st.st_size) });
                }
            }
            std::sort(result.begin(), result.end(), [](const Entry &a, const Entry &b) {
                return std::tie(a.sec, a.nsec, a.path) < std::tie(b.sec, b.nsec, b.path);
            });
            return result;
        }
        void remove_log(const Entry &e)
        {
            if (::unlink(e.path.c_str()) != 0 && errno != ENOENT)
                throw std::runtime_error("log prune failed");
            sync_directory(e.path.parent_path());
        }
        bool reserve(const CollectorOptions &o, std::uint64_t bytes = 0, std::uint64_t count = 0)
        {
            if (bytes > o.total_bytes || count > o.total_files)
                return false;
            auto files = log_files(o.root / "logs", true);
            std::uint64_t total = 0, remaining = 0;
            std::vector<Entry> retained;
            for (const auto &e : files) {
                if (e.sec < now_seconds() - o.log_age)
                    remove_log(e);
                else {
                    retained.push_back(e);
                    total += e.size;
                    ++remaining;
                }
            }
            for (const auto &e : retained) {
                if (total <= o.total_bytes - bytes && remaining <= o.total_files - count)
                    break;
                remove_log(e);
                total -= e.size;
                --remaining;
            }
            auto logs = o.root / "logs";
            for (const auto &d : fs::directory_iterator(logs)) {
                if (!fs::is_directory(d.symlink_status()))
                    continue;
                for (const auto &e : fs::directory_iterator(d.path())) {
                    if (!fs::is_regular_file(e.symlink_status()))
                        continue;
                    auto name = e.path().filename().string();
                    if (name.find(".tmp-") == std::string::npos
                        && (name.size() < 4 || name.substr(name.size() - 4) != ".tmp"))
                        continue;
                    struct stat st { };
                    if (::lstat(e.path().c_str(), &st) == 0 && st.st_mtim.tv_sec < now_seconds() - o.tmp_age) {
                        require(::unlink(e.path().c_str()) == 0, "tmp prune failed");
                        sync_directory(d.path());
                    }
                }
            }
            return total <= o.total_bytes - bytes && remaining <= o.total_files - count;
        }
        void prune_client(const CollectorOptions &o, const fs::path &dir)
        {
            auto files = log_files(dir, false);
            std::uint64_t bytes = 0, count = files.size();
            for (const auto &e : files)
                bytes += e.size;
            for (const auto &e : files) {
                if (bytes <= o.client_bytes && count <= o.client_files)
                    break;
                remove_log(e);
                bytes -= e.size;
                --count;
            }
        }
        HttpResponse response(int status)
        {
            HttpResponse r;
            r.status = status;
            r.headers["Cache-Control"] = "no-store";
            return r;
        }
        HttpResponse accepted(const std::string &batch, bool replay)
        {
            auto r = response(204);
            r.headers["X-Amnezia-Batch-Accepted"] = "1";
            r.headers["X-Amnezia-Batch-Id"] = batch;
            if (replay)
                r.headers["X-Amnezia-Batch-Replayed"] = "1";
            return r;
        }
        struct Slot
        {
            std::atomic<unsigned> &count;
            bool held = false;
            Slot(std::atomic<unsigned> &c, unsigned maximum) : count(c)
            {
                auto n = count.load();
                while (n < maximum) {
                    if (count.compare_exchange_weak(n, n + 1)) {
                        held = true;
                        break;
                    }
                }
            }
            ~Slot()
            {
                if (held)
                    --count;
            }
        };
    }
    Collector::Collector(CollectorOptions options) : options_(std::move(options))
    {
        require(options_.root.is_absolute(), "absolute data root required");
        require(!options_.allow_bootstrap || safe_installation(options_.scope), "safe legacy scope required");
        ::umask(0077);
        directory(options_.root);
        directory(options_.root / "logs");
        directory(options_.root / "locks");
        maintenance(false);
    }
    void Collector::invalidate_health()
    {
        std::lock_guard<std::mutex> lock(health_mutex_);
        health_expires_ = 0;
    }
    std::string Collector::resolve_legacy(const std::string &peer)
    {
        if (!options_.allow_bootstrap || !safe_installation(options_.scope))
            return { };
        return scan_auth_rows<std::string>(options_.root / "legacy" / (options_.scope + ".tsv"),
                [&](auto &found, const auto &r, auto count) {
                    if (count >= 2 && r[0] == peer && digest_id(r[1]))
                        found = r[1];
                });
    }
    int Collector::authenticate(const HttpRequest &request, std::string &id)
    {
        id = header(request, "x-amnezia-client-id");
        if (!digest_id(id))
            return 400;
        auto token = header(request, "x-amnezia-log-token");
        if (!token_valid(token))
            return 403;
        try {
            auto saved = scan_auth_rows<std::string>(options_.root / "tokens.tsv",
                    [&](auto &found, const auto &r, auto count) {
                        if (count >= 2 && r[0] == id && !r[1].empty())
                            found = r[1]; // Last nonempty duplicate wins, as in tokens().
                    });
            if (!token_valid(saved) || !equal_secret(saved, token))
                return 403;
            auto flags = scan_auth_rows<std::pair<bool, bool>>(options_.root / "legacy_tokens.tsv",
                    [&](auto &found, const auto &r, auto count) {
                        if (count >= 3 && r[0] == id && equal_secret(r[1], token)) {
                            found.first = true;
                            found.second |= r[2] == options_.scope;
                        }
                    });
            bool legacy = flags.first, scope = flags.second;
            if (legacy && (!options_.allow_bootstrap || !scope || resolve_legacy(request.peer) != id))
                return 403;
            return 0;
        } catch (...) {
            return 503;
        }
    }
    HttpResponse Collector::bootstrap(const HttpRequest &request)
    {
        if (!options_.allow_bootstrap)
            return response(404);
        if (request.body.size() > 1024)
            return response(413);
        Slot slot(uploads_, 4);
        if (!slot.held)
            return response(503);
        try {
            auto id = resolve_legacy(request.peer);
            auto claimed = header(request, "x-amnezia-client-id");
            if (id.empty() || (!claimed.empty() && claimed != id))
                return response(403);
            std::lock_guard<std::mutex> guard(token_mutex_);
            auto lockdir = options_.root / "tokens.lock";
            bool held = false;
            for (unsigned attempt = 0; attempt < 30 && !held; ++attempt) {
                if (::mkdir(lockdir.c_str(), 0700) == 0) {
                    held = true;
                    break;
                }
                require(errno == EEXIST, "token lock failed");
                struct stat st { };
                if (::lstat(lockdir.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && st.st_mtim.tv_sec < now_seconds() - 120)
                    ::rmdir(lockdir.c_str());
                if (attempt < 29)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            require(held, "token lock timeout");
            struct Unlock
            {
                fs::path p;
                ~Unlock()
                {
                    ::rmdir(p.c_str());
                }
            } unlock { lockdir };
            auto map = tokens(options_.root);
            auto token = map[id];
            if (token.empty()) {
                token = random_token();
                map[id] = token;
            }
            std::string legacy;
            for (const auto &row : rows(options_.root / "legacy_tokens.tsv")) {
                if (row.size() >= 3 && !(row[0] == id && row[2] == options_.scope)) {
                    for (std::size_t i = 0; i < row.size(); ++i) {
                        if (i)
                            legacy += "\t";
                        legacy += row[i];
                    }
                    legacy += "\n";
                }
            }
            legacy += id + "\t" + token + "\t" + options_.scope + "\n";
            std::string all;
            for (const auto &row : map)
                all += row.first + "\t" + row.second + "\n";
            write_atomic(options_.root / "legacy_tokens.tsv", legacy);
            write_atomic(options_.root / "tokens.tsv", all);
            auto r = response(200);
            r.headers["Content-Type"] = "application/json";
            r.body = "{\"endpoint\":\"http://172.29.172.251:" + std::to_string(options_.port) + options_.upload_path
                    + "\",\"clientId\":\"" + id + "\",\"token\":\"" + json_escape(token) + "\"}";
            invalidate_health();
            return r;
        } catch (...) {
            return response(503);
        }
    }
    HttpResponse Collector::upload(const HttpRequest &request)
    {
        std::string id;
        int auth = authenticate(request, id);
        if (auth)
            return response(auth);
        auto kind = header(request, "x-amnezia-log-kind", "client");
        if (kind != "android" && kind != "client" && kind != "service")
            return response(400);
        auto install = header(request, "x-amnezia-installation-id", "unknown");
        if (!safe_installation(install))
            install = "unknown";
        auto batch = header(request, "x-amnezia-batch-id");
        if (batch.empty())
            return response(428);
        if (!digest_id(batch))
            return response(400);
        if (request.body.empty() || request.body.size() > options_.upload_bytes)
            return response(413);
        Slot slot(uploads_, 4);
        if (!slot.held)
            return response(503);
        try {
            FileLock client(options_.root / "locks" / (id + ".lock"));
            auto dir = options_.root / "logs" / id;
            directory(dir);
            Db db(options_.root);
            auto meta = receipt(db, id, batch);
            Metadata stored;
            if (!meta.found || !meta.bound)
                for (const auto &e : log_files(dir, false)) {
                    auto name = e.path.filename().string();
                    auto suffix = "-" + batch + ".log";
                    if (name == batch + ".log"
                        || (name.size() >= suffix.size() && name.substr(name.size() - suffix.size()) == suffix)) {
                        auto metadata = file_metadata(e.path, options_.upload_bytes);
                        stored = { true, true, metadata.first, metadata.second };
                        break;
                    }
                }
            auto hash = sha256(request.body);
            if (meta.found || stored.found) {
                auto expected = meta.bound ? meta : stored;
                if (expected.bound) {
                    require(digest_id(expected.hash) && expected.size > 0
                                    && std::uint64_t(expected.size) <= options_.upload_bytes,
                            "invalid receipt metadata");
                    if (expected.size != std::int64_t(request.body.size()) || !equal_secret(expected.hash, hash))
                        return response(409);
                }
                if (stored.found)
                    sync_directory(dir);
                if (!meta.bound)
                    record(db, options_, id, batch, hash, request.body.size());
                invalidate_health();
                return accepted(batch, true);
            }
            auto stamp = std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count();
            std::time_t seconds = now_seconds();
            std::tm utc { };
            require(::gmtime_r(&seconds, &utc) != nullptr, "UTC timestamp failed");
            std::ostringstream prefix;
            prefix << std::put_time(&utc, "%Y%m%d-%H%M%S") << "-" << stamp;
            auto final = dir / (prefix.str() + "-" + install + "-" + kind + "-" + batch + ".log");
            auto temp = fs::path(final.string() + ".tmp-" + random_hex());
            struct Cleanup
            {
                fs::path p;
                ~Cleanup()
                {
                    if (!p.empty())
                        ::unlink(p.c_str());
                }
            } cleanup { temp };
            {
                Fd fd(::open(temp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600));
                std::size_t offset = 0;
                while (offset < request.body.size()) {
                    auto n = ::write(fd.value, request.body.data() + offset, request.body.size() - offset);
                    if (n < 0 && errno == EINTR)
                        continue;
                    require(n > 0, "upload write failed");
                    offset += std::size_t(n);
                }
                require(::fsync(fd.value) == 0, "upload fsync failed");
            }
            {
                std::lock_guard<std::mutex> guard(storage_mutex_);
                FileLock global(options_.root / "retention.lock");
                if (!reserve(options_, request.body.size(), 1))
                    return response(507);
                require(::rename(temp.c_str(), final.c_str()) == 0, "upload rename failed");
                cleanup.p.clear();
                sync_directory(dir);
                record(db, options_, id, batch, hash, request.body.size());
                prune_client(options_, dir);
            }
            maintenance();
            invalidate_health();
            return accepted(batch, false);
        } catch (...) {
            invalidate_health();
            return response(500);
        }
    }
    void Collector::maintenance(bool force)
    {
        std::lock_guard<std::mutex> guard(storage_mutex_);
        FileLock global(options_.root / "retention.lock");
        auto state = options_.root / "retention.last";
        double last = 0;
        try {
            auto s = read_stable(state, true);
            if (!s.empty() && s.size() < 64)
                last = std::stod(s);
        } catch (...) {
            last = 0;
        }
        auto now = now_seconds();
        if (!force && last >= 0 && last <= now + 300 && double(now) - last < 3600)
            return;
        reserve(options_);
        Db db(options_.root);
        db.exec("BEGIN IMMEDIATE");
        try {
            Statement age(db, "DELETE FROM batch_receipts WHERE accepted_at<?");
            age.integer(1, now - options_.receipt_age);
            age.done();
            Statement cap(db,
                          "DELETE FROM batch_receipts WHERE rowid IN(SELECT rowid FROM batch_receipts ORDER BY "
                          "accepted_at DESC,rowid DESC LIMIT -1 OFFSET ?)");
            cap.integer(1, options_.total_receipts);
            cap.done();
            db.exec("COMMIT");
        } catch (...) {
            db.exec("ROLLBACK");
            throw;
        }
        write_atomic(state, std::to_string(now) + "\n");
    }
    bool Collector::healthy()
    {
        std::lock_guard<std::mutex> health(health_mutex_);
        if (health_expires_ > steady())
            return health_ready_;
        health_expires_ = steady() + 15;
        health_ready_ = false;
        try {
            scan_auth_rows<bool>(options_.root / "tokens.tsv",
                    [](auto &, const auto &r, auto count) {
                        if (count == 1 && r[0].empty())
                            return;
                        require(count == 2 && digest_id(r[0]) && token_valid(r[1]), "invalid token map");
                    }, false);
            Db db(options_.root);
            db.exec("BEGIN IMMEDIATE");
            db.exec("INSERT OR REPLACE INTO collector_health(singleton,touched_at)VALUES(1,0)");
            db.exec("ROLLBACK");
            auto probe = options_.root / "logs" / (".health-" + random_hex() + ".tmp");
            write_atomic(probe, "1");
            require(::unlink(probe.c_str()) == 0, "probe cleanup failed");
            sync_directory(probe.parent_path());
            std::lock_guard<std::mutex> guard(storage_mutex_);
            FileLock global(options_.root / "retention.lock");
            auto files = log_files(options_.root / "logs", true);
            std::uint64_t size = 0;
            for (const auto &e : files)
                size += e.size;
            health_ready_ = size <= options_.total_bytes && files.size() <= options_.total_files;
        } catch (...) {
            health_ready_ = false;
        }
        return health_ready_;
    }
    HttpResponse Collector::preflight(const HttpRequest &request)
    {
        if (request.method == "GET")
            return response(request.target == "/healthz" ? 0 : 404);
        if (request.method != "POST")
            return response(501);
        auto content_length = [&]() -> std::uint64_t {
            auto text = header(request, "content-length", "0");
            if (text.empty() || text.find_first_not_of("0123456789") != std::string::npos)
                throw std::invalid_argument("invalid body length");
            std::size_t consumed = 0;
            auto value = std::stoull(text, &consumed);
            require(consumed == text.size(), "invalid body length");
            return value;
        };
        if (request.target == options_.bootstrap_path) {
            try {
                if (content_length() > 1024)
                    return response(413);
            } catch (...) {
                return response(400);
            }
            if (!options_.allow_bootstrap)
                return response(404);
            try {
                auto id = resolve_legacy(request.peer);
                auto claimed = header(request, "x-amnezia-client-id");
                return response(id.empty() || (!claimed.empty() && claimed != id) ? 403 : 0);
            } catch (...) {
                return response(503);
            }
        }
        if (request.target != options_.upload_path)
            return response(404);
        std::string id;
        int auth = authenticate(request, id);
        if (auth)
            return response(auth);
        auto kind = header(request, "x-amnezia-log-kind", "client");
        if (kind != "android" && kind != "client" && kind != "service")
            return response(400);
        auto batch = header(request, "x-amnezia-batch-id");
        if (batch.empty())
            return response(428);
        if (!digest_id(batch))
            return response(400);
        try {
            auto length = content_length();
            if (!length || length > options_.upload_bytes)
                return response(413);
        } catch (...) {
            return response(400);
        }
        return response(0);
    }
    HttpResponse Collector::handle(const HttpRequest &request)
    {
        if (request.method == "GET") {
            if (request.target != "/healthz")
                return response(404);
            Slot slot(health_requests_, 8);
            if (!slot.held)
                return response(503);
            bool ready = healthy();
            auto r = response(ready ? 200 : 503);
            r.headers["Content-Type"] = "application/json";
            r.body = ready ? "{\"status\":\"ok\",\"collectorVersion\":3}"
                           : "{\"status\":\"degraded\",\"collectorVersion\":3}";
            return r;
        }
        if (request.method != "POST")
            return response(501);
        if (request.target == options_.bootstrap_path)
            return bootstrap(request);
        if (request.target != options_.upload_path)
            return response(404);
        return upload(request);
    }
}
