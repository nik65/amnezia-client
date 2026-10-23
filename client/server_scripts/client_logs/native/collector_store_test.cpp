#include "collector_store.h"
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sqlite3.h>
#include <sstream>
#include <stdexcept>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>
namespace fs = std::filesystem;
using namespace amnezia::collector;
void check(bool c, const char *s)
{
    if (!c)
        throw std::runtime_error(s);
}
struct Temp
{
    fs::path root;
    Temp()
    {
        char name[] = "/tmp/amnezia-collector-store-test-XXXXXX";
        auto p = ::mkdtemp(name);
        check(p, "mkdtemp");
        root = p;
    }
    ~Temp()
    {
        fs::remove_all(root);
    }
};
void put(const fs::path &p, const std::string &s)
{
    fs::create_directories(p.parent_path());
    std::ofstream f(p, std::ios::binary);
    f << s;
    check(bool(f), "fixture write");
}
HttpRequest request(std::string id = std::string(64, 'a'), std::string batch = std::string(64, 'b'),
                    std::string body = "test-body")
{
    HttpRequest r;
    r.method = "POST";
    r.target = "/logs";
    r.peer = "127.0.0.1";
    r.body = body;
    r.headers = { { "x-amnezia-client-id", id }, { "x-amnezia-log-token", "test-token" }, { "x-amnezia-batch-id", batch } };
    return r;
}
std::vector<fs::path> files(const fs::path &root)
{
    std::vector<fs::path> v;
    for (const auto &e : fs::recursive_directory_iterator(root / "logs"))
        if (e.is_regular_file() && e.path().extension() == ".log")
            v.push_back(e.path());
    return v;
}
void sql(const fs::path &p, const std::string &text)
{
    sqlite3 *d = nullptr;
    check(sqlite3_open(p.c_str(), &d) == SQLITE_OK, "sqlite open");
    char *error = nullptr;
    auto rc = sqlite3_exec(d, text.c_str(), nullptr, nullptr, &error);
    sqlite3_free(error);
    sqlite3_close(d);
    check(rc == SQLITE_OK, "sqlite exec");
}
int main()
{
    try {
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            Collector c(o);
            auto r = request();
            auto accepted = c.handle(r);
            check(accepted.status == 204 && accepted.headers.at("X-Amnezia-Batch-Id") == std::string(64, 'b'),
                  "durable ack");
            check(files(t.root).size() == 1, "one stored file");
            auto replay = c.handle(r);
            check(replay.status == 204 && replay.headers.at("X-Amnezia-Batch-Replayed") == "1", "replay");
            r.body = "different";
            check(c.handle(r).status == 409, "same id changed body conflict");
            r = request();
            fs::remove(files(t.root).front());
            check(c.handle(r).headers.at("X-Amnezia-Batch-Replayed") == "1", "ledger survives log prune");
            Collector restart(o);
            check(restart.handle(r).status == 204, "restart durable ledger");
            r.headers["x-amnezia-log-token"] = "wrong";
            check(c.handle(r).status == 403, "wrong token");
            r = request();
            r.headers.erase("x-amnezia-batch-id");
            check(c.handle(r).status == 428, "missing batch");
            r = request();
            r.headers["x-amnezia-client-id"] = "../bad";
            check(c.handle(r).status == 400, "traversal client rejected");
            r = request();
            r.headers["x-amnezia-log-kind"] = "bad";
            check(c.handle(r).status == 400, "kind rejected");
            HttpRequest health;
            health.method = "GET";
            health.target = "/healthz";
            check(c.handle(health).status == 200, "health ready");
            put(t.root / "tokens.tsv", "invalid\tmap\n");
            Collector unhealthy(o);
            check(unhealthy.handle(health).status == 503, "invalid token map degraded health");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            Collector c(o);
            auto dir = t.root / "logs" / std::string(64, 'a');
            put(dir / (std::string(64, 'b') + ".log"), "test-body");
            auto r = c.handle(request());
            check(r.status == 204 && r.headers.count("X-Amnezia-Batch-Replayed"),
                  "crash window stored file binds receipt");
            auto conflict = request();
            conflict.body = "bad";
            check(c.handle(conflict).status == 409, "stored file body mismatch");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            sql(t.root / "batch-receipts.sqlite3",
                "CREATE TABLE batch_receipts(client_id TEXT NOT NULL,batch_id TEXT NOT NULL,accepted_at INTEGER NOT "
                "NULL,PRIMARY KEY(client_id,batch_id));INSERT INTO batch_receipts VALUES('"
                        + std::string(64, 'a') + "','" + std::string(64, 'b') + "',strftime('%s','now'));");
            CollectorOptions o;
            o.root = t.root;
            Collector c(o);
            check(c.handle(request()).status == 204, "legacy receipt migration");
            auto r = request();
            r.body = "changed";
            check(c.handle(r).status == 409, "legacy receipt now bound");
        }
        {
            Temp t;
            std::string text;
            for (char id = 'a'; id <= 'd'; ++id)
                text += std::string(64, id) + "\ttest-token\n";
            put(t.root / "tokens.tsv", text);
            CollectorOptions o;
            o.root = t.root;
            o.total_files = 2;
            o.total_bytes = 12;
            Collector c(o);
            std::vector<std::thread> threads;
            std::vector<int> statuses(4);
            for (int i = 0; i < 4; ++i)
                threads.emplace_back([&, i] {
                    statuses[i] =
                            c.handle(request(std::string(64, char('a' + i)), std::string(64, char('a' + i)), "body-0")).status;
                });
            for (auto &thread : threads)
                thread.join();
            for (auto s : statuses)
                check(s == 204, "concurrent commits ack");
            auto stored = files(t.root);
            std::uint64_t bytes = 0;
            for (const auto &p : stored)
                bytes += fs::file_size(p);
            check(stored.size() <= 2 && bytes <= 12, "global hard cap preserved");
            for (int i = 0; i < 4; ++i)
                check(c.handle(request(std::string(64, char('a' + i)), std::string(64, char('a' + i)), "body-0"))
                              .headers.count("X-Amnezia-Batch-Replayed"),
                      "pruned global logs retain ack ledger");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n" + std::string(64, 'c') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            Collector c(o);
            for (auto pair : std::vector<std::pair<char, int>> { { 'a', 1706 }, { 'c', 1687 } }) {
                auto dir = t.root / "logs" / std::string(64, pair.first);
                for (int i = 0; i < pair.second; ++i)
                    put(dir / ("chunk-" + std::to_string(i) + ".log"), "tiny\n");
            }
            c.maintenance(true);
            check(files(t.root).size() == 3393, "observed 24h tiny cadence retained defaults");
            check(fs::exists(t.root / "logs" / std::string(64, 'a') / "chunk-0.log"), "first PC retained");
            check(c.handle(request()).status == 204, "per client prune checked on upload");
            check(files(t.root).size() == 3394, "default perclient quota roomy");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            o.client_files = 2;
            Collector c(o);
            for (char b = 'b'; b <= 'd'; ++b)
                check(c.handle(request(std::string(64, 'a'), std::string(64, b))).status == 204, "small client uploads");
            check(files(t.root).size() == 2, "per-client cap enforced");
            auto r = request();
            check(c.handle(r).headers.count("X-Amnezia-Batch-Replayed"), "perclient pruned receipt survives");
        }
        {
            Temp t;
            auto client = std::string(64, 'a');
            put(t.root / "tokens.tsv", client + "\ttest-token\n");
            put(t.root / "legacy_tokens.tsv", client + "\ttest-token\tawg\n");
            put(t.root / "legacy/awg.tsv", "127.0.0.1\t" + client + "\n");
            CollectorOptions o;
            o.root = t.root;
            Collector no_legacy(o);
            check(no_legacy.handle(request()).status == 403, "bridge rejects legacy token");
            o.allow_bootstrap = true;
            o.scope = "awg";
            Collector legacy(o);
            check(legacy.handle(request()).status == 204, "tunnel scope+source legacy allowed");
            auto r = request();
            r.peer = "127.0.0.2";
            check(legacy.handle(r).status == 403, "wrong source rejects legacy");
            r.method = "POST";
            r.target = "/bootstrap";
            r.body = "";
            r.peer = "127.0.0.1";
            check(legacy.handle(r).status == 200, "bootstrap existing mapped client");
        }
        {
            Temp t;
            auto first = std::string(64, 'a');
            auto last = std::string(64, 'c');
            put(t.root / "tokens.tsv", first + "\ttest-token\n" + last + "\ttest-token\n");
            put(t.root / "legacy/awg.tsv", "127.0.0.1\t" + first + "\n127.0.0.1\t" + last + "\n");
            auto preserved = first + "\ttest-token\tother\textra-column\n";
            put(t.root / "legacy_tokens.tsv", preserved);
            CollectorOptions o;
            o.root = t.root;
            o.allow_bootstrap = true;
            o.scope = "awg";
            Collector c(o);
            auto r = request(last);
            r.target = "/bootstrap";
            r.body.clear();
            auto answer = c.handle(r);
            check(answer.status == 200 && answer.body.find(last) != std::string::npos,
                  "duplicate legacy IP uses last row like Python dict");
            std::ifstream input(t.root / "legacy_tokens.tsv");
            std::string contents((std::istreambuf_iterator<char>(input)), { });
            check(contents.find(preserved) != std::string::npos, "bootstrap preserves unrelated legacy TSV columns");
            r.headers["x-amnezia-client-id"] = first;
            check(c.handle(r).status == 403, "superseded duplicate IP cannot bootstrap prior client");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            Collector c(o);
            auto lock = t.root / "locks" / (std::string(64, 'a') + ".lock");
            check(::mkfifo(lock.c_str(), 0600) == 0, "FIFO lock fixture");
            check(c.handle(request()).status == 500, "nonregular lock fails closed without ACK");
            check(files(t.root).empty(), "invalid lock cannot persist upload");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            Collector c(o);
            auto batch = std::string(64, 'b');
            std::string body(15 * 1024 * 1024, 'x');
            put(t.root / "logs" / std::string(64, 'a') / (batch + ".log"), body);
            check(c.handle(request(std::string(64, 'a'), batch, body)).status == 204,
                  "maximum crash-window log streams digest and recovers durable receipt");
            body.back() = 'y';
            check(c.handle(request(std::string(64, 'a'), batch, body)).status == 409,
                  "maximum recovered log rejects last-byte mismatch");
        }
        {
            Temp t;
            put(t.root / "tokens.tsv", std::string(64, 'a') + "\ttest-token\n");
            CollectorOptions o;
            o.root = t.root;
            o.total_receipts = 1;
            Collector c(o);
            for (unsigned i = 0; i < 512; ++i) {
                std::ostringstream batch;
                batch << std::hex << std::setw(64) << std::setfill('0') << i;
                check(c.handle(request(std::string(64, 'a'), batch.str())).status == 204, "periodic receipt upload");
            }
            sqlite3 *db = nullptr;
            check(sqlite3_open((t.root / "batch-receipts.sqlite3").c_str(), &db) == SQLITE_OK, "receipt count DB");
            sqlite3_stmt *statement = nullptr;
            check(sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM batch_receipts", -1, &statement, nullptr) == SQLITE_OK,
                  "receipt count query");
            check(sqlite3_step(statement) == SQLITE_ROW, "receipt count row");
            auto count = sqlite3_column_int64(statement, 0);
            sqlite3_finalize(statement);
            sqlite3_close(db);
            check(count <= 256, "global receipt cap checked within256 records even inside hourly interval");
        }
        std::cout << "collector store contract PASS\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << '\n';
        return 1;
    }
}
