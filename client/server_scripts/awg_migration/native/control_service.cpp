#include "control_service.h"
#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <fcntl.h>
#include <json-c/json.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <set>
#include <sqlite3.h>
#include <stdexcept>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>
namespace amnezia::awgMigration
{
    namespace
    {
        constexpr std::size_t controlJsonLimit = 1024 * 1024;
        constexpr std::size_t readyStateLimit = 8 * 1024 * 1024;
        void need(bool v)
        {
            if (!v)
                throw std::runtime_error("invalid control request or state");
        }
        using Json = std::unique_ptr<json_object, decltype(&json_object_put)>;
        Json own(json_object *p)
        {
            return Json(p, json_object_put);
        }

        // RapidJSON owns JSON grammar/UTF-8/escape validation. SAX callbacks only
        // enforce protocol depth/numeric bounds and duplicate keys before json-c
        // can perform its normal last-key-wins object insertion.
        struct StrictJson : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, StrictJson>
        {
            struct Frame
            {
                json_object *value;
                std::set<std::string> keys;
                std::string key;
            };
            Json root = own(nullptr);
            std::vector<Frame> stack;
            bool started = false;
            bool add(json_object *value)
            {
                if (stack.empty()) {
                    if (started) {
                        if (value)
                            json_object_put(value);
                        return false;
                    }
                    started = true;
                    root = own(value);
                } else if (json_object_get_type(stack.back().value) == json_type_array)
                    json_object_array_add(stack.back().value, value);
                else
                    json_object_object_add(stack.back().value, stack.back().key.c_str(), value);
                return true;
            }
            bool Null()
            {
                return add(nullptr);
            }
            bool Bool(bool b)
            {
                return add(json_object_new_boolean(b));
            }
            bool Int(int v)
            {
                return Int64(v);
            }
            bool Uint(unsigned v)
            {
                return Int64(v);
            }
            bool Int64(std::int64_t v)
            {
                return add(json_object_new_int64(v));
            }
            bool Uint64(std::uint64_t v)
            {
                return v <= std::uint64_t(INT64_MAX) && Int64(std::int64_t(v));
            }
            bool Double(double)
            {
                return false;
            }
            bool String(const char *p, rapidjson::SizeType n, bool)
            {
                return add(json_object_new_string_len(p, int(n)));
            }
            bool Key(const char *p, rapidjson::SizeType n, bool)
            {
                if (stack.empty())
                    return false;
                std::string key(p, n);
                if (key.find('\0') != std::string::npos || !stack.back().keys.insert(key).second)
                    return false;
                stack.back().key = std::move(key);
                return true;
            }
            bool begin(bool object)
            {
                if (stack.size() >= 64)
                    return false;
                auto value = object ? json_object_new_object() : json_object_new_array();
                if (!add(value))
                    return false;
                stack.push_back({ value, { }, { } });
                return true;
            }
            bool StartObject()
            {
                return begin(true);
            }
            bool StartArray()
            {
                return begin(false);
            }
            bool EndObject(rapidjson::SizeType)
            {
                stack.pop_back();
                return true;
            }
            bool EndArray(rapidjson::SizeType)
            {
                stack.pop_back();
                return true;
            }
        };
        Json parse(const std::string &raw, std::size_t limit = controlJsonLimit)
        {
            need(raw.size() <= limit && raw.find('\0') == std::string::npos);
            rapidjson::MemoryStream stream(raw.data(), raw.size());
            rapidjson::Reader reader;
            StrictJson handler;
            need(reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, handler) && handler.started
                 && handler.stack.empty() && stream.Tell() == raw.size());
            return std::move(handler.root);
        }
        std::string quote(const std::string &raw)
        {
            rapidjson::StringBuffer buffer;
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::UTF8<>, rapidjson::ASCII<>> writer(buffer);
            need(writer.String(raw.data(), rapidjson::SizeType(raw.size())));
            std::string out(buffer.GetString(), buffer.GetSize());
            // Python ensure_ascii escapes DEL as well as non-ASCII; the ASCII
            // writer treats DEL as a literal ASCII codepoint.
            for (std::size_t at = 0; (at = out.find(char(0x7f), at)) != std::string::npos; at += 6)
                out.replace(at, 1, "\\u007f");
            // Python ensure_ascii uses lowercase hex, RapidJSON uses uppercase.
            // Escapes themselves and surrogate generation remain library-owned.
            for (std::size_t i = 0; i + 1 < out.size(); ++i) {
                if (out[i] != '\\')
                    continue;
                if (out[i + 1] == 'u') {
                    need(i + 5 < out.size());
                    for (unsigned j = 2; j < 6; ++j)
                        if (out[i + j] >= 'A' && out[i + j] <= 'F')
                            out[i + j] += 32;
                    i += 5;
                } else
                    ++i;
            }
            return out;
        }
        std::string canonical(json_object *j)
        {
            if (!j)
                return "null";
            switch (json_object_get_type(j)) {
            case json_type_null: return "null";
            case json_type_boolean: return json_object_get_boolean(j) ? "true" : "false";
            case json_type_int: return json_object_to_json_string_ext(j, JSON_C_TO_STRING_PLAIN);
            case json_type_string: return quote(std::string(json_object_get_string(j), json_object_get_string_len(j)));
            case json_type_array: {
                std::string o = "[";
                for (std::size_t i = 0; i < json_object_array_length(j); ++i) {
                    if (i)
                        o += ',';
                    o += canonical(json_object_array_get_idx(j, i));
                }
                return o + ']';
            }
            case json_type_object: {
                std::map<std::string, json_object *> m;
                json_object_object_foreach(j, k, v)
                {
                    m[k] = v;
                }
                std::string o = "{";
                for (auto &v : m) {
                    if (o.size() > 1)
                        o += ',';
                    o += quote(v.first) + ':' + canonical(v.second);
                }
                return o + '}';
            }
            default: throw std::runtime_error("unsupported control JSON number");
            }
        }
        json_object *get(json_object *j, const char *k)
        {
            json_object *v = nullptr;
            need(j && json_object_get_type(j) == json_type_object && json_object_object_get_ex(j, k, &v));
            return v;
        }
        std::string str(json_object *j)
        {
            need(j && json_object_get_type(j) == json_type_string);
            return { json_object_get_string(j), std::size_t(json_object_get_string_len(j)) };
        }
        std::string sget(json_object *j, const char *k)
        {
            return str(get(j, k));
        }
        std::int64_t num(json_object *j)
        {
            need(j && json_object_get_type(j) == json_type_int);
            return json_object_get_int64(j);
        }
        std::int64_t iget(json_object *j, const char *k)
        {
            return num(get(j, k));
        }
        void set(json_object *j, const char *k, const std::string &v)
        {
            json_object_object_add(j, k, json_object_new_string_len(v.data(), int(v.size())));
        }
        void set(json_object *j, const char *k, std::int64_t v)
        {
            json_object_object_add(j, k, json_object_new_int64(v));
        }
        void copy(json_object *j, const char *k, json_object *v)
        {
            json_object_object_add(j, k, json_object_get(v));
        }
        std::string b64(const unsigned char *p, std::size_t n, bool url = false)
        {
            std::string o(4 * ((n + 2) / 3), '\0');
            EVP_EncodeBlock((unsigned char *)o.data(), p, int(n));
            if (url) {
                std::replace(o.begin(), o.end(), '+', '-');
                std::replace(o.begin(), o.end(), '/', '_');
                while (!o.empty() && o.back() == '=')
                    o.pop_back();
            }
            return o;
        }
        std::string hash(const std::string &s)
        {
            unsigned char d[32];
            unsigned n = 0;
            need(EVP_Digest(s.data(), s.size(), d, &n, EVP_sha256(), nullptr) == 1 && n == 32);
            std::string o;
            const char *h = "0123456789abcdef";
            for (auto c : d) {
                o += h[c >> 4];
                o += h[c & 15];
            }
            return o;
        }
        bool nonce(const std::string &s)
        {
            return s.size() >= 32 && s.size() <= 128
                    && s.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")
                    == std::string::npos;
        }
        bool fingerprint(const std::string &s)
        {
            return s.size() == 64 && s.find_first_not_of("abcdef0123456789") == std::string::npos;
        }
        bool key(const std::string &s)
        {
            return s.size() == 44 && s.back() == '='
                    && s.substr(0, 43).find_first_not_of(
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                    == std::string::npos;
        }
        struct Fd
        {
            int n;
            ~Fd()
            {
                if (n >= 0)
                    ::close(n);
            }
        };
        std::string read(const std::filesystem::path &p, bool privateFile = false,
                         std::size_t limit = controlJsonLimit)
        {
            Fd f { ::open(p.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK) };
            struct stat st { };
            need(f.n >= 0 && ::fstat(f.n, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0
                 && static_cast<std::uint64_t>(st.st_size) <= limit);
            if (privateFile)
                need(st.st_uid == geteuid() && !(st.st_mode & 077) && st.st_size >= 32 && st.st_size <= 8192);
            std::string o;
            std::array<char, 4096> b;
            for (;;) {
                auto n = ::read(f.n, b.data(), b.size());
                need(n >= 0);
                if (!n)
                    break;
                o.append(b.data(), n);
                need(o.size() <= limit);
            }
            return o;
        }
        using Pkey = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
        Pkey signer(const std::string &pem)
        {
            auto b = std::unique_ptr<BIO, decltype(&BIO_free)>(BIO_new_mem_buf(pem.data(), int(pem.size())), BIO_free);
            Pkey k(PEM_read_bio_PrivateKey(
                           b.get(), nullptr, [](char *, int, int, void *) { return 0; }, nullptr),
                   EVP_PKEY_free);
            need(k && EVP_PKEY_id(k.get()) == EVP_PKEY_ED25519);
            return k;
        }
        std::string signWith(json_object *j, const std::string &pem)
        {
            auto k = signer(pem);
            auto ctx = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
            auto raw = canonical(j);
            std::array<unsigned char, 64> sig;
            std::size_t n = sig.size();
            need(EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, k.get()) == 1
                 && EVP_DigestSign(ctx.get(), sig.data(), &n, (const unsigned char *)raw.data(), raw.size()) == 1
                 && n == 64);
            auto o = own(json_object_new_object());
            set(o.get(), "payload", b64((const unsigned char *)raw.data(), raw.size()));
            set(o.get(), "signature", b64(sig.data(), sig.size()));
            return canonical(o.get());
        }
        std::string random(unsigned n)
        {
            std::vector<unsigned char> b(n);
            need(RAND_bytes(b.data(), int(n)) == 1);
            return b64(b.data(), b.size(), true);
        }
        std::string ip(const std::string &s)
        {
            unsigned char b[16];
            char out[INET6_ADDRSTRLEN];
            int family = s.find(':') == std::string::npos ? AF_INET : AF_INET6;
            need(inet_pton(family, s.c_str(), b) == 1 && inet_ntop(family, b, out, sizeof out));
            return out;
        }
        struct Db
        {
            sqlite3 *p = nullptr;
            explicit Db(const std::filesystem::path &path)
            {
                struct stat st { };
                need(::lstat(path.c_str(), &st) != 0
                     || (S_ISREG(st.st_mode) && st.st_uid == geteuid() && !(st.st_mode & 077)));
                int rc = sqlite3_open_v2(path.c_str(), &p,
                                         SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, nullptr);
                if (rc != SQLITE_OK) {
                    if (p)
                        sqlite3_close(p);
                    p = nullptr;
                    need(false);
                }
                sqlite3_busy_timeout(p, 5000);
            }
            ~Db()
            {
                if (p)
                    sqlite3_close(p);
            }
            void sql(const char *s)
            {
                need(sqlite3_exec(p, s, nullptr, nullptr, nullptr) == SQLITE_OK);
            }
        };
        struct Query
        {
            sqlite3_stmt *p = nullptr;
            Query(Db &d, const char *s)
            {
                need(sqlite3_prepare_v2(d.p, s, -1, &p, nullptr) == SQLITE_OK);
            }
            ~Query()
            {
                sqlite3_finalize(p);
            }
            void bind(int i, const std::string &s)
            {
                need(sqlite3_bind_text(p, i, s.data(), int(s.size()), SQLITE_TRANSIENT) == SQLITE_OK);
            }
            void bind(int i, std::int64_t n)
            {
                need(sqlite3_bind_int64(p, i, n) == SQLITE_OK);
            }
            bool row()
            {
                int r = sqlite3_step(p);
                need(r == SQLITE_ROW || r == SQLITE_DONE);
                return r == SQLITE_ROW;
            }
            void done()
            {
                need(!row());
            }
            std::string text(int i)
            {
                auto t = sqlite3_column_text(p, i);
                need(t);
                return (const char *)t;
            }
            std::int64_t integer(int i)
            {
                return sqlite3_column_int64(p, i);
            }
        };
    }
    std::string controlCanonical(const std::string &s)
    {
        return canonical(parse(s).get());
    }
    std::string controlBootstrapGrant(const std::string &secret, const std::string &binding)
    {
        auto raw = controlCanonical(binding);
        unsigned char d[EVP_MAX_MD_SIZE];
        unsigned n = 0;
        need(HMAC(EVP_sha384(), secret.data(), int(secret.size()), (const unsigned char *)raw.data(), raw.size(), d, &n)
             && n == 48);
        return b64(d, n, true);
    }
    std::string controlSign(const std::string &payload, const std::filesystem::path &dir)
    {
        return signWith(parse(payload).get(), read(dir / "signing.pem", true));
    }
    ControlService::ControlService(ControlOptions o) : options_(std::move(o))
    {
        need(options_.role == "source" || options_.role == "target");
        if (!options_.clock)
            options_.clock = []() {
                return std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                        .count();
            };
    }
    ControlResponse ControlService::dispatch(const ControlRequest &r, const std::function<std::string()> &auth) const
    {
        if (r.path.rfind("/migration/v1/", 0) != 0)
            return { };
        ControlResponse result { true, 403, { } };
        try {
            need(r.headers.count("transfer-encoding") == 0 && r.body.size() > 0 && r.body.size() <= 16384);
            auto length = r.headers.find("content-length");
            need(length != r.headers.end() && length->second == std::to_string(r.body.size()));
            auto body = parse(r.body);
            // Peer mappings are larger than their1MiB source/target configs.
            // Keep request/canonical/signer/handshake bounds unchanged.
            auto state = parse(read(options_.directory / "ready.json", false, readyStateLimit), readyStateLimit);
            need(iget(body.get(), "schema") == 1);
            auto now = options_.clock();
            bool target = options_.role == "target";
            bool renewing = target && r.path == "/migration/v1/renew";
            need((iget(state.get(), "expiresAt") > now || (target && (renewing || r.path == "/migration/v1/ack")))
                 && sget(state.get(), "containerId") == options_.scope);
            auto peer = sget(body.get(), "peerPublicKey");
            need(key(peer));
            auto mapping = get(get(state.get(), "peers"), peer.c_str());
            need(ip(r.peerAddress) == sget(mapping, target ? "targetIp" : "sourceIp"));
            std::map<std::string, std::set<std::string>> fields = {
                { "/migration/v1/bootstrap", { "schema", "peerPublicKey", "sourceFingerprint", "nonce" } },
                { "/migration/v1/offer", { "schema", "peerPublicKey", "sourceFingerprint", "nonce" } },
                { "/migration/v1/challenge", { "schema", "peerPublicKey", "generation", "grant", "nonce" } },
                { "/migration/v1/ack", { "schema", "peerPublicKey", "generation", "grant", "challengeReceipt" } },
                { "/migration/v1/renew", { "schema", "peerPublicKey", "generation", "grant", "nonce", "challengeReceipt" } }
            };
            need(fields.count(r.path));
            std::set<std::string> observed;
            json_object_object_foreach(body.get(), name, value)
            {
                (void)value;
                observed.insert(name);
            }
            need(observed == fields.at(r.path));
            // The owned private directory prevents replacement of SQLite sidecars. Never
            // accept a world/group writable directory or a caller supplied symlink DB.
            struct stat directory { };
            need(lstat(options_.directory.c_str(), &directory) == 0 && S_ISDIR(directory.st_mode)
                 && directory.st_uid == geteuid() && !(directory.st_mode & 077));
            {
                Fd created { open((options_.directory / "grants.sqlite3").c_str(),
                                  O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600) };
                need(created.n >= 0 || errno == EEXIST);
            }
            Db db(options_.directory / "grants.sqlite3");
            db.sql("PRAGMA synchronous=FULL");
            db.sql("BEGIN IMMEDIATE");
            try {
                db.sql("CREATE TABLE IF NOT EXISTS grants(digest TEXT PRIMARY KEY,peer TEXT,fingerprint "
                       "TEXT,generation INTEGER,expires INTEGER,challenge TEXT,proved INTEGER DEFAULT 0,ack INTEGER "
                       "DEFAULT 0,issued INTEGER,proofExpires INTEGER)");
                std::set<std::string> columns;
                {
                    Query q(db, "PRAGMA table_info(grants)");
                    while (q.row())
                        columns.insert(q.text(1));
                }
                if (!columns.count("proofExpires")) {
                    db.sql("ALTER TABLE grants ADD COLUMN proofExpires INTEGER");
                    db.sql("UPDATE grants SET proofExpires=expires");
                }
                for (auto column : { "bootstrapNonceHash", "bootstrapClient" })
                    if (!columns.count(column))
                        db.sql((std::string("ALTER TABLE grants ADD COLUMN ") + column + " TEXT").c_str());
                db.sql("CREATE TABLE IF NOT EXISTS renewalNonces(digest TEXT PRIMARY KEY)");
                std::string response;
                if (r.path == "/migration/v1/bootstrap" && !target) {
                    auto client = auth();
                    need(!client.empty() && client == sget(mapping, "clientId"));
                    auto n = sget(body.get(), "nonce"), fp = sget(body.get(), "sourceFingerprint");
                    need(nonce(n) && fingerprint(fp));
                    {
                        Query q(db, "DELETE FROM grants WHERE expires<? AND proved=0");
                        q.bind(1, now);
                        q.done();
                    }
                    std::string digest, challenge;
                    std::int64_t expiry = 0, issued = 0;
                    bool exists = false;
                    {
                        Query q(db,
                                "SELECT digest,expires,proved,ack,challenge,issued FROM grants WHERE peer=? AND "
                                "fingerprint=? AND generation=? AND bootstrapNonceHash=? AND bootstrapClient=?");
                        q.bind(1, peer);
                        q.bind(2, fp);
                        q.bind(3, iget(state.get(), "generation"));
                        q.bind(4, hash(n));
                        q.bind(5, client);
                        if (q.row()) {
                            exists = true;
                            digest = q.text(0);
                            expiry = q.integer(1);
                            need(!q.integer(2) && !q.integer(3) && expiry > now);
                            challenge = q.text(4);
                            issued = q.integer(5);
                            need(!q.row());
                        }
                    }
                    auto secret = read(options_.directory / "signing.pem", true);
                    auto signerKey = signer(secret);
                    unsigned char publicKey[32];
                    std::size_t publicSize = 32;
                    need(EVP_PKEY_get_raw_public_key(signerKey.get(), publicKey, &publicSize) == 1 && publicSize == 32
                         && b64(publicKey, 32) == sget(state.get(), "signingPublicKey"));
                    if (!exists) {
                        Query q(db, "SELECT count(*) FROM grants WHERE peer=? AND expires>?");
                        q.bind(1, peer);
                        q.bind(2, now);
                        need(q.row() && q.integer(0) < 32);
                        expiry = std::min(now + 86400, iget(state.get(), "expiresAt"));
                        issued = now;
                        challenge = random(32);
                    }
                    auto binding = own(json_object_new_object());
                    set(binding.get(), "domain", "amnezia-awg-migration-bootstrap-grant-v1");
                    set(binding.get(), "scope", options_.scope);
                    copy(binding.get(), "server", get(state.get(), "serverPublicKey"));
                    set(binding.get(), "peer", peer);
                    set(binding.get(), "client", client);
                    set(binding.get(), "fingerprint", fp);
                    copy(binding.get(), "generation", get(state.get(), "generation"));
                    set(binding.get(), "nonce", n);
                    set(binding.get(), "challenge", challenge);
                    set(binding.get(), "issued", issued);
                    set(binding.get(), "expires", expiry);
                    auto grant = controlBootstrapGrant(secret, canonical(binding.get()));
                    auto observedDigest = hash(grant);
                    if (exists)
                        need(observedDigest == digest);
                    else {
                        Query q(db,
                                "INSERT INTO "
                                "grants(digest,peer,fingerprint,generation,expires,challenge,issued,proofExpires,"
                                "bootstrapNonceHash,bootstrapClient) VALUES(?,?,?,?,?,?,?,?,?,?)");
                        q.bind(1, observedDigest);
                        q.bind(2, peer);
                        q.bind(3, fp);
                        q.bind(4, iget(state.get(), "generation"));
                        q.bind(5, expiry);
                        q.bind(6, challenge);
                        q.bind(7, issued);
                        q.bind(8, expiry);
                        q.bind(9, hash(n));
                        q.bind(10, client);
                        q.done();
                    }
                    auto out = own(json_object_new_object());
                    set(out.get(), "schema", std::int64_t(1));
                    for (auto k : { "serverPublicKey", "signingPublicKey", "generation" })
                        copy(out.get(), k, get(state.get(), k));
                    set(out.get(), "containerId", options_.scope);
                    set(out.get(), "peerPublicKey", peer);
                    set(out.get(), "sourceFingerprint", fp);
                    set(out.get(), "nonce", n);
                    set(out.get(), "grant", grant);
                    set(out.get(), "expiresAt", expiry);
                    response = canonical(out.get());
                } else {
                    json_object *grantValue = nullptr;
                    bool bodyGrant = json_object_object_get_ex(body.get(), "grant", &grantValue);
                    std::string grant = bodyGrant ? str(grantValue) : "";
                    auto header = r.headers.find("x-amnezia-migration-grant");
                    if (header != r.headers.end()) {
                        need(!bodyGrant || grant == header->second);
                        grant = header->second;
                    }
                    need(nonce(grant));
                    auto digest = hash(grant);
                    std::string fp, challenge;
                    std::int64_t generation, expiry, issued, proofExpiry, proved;
                    {
                        Query q(db, "SELECT peer,fingerprint,generation,expires,challenge,proved,issued,proofExpires FROM grants WHERE digest=?");
                        q.bind(1, digest);
                        need(q.row() && q.text(0) == peer);
                        fp = q.text(1);
                        generation = q.integer(2);
                        expiry = q.integer(3);
                        challenge = q.text(4);
                        proved = q.integer(5);
                        issued = q.integer(6);
                        proofExpiry = q.integer(7);
                        need(generation == iget(state.get(), "generation") && (expiry > now || renewing));
                    }
                    auto common = own(json_object_new_object());
                    set(common.get(), "schema", std::int64_t(1));
                    copy(common.get(), "serverPublicKey", get(state.get(), "serverPublicKey"));
                    set(common.get(), "containerId", options_.scope);
                    set(common.get(), "peerPublicKey", peer);
                    set(common.get(), "generation", generation);
                    set(common.get(), "expiresAt", expiry);
                    auto targetObject = own(json_object_new_object());
                    copy(targetObject.get(), "endpoint", get(state.get(), "endpoint"));
                    copy(targetObject.get(), "clientAddress", get(mapping, "clientAddress"));
                    copy(targetObject.get(), "parameters", get(state.get(), "parameters"));
                    if (r.path == "/migration/v1/offer" && !target) {
                        auto n = sget(body.get(), "nonce");
                        need(nonce(n) && sget(body.get(), "sourceFingerprint") == fp);
                        set(common.get(), "sourceFingerprint", fp);
                        set(common.get(), "nonce", n);
                        copy(common.get(), "target", targetObject.get());
                        auto c = own(json_object_new_object());
                        copy(c.get(), "address", get(state.get(), "challengeAddress"));
                        copy(c.get(), "port", get(state.get(), "challengePort"));
                        set(c.get(), "nonce", challenge);
                        copy(common.get(), "challenge", c.get());
                        response = controlSign(canonical(common.get()), options_.directory);
                    } else {
                        need(target && (r.path == "/migration/v1/challenge" || r.path == "/migration/v1/ack" || renewing)
                             && iget(body.get(), "generation") == generation);
                        auto handshakes = read(options_.directory / "handshakes.tsv");
                        std::int64_t handshake = 0;
                        std::size_t start = 0;
                        while (start < handshakes.size()) {
                            auto end = handshakes.find('\n', start);
                            auto line = handshakes.substr(start, end - start);
                            auto tab = line.find('\t');
                            need(tab != std::string::npos && line.find('\t', tab + 1) == std::string::npos);
                            if (line.substr(0, tab) == peer) {
                                auto text = line.substr(tab + 1);
                                std::size_t consumed = 0;
                                handshake = std::stoll(text, &consumed);
                                need(consumed == text.size());
                            }
                            if (end == std::string::npos)
                                break;
                            start = end + 1;
                        }
                        need(handshake >= std::max(now - 120, issued - 5) && handshake <= now + 5);
                        set(common.get(), "nonce", challenge);
                        copy(common.get(), "targetAddress", get(mapping, "targetIp"));
                        set(common.get(), "expiresAt", proofExpiry);
                        auto receipt = controlSign(canonical(common.get()), options_.directory);
                        if (r.path == "/migration/v1/challenge") {
                            need(sget(body.get(), "nonce") == challenge);
                            response = receipt;
                            Query q(db, "UPDATE grants SET proved=1 WHERE digest=?");
                            q.bind(1, digest);
                            q.done();
                        } else {
                            need(proved && canonical(get(body.get(), "challengeReceipt")) == receipt);
                            if (renewing) {
                                auto n = sget(body.get(), "nonce");
                                need(auth() == sget(mapping, "clientId") && nonce(n));
                                {
                                    Query q(db, "INSERT INTO renewalNonces(digest) VALUES(?)");
                                    q.bind(1, hash(peer + '\t' + n));
                                    q.done();
                                }
                                {
                                    Query q(db, "SELECT count(*) FROM grants WHERE peer=? AND expires>?");
                                    q.bind(1, peer);
                                    q.bind(2, now);
                                    need(q.row() && q.integer(0) < 32);
                                }
                                auto next = random(48);
                                auto nextExpiry = now + 86400;
                                {
                                    Query q(db, "INSERT INTO grants(digest,peer,fingerprint,generation,expires,challenge,issued,proofExpires,proved) VALUES(?,?,?,?,?,?,?,?,1)");
                                    q.bind(1, hash(next));
                                    q.bind(2, peer);
                                    q.bind(3, fp);
                                    q.bind(4, generation);
                                    q.bind(5, nextExpiry);
                                    q.bind(6, challenge);
                                    q.bind(7, issued);
                                    q.bind(8, proofExpiry);
                                    q.done();
                                }
                                auto out = own(json_object_new_object());
                                set(out.get(), "schema", std::int64_t(1));
                                copy(out.get(), "serverPublicKey", get(state.get(), "serverPublicKey"));
                                set(out.get(), "peerPublicKey", peer);
                                set(out.get(), "containerId", options_.scope);
                                set(out.get(), "generation", generation);
                                set(out.get(), "nonce", n);
                                set(out.get(), "grant", next);
                                set(out.get(), "sourceFingerprint", fp);
                                set(out.get(), "targetHash", hash(canonical(targetObject.get())));
                                set(out.get(), "expiresAt", nextExpiry);
                                response = controlSign(canonical(out.get()), options_.directory);
                            } else {
                                Query q(db, "UPDATE grants SET ack=1 WHERE digest=?");
                                q.bind(1, digest);
                                q.done();
                                auto out = own(json_object_new_object());
                                set(out.get(), "schema", std::int64_t(1));
                                set(out.get(), "generation", generation);
                                json_object_object_add(out.get(), "ok", json_object_new_boolean(true));
                                json_object_object_add(out.get(), "acknowledged", json_object_new_boolean(true));
                                response = canonical(out.get());
                            }
                        }
                    }
                }
                db.sql("COMMIT");
                Fd dirfd { open(options_.directory.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC | O_NOFOLLOW) };
                need(dirfd.n >= 0 && fsync(dirfd.n) == 0);
                result.status = 200;
                result.body = std::move(response);
            } catch (...) {
                sqlite3_exec(db.p, "ROLLBACK", nullptr, nullptr, nullptr);
                throw;
            }
        } catch (...) {
            result.status = 403;
            result.body.clear();
        }
        return result;
    }
}

