#include "trusted_image.h"
#include <algorithm>
#include <cctype>
#include <climits>
#include <rapidjson/encodings.h>
#include <rapidjson/memorystream.h>
#include <rapidjson/reader.h>
#include <set>
namespace amnezia::awgMigration
{
    namespace
    {
        // json-c keeps the last duplicate key and accepts NaN/Infinity even in
        // strict mode. Validate the complete JSON grammar/decoded key set first.
        struct UniqueKeys : rapidjson::BaseReaderHandler<rapidjson::UTF8<>, UniqueKeys>
        {
            struct Frame { bool object; std::set<std::string> keys; };
            std::vector<Frame> stack;
            bool StartObject() {
                if (stack.size() >= 32) return false;
                stack.push_back({true, {}}); return true;
            }
            bool StartArray() {
                if (stack.size() >= 32) return false;
                stack.push_back({false, {}}); return true;
            }
            bool EndObject(rapidjson::SizeType) {
                if (stack.empty() || !stack.back().object) return false;
                stack.pop_back(); return true;
            }
            bool EndArray(rapidjson::SizeType) {
                if (stack.empty() || stack.back().object) return false;
                stack.pop_back(); return true;
            }
            bool String(const char *data, rapidjson::SizeType size, bool) {
                return std::string_view(data, size).find('\0') == std::string_view::npos;
            }
            bool Key(const char *data, rapidjson::SizeType size, bool) {
                return String(data, size, false) && !stack.empty() && stack.back().object
                    && stack.back().keys.emplace(data, size).second;
            }
        };
        json_object *member(json_object *p, const char *k, json_type type)
        {
            json_object *v = nullptr;
            return p && json_object_get_type(p) == json_type_object && json_object_object_get_ex(p, k, &v) && v
                            && json_object_get_type(v) == type
                    ? v
                    : nullptr;
        }
        bool equals(json_object *p, const char *k, std::string_view expected)
        {
            auto *v = member(p, k, json_type_string);
            return v && std::string_view(json_object_get_string(v), json_object_get_string_len(v)) == expected;
        }
        bool pythonSpace(unsigned codepoint)
        {
            // Python str.strip/isspace semantics: empirical Unicode property set,
            // independent of the process locale and the UTF-8 byte spelling.
            return (codepoint >= 0x09 && codepoint <= 0x0d)
                || (codepoint >= 0x1c && codepoint <= 0x20)
                || codepoint == 0x85 || codepoint == 0xa0 || codepoint == 0x1680
                || (codepoint >= 0x2000 && codepoint <= 0x200a)
                || codepoint == 0x2028 || codepoint == 0x2029 || codepoint == 0x202f
                || codepoint == 0x205f || codepoint == 0x3000;
        }
        std::string trimmed(std::string s)
        {
            rapidjson::MemoryStream input(s.data(), s.size());
            std::size_t first = std::string::npos, last = 0;
            while (input.Tell() < s.size()) {
                const auto begin = input.Tell();
                unsigned codepoint = 0;
                if (!rapidjson::UTF8<>::Decode(input, &codepoint))
                    throw PlannerError("trusted_image_unavailable");
                if (!pythonSpace(codepoint)) {
                    if (first == std::string::npos) first = begin;
                    last = input.Tell();
                }
            }
            return first == std::string::npos ? std::string() : s.substr(first, last - first);
        }
        PlannerJson output(ProcessRunner &r, const ProcessArgs &a)
        {
            return plannerJson(r.run(a));
        }
        json_object *one(PlannerJson &j)
        {
            return json_object_get_type(j.get()) == json_type_array && json_object_array_length(j.get()) == 1
                    ? json_object_array_get_idx(j.get(), 0)
                    : nullptr;
        }
        std::string sandbox(ProcessRunner &r, const ProcessArgs &tail)
        {
            auto a = trustedSandboxArgs();
            a.insert(a.end(), tail.begin(), tail.end());
            auto v = r.run(a);
            if (v.size() > 1024 * 1024)
                throw PlannerError("trusted_image_unavailable");
            return v;
        }
    }
    PlannerJson plannerJson(std::string_view raw, std::size_t limit)
    {
        if (raw.empty() || raw.size() > limit || raw.size() > INT_MAX || raw.find('\0') != std::string_view::npos)
            throw PlannerError("invalid_json");
        rapidjson::MemoryStream stream(raw.data(), raw.size());
        rapidjson::Reader reader;
        UniqueKeys keys;
        if (!reader.Parse<rapidjson::kParseValidateEncodingFlag>(stream, keys)
            || !keys.stack.empty() || stream.Tell() != raw.size())
            throw PlannerError("invalid_json");
        std::unique_ptr<json_tokener, decltype(&json_tokener_free)> t(json_tokener_new_ex(32), json_tokener_free);
        if (!t)
            throw PlannerError("invalid_json");
        json_tokener_set_flags(t.get(), JSON_TOKENER_STRICT | JSON_TOKENER_VALIDATE_UTF8);
        PlannerJson j(json_tokener_parse_ex(t.get(), raw.data(), int(raw.size())));
        if (!j || json_tokener_get_error(t.get()) != json_tokener_success)
            throw PlannerError("invalid_json");
        for (auto i = json_tokener_get_parse_end(t.get()); i < raw.size(); ++i)
            if (!std::isspace(static_cast<unsigned char>(raw[i])))
                throw PlannerError("invalid_json");
        return j;
    }
    bool trustedImageIdentity(json_object *p) noexcept
    {
        auto *digests = member(p, "RepoDigests", json_type_array);
        if (!digests)
            return false;
        bool found = false;
        for (std::size_t i = 0; i < json_object_array_length(digests); ++i) {
            auto *v = json_object_array_get_idx(digests, i);
            if (v && json_object_get_type(v) == json_type_string
                && std::string_view(json_object_get_string(v), json_object_get_string_len(v)) == TrustedImage)
                found = true;
        }
        if (!found)
            return false;
        std::string_view manifest = std::string_view(TrustedImage).substr(std::string_view(TrustedImage).find('@') + 1);
        return equals(p, "Id", TrustedImageId)
                || (equals(p, "Id", manifest) && equals(member(p, "Descriptor", json_type_object), "digest", manifest));
    }
    ProcessArgs trustedSandboxArgs()
    {
        return { "docker",         "run",
                 "--rm",           "--network",
                 "none",           "--read-only",
                 "--cap-drop",     "ALL",
                 "--security-opt", "no-new-privileges:true",
                 "--pids-limit",   "32",
                 "--memory",       "64m",
                 "--cpus",         "1" };
    }
    std::string resolveTrustedImage(ProcessRunner &r)
    {
        try {
            auto host = output(r, { "docker", "info", "--format", "{{json .}}" });
            if (json_object_get_type(host.get()) != json_type_object)
                throw PlannerError("trusted_image_unavailable");
            if (!equals(host.get(), "OSType", "linux")
                || (!equals(host.get(), "Architecture", "x86_64") && !equals(host.get(), "Architecture", "amd64")))
                throw PlannerError("unsupported_server_architecture");
            bool cached = false;
            try {
                auto j = output(r, { "docker", "image", "inspect", TrustedImage });
                auto *p = one(j);
                cached = trustedImageIdentity(p) && equals(p, "Os", "linux") && equals(p, "Architecture", "amd64");
            } catch (...) {
                cached = false;
            }
            if (!cached) {
                try {
                    r.run({ "docker", "pull", "--platform", "linux/amd64", TrustedImage });
                } catch (const ProcessFailure &e) {
                    if (e.kind != ProcessFailureKind::Other)
                        throw PlannerError("image_fetch_unavailable");
                    throw;
                }
            }
            auto images = output(r, { "docker", "image", "inspect", TrustedImage });
            auto *p = one(images);
            if (!trustedImageIdentity(p))
                throw PlannerError("trusted_image_unavailable");
            if (!equals(p, "Os", "linux") || !equals(p, "Architecture", "amd64"))
                throw PlannerError("unsupported_server_architecture");
            if (trimmed(sandbox(r, { "--entrypoint", "sha256sum", TrustedImage, "/usr/bin/amneziawg-go" }))
                != std::string(TrustedBinarySha256) + "  /usr/bin/amneziawg-go")
                throw PlannerError("trusted_image_unavailable");
            if (trimmed(sandbox(r, { "--entrypoint", "/usr/bin/amneziawg-go", TrustedImage, "--version" }))
                != TrustedReportedVersion)
                throw PlannerError("trusted_image_unavailable");
            if (sandbox(r,
                        { "--entrypoint", "sh", TrustedImage, "-c",
                          "set -eu; for tool in awg awg-quick amneziawg-go iptables ip sleep mv cat cut sha256sum; do "
                          "command -v \"$tool\" >/dev/null; done; printf ready" })
                != "ready")
                throw PlannerError("trusted_image_unavailable");
            return TrustedImage;
        } catch (const PlannerError &e) {
            if (std::string_view(e.code()) == "unsupported_server_architecture"
                || std::string_view(e.code()) == "image_fetch_unavailable")
                throw;
            throw PlannerError("trusted_image_unavailable");
        } catch (...) {
            throw PlannerError("trusted_image_unavailable");
        }
    }
}
