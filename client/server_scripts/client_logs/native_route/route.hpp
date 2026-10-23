#pragma once
#include <cstdint>
#include <json-c/json.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>
namespace collector_route
{
    using Args = std::vector<std::string>;
    struct Failure : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };
    struct JsonDeleter
    {
        void operator()(json_object *p) const
        {
            if (p)
                json_object_put(p);
        }
    };
    using Json = std::unique_ptr<json_object, JsonDeleter>;
    Json parse(const std::string &, std::size_t limit);
    struct Binding
    {
        std::string scope, sourceId, collectorId;
    };
    struct Container
    {
        std::string id, name, startedAt, image, label, network, nativeSha256;
        bool nativeProcess {};
        bool scopeEnvironment {};
        std::int64_t pid {};
        bool running {};
        bool mountValid {};
    };
    Binding binding(const std::string &);
    std::string collectorName(const std::string &scope);
    std::string canonical(const Binding &);
    Container inspectDocument(const std::string &, const std::string &scope, const std::string &root, bool publication = false);
    void validate(const Container &, const Container &, const Binding &);
    struct Result
    {
        int code;
        std::string output;
    };
    class Adapter
    {
    public:
        virtual ~Adapter() = default;
        virtual Result run(const Args &) = 0;
        virtual std::string netns(const Container &) = 0;
        virtual bool listener(const Container &) = 0;
        virtual void pause() = 0;
    };
    void publicationPreflight(Adapter &, const std::string &scope, const std::string &root);
    void reconcile(Adapter &, const Binding &, const std::string &root = "/opt/amnezia/client-logs");
    class PosixAdapter : public Adapter
    {
        std::string procRoot_;

    public:
        explicit PosixAdapter(std::string procRoot = "/proc") : procRoot_(std::move(procRoot)) { };
        Result run(const Args &) override;
        std::string netns(const Container &) override;
        bool listener(const Container &) override;
        void pause() override;
    };
    void cli(Adapter &, const Args &, const std::string &root = "/opt/amnezia/client-logs", unsigned trustedUid = 0);
}
