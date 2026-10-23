#pragma once
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <string>
namespace amnezia::awgMigration
{
    // Values are serialized JSON, parsed strictly with duplicate-object keys rejected.
    std::string controlCanonical(const std::string &json);
    std::string controlBootstrapGrant(const std::string &secret, const std::string &bindingJson);
    std::string controlSign(const std::string &payloadJson, const std::filesystem::path &directory);
    struct ControlRequest
    {
        std::string path, peerAddress, body;
        std::map<std::string, std::string> headers; // lowercase, transport rejects duplicates
    };
    struct ControlResponse
    {
        bool handled = false;
        int status = 403;
        std::string body;
    };
    struct ControlOptions
    {
        std::filesystem::path directory;
        std::string role, scope;
        std::function<std::int64_t()> clock;
    };
    class ControlService
    {
    public:
        explicit ControlService(ControlOptions options);
        ControlResponse dispatch(const ControlRequest &, const std::function<std::string()> &authenticate) const;

    private:
        ControlOptions options_;
    };
}
