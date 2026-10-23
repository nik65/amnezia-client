#pragma once
#include <json-c/json.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
namespace amnezia::awgMigration
{
    using ProcessArgs = std::vector<std::string>;
    enum class ProcessFailureKind {
        Exit,
        Timeout,
        Os,
        Other
    };
    class ProcessFailure final : public std::exception
    {
    public:
        ProcessFailureKind kind;
        explicit ProcessFailure(ProcessFailureKind k) : kind(k) { };
        const char *what() const noexcept override
        {
            return "private process failed";
        }
    };
    class PlannerError final : public std::runtime_error
    {
    public:
        explicit PlannerError(const std::string &code) : std::runtime_error(code) { };
        const char *code() const noexcept
        {
            return what();
        }
    };
    class ProcessRunner
    {
    public:
        virtual ~ProcessRunner() = default;
        virtual std::string run(const ProcessArgs &) = 0;
    };
    struct PlannerJsonDelete
    {
        void operator()(json_object *p) const noexcept
        {
            if (p)
                json_object_put(p);
        }
    };
    using PlannerJson = std::unique_ptr<json_object, PlannerJsonDelete>;
    PlannerJson plannerJson(std::string_view, std::size_t limit = 1024 * 1024);
    inline constexpr const char *TrustedImage =
            "amneziavpn/amneziawg-go@sha256:4e1fd2840f8d26eb6ec8bc1598e66f2f17f5d0201cd2baadbde560c104d4fc9d";
    inline constexpr const char *TrustedImageId =
            "sha256:777f70bf17917842a532ffba9643e92284ffc003e054a567e64fca74f97b8aff";
    inline constexpr const char *TrustedBinarySha256 =
            "6d96502ebd9ed6f9d17bdecd637cba7502c9960fed1b6922b3882784417a036d";
    inline constexpr const char *TrustedReportedVersion = "amneziawg-go 0.0.20250522\n\nUserspace AmneziaWG daemon for "
                                                          "linux-amd64.\nInformation available at https://amnezia.org";
    bool trustedImageIdentity(json_object *) noexcept;
    ProcessArgs trustedSandboxArgs();
    std::string resolveTrustedImage(ProcessRunner &);
}
