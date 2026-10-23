#pragma once
#include "trusted_image.h"
#include <cstdint>
#include <filesystem>
#include <set>
namespace amnezia::awgMigration
{
    using UdpPorts = std::set<unsigned>;
    UdpPorts occupiedUdpPorts(ProcessRunner &);
    unsigned selectUdpPort(const UdpPorts &, unsigned sourcePort);
    struct AutomaticRequest
    {
        std::string host, image;
        unsigned port {};
        std::uint64_t generation {};
    };
    AutomaticRequest automaticPlan(const std::filesystem::path &root, const std::string &source,
                                   const std::string &host, const std::string &image, std::string_view rawSource,
                                   unsigned sourcePort, const UdpPorts &);
    std::string automaticRequestJson(const AutomaticRequest &);
    enum class UdpFamily {
        V4,
        V6
    };
    class PortLease
    {
    public:
        virtual ~PortLease() = default;
        virtual void ipv6Only() = 0;
        virtual void bind(const std::string &address, unsigned port) = 0;
    };
    class PortProbe
    {
    public:
        virtual ~PortProbe() = default;
        virtual std::unique_ptr<PortLease> open(UdpFamily) = 0;
    };
    // No system-socket adapter here: preparation can supply a separately reviewed adapter.
    void verifyAutomaticPort(unsigned port, PortProbe &);
}
