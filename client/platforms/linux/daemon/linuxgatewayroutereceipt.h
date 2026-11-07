#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

namespace amnezia::linux_routes {
inline constexpr uint32_t OwnedGatewayRoutePriority = 1;
inline constexpr uint32_t TunnelRoutePriority = 2;
// IPv4 values are the exact four address bytes (network byte order).
struct RouteReceipt {
    uint32_t destination = 0, gateway = 0, interfaceIndex = 0;
    uint32_t table = RT_TABLE_MAIN, priority = OwnedGatewayRoutePriority;
    uint8_t prefixLength = 0, protocol = RTPROT_BOOT;
    uint8_t scope = RT_SCOPE_UNIVERSE, type = RTN_UNICAST;
};
enum class ReadbackResult { Match, Absent, Changed, Unknown };

// Pure bounded decoder. The caller owns the socket and supplies recvmsg metadata.
class RouteDumpParser {
public:
    RouteDumpParser(const RouteReceipt &receipt, uint32_t sequence, uint32_t port)
        : expected_(receipt), sequence_(sequence), port_(port) {}
    bool consume(const void *data, size_t length, uint32_t senderPid = 0, int msgFlags = 0)
    {
        if (failed_) return false;
        if (done_) return fail("data after done");
        if (senderPid || (msgFlags & (MSG_TRUNC | MSG_CTRUNC))) return fail("sender or truncation");
        if (!data || !length || length > MaxBytes - bytes_) return fail("byte limit or empty datagram");
        bytes_ += length;
        const auto *p = static_cast<const unsigned char *>(data);
        while (length) {
            if (++messages_ > MaxMessages || length < sizeof(nlmsghdr)) return fail("message limit or short header");
            nlmsghdr h{}; std::memcpy(&h, p, sizeof(h));
            if (h.nlmsg_len < sizeof(h) || h.nlmsg_len > length) return fail("invalid message length");
            if (h.nlmsg_seq != sequence_ || h.nlmsg_pid != port_) return fail("sequence or port mismatch");
            if (h.nlmsg_flags & (NLM_F_DUMP_INTR | NLM_F_DUMP_FILTERED)) return fail("interrupted or filtered dump");
            const size_t bodyLength = h.nlmsg_len - sizeof(h);
            const auto *body = p + sizeof(h);
            if (h.nlmsg_type == NLMSG_DONE) {
                if (bodyLength != 0 && bodyLength != sizeof(int)) return fail("invalid done status length");
                int status = 0;
                if (bodyLength) std::memcpy(&status, body, sizeof(status));
                if (status) return fail("dump error");
                done_ = true;
            } else if (h.nlmsg_type == RTM_NEWROUTE) {
                if (!route(body, bodyLength)) return false;
            } else if (h.nlmsg_type != NLMSG_NOOP) {
                return fail("unexpected message or netlink error");
            }
            const size_t aligned = NLMSG_ALIGN(h.nlmsg_len);
            // A final unpadded message is legal; partial padding is not.
            const size_t step = h.nlmsg_len == length ? length : aligned;
            if (step > length) return fail("partial message padding");
            p += step; length -= step;
            if (done_ && length) return fail("message after done");
        }
        return true;
    }
    ReadbackResult result() const {
        if (failed_ || !done_) return ReadbackResult::Unknown;
        if (!candidates_) return ReadbackResult::Absent;
        return matches_ ? ReadbackResult::Match : ReadbackResult::Changed;
    }
    bool complete() const { return done_ && !failed_; }
    const char *reason() const { return reason_; }
private:
    static constexpr size_t MaxBytes = 1024 * 1024, MaxMessages = 16384;
    bool fail(const char *why) { failed_ = true; reason_ = why; return false; }
    bool route(const unsigned char *data, size_t length) {
        if (length < sizeof(rtmsg)) return fail("short route");
        rtmsg r{}; std::memcpy(&r, data, sizeof(r));
        if (r.rtm_family != AF_INET && r.rtm_family != AF_INET6) return true;
        uint32_t dst = 0, gateway = 0, oif = 0, metric = 0, table = r.rtm_table;
        uint32_t seen = 0; bool unsupported = false;
        size_t offset = NLMSG_ALIGN(sizeof(rtmsg));
        if (length < offset) return fail("short route alignment");
        while (offset < length) {
            if (length - offset < sizeof(rtattr)) return fail("short attribute");
            rtattr a{}; std::memcpy(&a, data + offset, sizeof(a));
            if (a.rta_len < sizeof(a) || a.rta_len > length - offset) return fail("invalid attribute length");
            const unsigned kind = a.rta_type & NLA_TYPE_MASK;
            unsigned bit = 0; uint32_t *value = nullptr;
            switch (kind) {
            case RTA_DST: bit = 1; value = &dst; break;
            case RTA_GATEWAY: bit = 2; value = &gateway; break;
            case RTA_OIF: bit = 4; value = &oif; break;
            case RTA_PRIORITY: bit = 8; value = &metric; break;
            case RTA_TABLE: bit = 16; value = &table; break;
            case RTA_MULTIPATH: case RTA_VIA: case RTA_NH_ID: case RTA_SRC:
            case RTA_IIF: case RTA_METRICS: case RTA_ENCAP: case RTA_ENCAP_TYPE:
                unsupported = true; break;
            default: break;
            }
            if (bit) {
                if (seen & bit) return fail("duplicate relevant attribute");
                seen |= bit;
                const size_t size = a.rta_len - sizeof(a);
                const size_t required = r.rtm_family == AF_INET6 && (bit == 1 || bit == 2) ? 16 : 4;
                if (size != required || (a.rta_type & ~NLA_TYPE_MASK)) return fail("invalid relevant attribute");
                if (required == 4) std::memcpy(value, data + offset + sizeof(a), 4);
            }
            const size_t remaining = length - offset;
            const size_t step = a.rta_len == remaining ? remaining : RTA_ALIGN(a.rta_len);
            if (step > remaining) return fail("partial attribute padding");
            offset += step;
        }
        if (r.rtm_family != AF_INET) return true;
        if (r.rtm_dst_len > 32 || r.rtm_src_len > 32) return fail("invalid IPv4 prefix");
        if (r.rtm_dst_len != expected_.prefixLength || dst != expected_.destination
            || table != expected_.table || metric != expected_.priority
            || r.rtm_tos != 0 || r.rtm_src_len != 0) return true;
        if (++candidates_ > 1) return fail("duplicate route candidate");
        // Missing metric means zero. Missing gateway/oif cannot prove ownership.
        matches_ = (seen & 6) == 6 && (r.rtm_dst_len == 0 || (seen & 1))
            && !unsupported && r.rtm_src_len == 0 && r.rtm_tos == 0
            && !(r.rtm_flags & (RTM_F_CLONED | RTM_F_OFFLOAD_FAILED))
            && gateway == expected_.gateway && oif == expected_.interfaceIndex
            && metric == expected_.priority && r.rtm_protocol == expected_.protocol
            && r.rtm_scope == expected_.scope && r.rtm_type == expected_.type;
        return true;
    }
    RouteReceipt expected_;
    uint32_t sequence_, port_;
    size_t bytes_ = 0, messages_ = 0;
    unsigned candidates_ = 0;
    bool matches_ = false, done_ = false, failed_ = false;
    const char *reason_ = "pending";
};
} // namespace amnezia::linux_routes





