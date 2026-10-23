#pragma once

#if defined(__linux__) && !defined(__ANDROID__)
#include <systemd/sd-bus.h>
#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <poll.h>
#include <unistd.h>

namespace amnezia::ipc::linuxSystemd {

inline uint64_t monotonicUsec()
{
    timespec now {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return uint64_t(now.tv_sec) * 1000000 + uint64_t(now.tv_nsec) / 1000;
}

// Owns a caller-established nonblocking Unix connection. It never chooses an
// address, opens a default/session bus, launches a process, or retries connect.
class AsyncBus final {
public:
    explicit AsyncBus(uint64_t deadline) : deadline_(deadline) {}
    ~AsyncBus() { sd_bus_close(bus_); sd_bus_unref(bus_); }
    AsyncBus(const AsyncBus &) = delete;
    AsyncBus &operator=(const AsyncBus &) = delete;

    bool start(int fd)
    {
        if (bus_ || expired() || sd_bus_new(&bus_) < 0) { close(fd); return false; }
        if (sd_bus_set_fd(bus_, fd, fd) < 0) { close(fd); return false; }
        // sd_bus now owns fd; start queues Hello and does not wait for auth.
        if (sd_bus_set_bus_client(bus_, 1) < 0 || sd_bus_start(bus_) < 0) return false;
        while (!expired()) {
            const int ready = sd_bus_is_ready(bus_);
            if (ready < 0) return false;
            if (ready > 0) return true;
            if (!step()) return false;
        }
        return false;
    }

    sd_bus *get() const { return bus_; }
    bool expired() const { const auto now = monotonicUsec(); return !now || now >= deadline_; }

    // Returned reply is owned by caller. One global deadline includes initial
    // connect/auth/Hello and every request; per-request timeouts cannot extend it.
    sd_bus_message *request(sd_bus_message *message)
    {
        if (!bus_ || !message || expired()) return nullptr;
        struct Reply { bool done = false; sd_bus_message *message = nullptr; } reply;
        sd_bus_slot *slot = nullptr;
        const auto callback = [](sd_bus_message *m, void *data, sd_bus_error *) -> int {
            auto &result = *static_cast<Reply *>(data);
            result.done = true;
            result.message = sd_bus_message_ref(m);
            return 1;
        };
        const uint64_t now = monotonicUsec();
        if (!now || now >= deadline_) return nullptr;
        const uint64_t remaining = deadline_ - now;
        if (sd_bus_call_async(bus_, &slot, message, callback, &reply, remaining) < 0) {
            sd_bus_slot_unref(slot);
            return nullptr;
        }
        while (!reply.done && !expired()) if (!step()) break;
        sd_bus_slot_unref(slot); // unregister callback before stack data dies
        if (!reply.done || expired() || sd_bus_message_is_method_error(reply.message, nullptr) != 0) {
            sd_bus_message_unref(reply.message);
            return nullptr;
        }
        return reply.message;
    }

private:
    bool step()
    {
        if (expired()) return false;
        const int processed = sd_bus_process(bus_, nullptr);
        if (processed < 0 || expired()) return false;
        if (processed > 0) return true; // caller rechecks deadline even on floods
        const int fd = sd_bus_get_fd(bus_);
        const int events = sd_bus_get_events(bus_);
        uint64_t busTimeout = UINT64_MAX;
        if (fd < 0 || events < 0 || sd_bus_get_timeout(bus_, &busTimeout) < 0) return false;
        const uint64_t now = monotonicUsec();
        const uint64_t end = std::min(deadline_, busTimeout);
        if (!now || now >= deadline_) return false;
        const int timeoutMs = end <= now ? 0 : int(std::min<uint64_t>((end-now+999)/1000, 2000));
        pollfd wait {fd, short(events), 0};
        const int result = poll(&wait, 1, timeoutMs);
        if (result < 0) return errno == EINTR && !expired();
        return !(wait.revents & (POLLERR | POLLNVAL)) && !expired();
    }
    uint64_t deadline_;
    sd_bus *bus_ = nullptr;
};
}
#endif
