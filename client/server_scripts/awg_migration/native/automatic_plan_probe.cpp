#include "automatic_plan.h"
#include <algorithm>
#include <iostream>
#include <iterator>
using namespace amnezia::awgMigration;
namespace
{
    json_object *get(json_object *p, const char *k, json_type type)
    {
        json_object *v = nullptr;
        if (!p || !json_object_object_get_ex(p, k, &v) || !v || json_object_get_type(v) != type)
            throw PlannerError("fixture_shape");
        return v;
    }
    std::string str(json_object *p, const char *k)
    {
        auto *v = get(p, k, json_type_string);
        return { json_object_get_string(v), std::size_t(json_object_get_string_len(v)) };
    }
    // Test-only byte-output seam; never part of a production CLI.
    std::string unhex(const std::string &value)
    {
        if (value.size() % 2 || value.size() > 2 * 1024 * 1024)
            throw PlannerError("fixture_shape");
        const auto nibble = [](unsigned char c) -> unsigned {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw PlannerError("fixture_shape");
        };
        std::string result; result.reserve(value.size() / 2);
        for (std::size_t i = 0; i < value.size(); i += 2)
            result.push_back(static_cast<char>((nibble(value[i]) << 4) | nibble(value[i + 1])));
        return result;
    }
    struct Runner : ProcessRunner
    {
        json_object *responses {};
        std::size_t position {};
        std::vector<ProcessArgs> calls;
        std::string run(const ProcessArgs &a) override
        {
            calls.push_back(a);
            if (!responses || position >= json_object_array_length(responses))
                throw ProcessFailure(ProcessFailureKind::Other);
            auto *r = json_object_array_get_idx(responses, position++);
            auto *args = get(r, "args", json_type_array);
            ProcessArgs expected;
            for (std::size_t i = 0; i < json_object_array_length(args); ++i) {
                auto *x = json_object_array_get_idx(args, i);
                if (!x || json_object_get_type(x) != json_type_string)
                    throw PlannerError("fixture_shape");
                expected.emplace_back(json_object_get_string(x), json_object_get_string_len(x));
            }
            if (a != expected)
                throw ProcessFailure(ProcessFailureKind::Other);
            json_object *failure = nullptr;
            if (json_object_object_get_ex(r, "failure", &failure)) {
                auto k = str(r, "failure");
                throw ProcessFailure(k == "exit"              ? ProcessFailureKind::Exit
                                             : k == "timeout" ? ProcessFailureKind::Timeout
                                             : k == "os"      ? ProcessFailureKind::Os
                                                              : ProcessFailureKind::Other);
            }
            json_object *hex = nullptr;
            if (json_object_object_get_ex(r, "output_hex", &hex)) {
                json_object *ordinary = nullptr;
                if (json_object_object_get_ex(r, "output", &ordinary))
                    throw PlannerError("fixture_shape");
                return unhex(str(r, "output_hex"));
            }
            return str(r, "output");
        }
    };
}
int main()
{
    Runner runner;
    PlannerJson result(json_object_new_object());
    try {
        std::string raw((std::istreambuf_iterator<char>(std::cin)), {});
        auto j = plannerJson(raw);
        auto *p = j.get();
        json_object *responses = nullptr;
        if (json_object_object_get_ex(p, "responses", &responses))
            runner.responses = responses;
        auto mode = str(p, "mode");
        PlannerJson value;
        if (mode == "automatic") {
            UdpPorts ports;
            auto *a = get(p, "occupied", json_type_array);
            for (std::size_t i = 0; i < json_object_array_length(a); ++i) {
                auto *v = json_object_array_get_idx(a, i);
                if (json_object_get_type(v) != json_type_int)
                    throw PlannerError("fixture_shape");
                ports.insert(unsigned(json_object_get_int64(v)));
            }
            auto request = automaticPlan(str(p, "root"), str(p, "source"), str(p, "host"), str(p, "image"), str(p, "raw"),
                                         unsigned(json_object_get_int64(get(p, "sourcePort", json_type_int))), ports);
            value = plannerJson(automaticRequestJson(request));
        } else if (mode == "inventory") {
            auto ports = occupiedUdpPorts(runner);
            value.reset(json_object_new_array());
            for (auto n : ports)
                json_object_array_add(value.get(), json_object_new_int64(n));
        } else if (mode == "trusted") {
            auto image = resolveTrustedImage(runner);
            value.reset(json_object_new_string(image.c_str()));
        } else
            throw PlannerError("fixture_shape");
        json_object_object_add(result.get(), "ok", json_object_new_boolean(true));
        json_object_object_add(result.get(), "value", value.release());
    } catch (const PlannerError &e) {
        json_object_object_add(result.get(), "ok", json_object_new_boolean(false));
        json_object_object_add(result.get(), "error", json_object_new_string(e.code()));
    } catch (...) {
        json_object_object_add(result.get(), "ok", json_object_new_boolean(false));
        json_object_object_add(result.get(), "error", json_object_new_string("fixture_error"));
    }
    auto *calls = json_object_new_array();
    for (auto &a : runner.calls) {
        auto *row = json_object_new_array();
        for (auto &s : a)
            json_object_array_add(row, json_object_new_string_len(s.data(), int(s.size())));
        json_object_array_add(calls, row);
    }
    json_object_object_add(result.get(), "calls", calls);
    std::cout << json_object_to_json_string_ext(result.get(), JSON_C_TO_STRING_PLAIN) << '\n';
}
