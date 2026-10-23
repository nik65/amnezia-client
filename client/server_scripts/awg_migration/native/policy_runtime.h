#pragma once
#include "policy.h"
namespace amnezia::awgMigration::policy
{
    std::string runReadOnlyDocker(const Lines &argv);
    std::string runtimeRequest(const std::string &request, const Runner &runner);
    int policyJsonMain();
}
