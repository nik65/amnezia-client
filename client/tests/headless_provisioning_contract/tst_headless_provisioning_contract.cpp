#include "core/controllers/selfhosted/headlessProvisioning.h"
#include <cstdio>

int main()
{
    using amnezia::selfhostedUpdates::hasSupportedHeadlessProvisioningFiles;
    int failures = 0;
    auto check = [&](bool condition) { failures += condition ? 0 : 1; };
    QJsonArray legacy {
        "install_headless.sh", "amneziad", "amnezia-cli", "amneziad.service",
        "package-manifest.json", "runtime-dependencies.json", "runtime-dependencies.txt", "SHA256SUMS"
    };
    check(hasSupportedHeadlessProvisioningFiles(legacy));
    QJsonArray native = legacy;
    native.append("amnezia-headless-fs");
    check(hasSupportedHeadlessProvisioningFiles(native));
    check(!hasSupportedHeadlessProvisioningFiles(QJsonValue()));
    check(!hasSupportedHeadlessProvisioningFiles(QJsonArray()));
    native[native.size() - 1] = "foreign-executable";
    check(!hasSupportedHeadlessProvisioningFiles(native));
    native[native.size() - 1] = "amnezia-headless-fs";
    native.append("extra");
    check(!hasSupportedHeadlessProvisioningFiles(native));
    legacy.removeLast();
    check(!hasSupportedHeadlessProvisioningFiles(legacy));
    legacy.append("SHA256SUMS");
    legacy[0] = "amneziad";
    check(!hasSupportedHeadlessProvisioningFiles(legacy));
    native = { "amnezia-headless-fs", "install_headless.sh", "amneziad", "amnezia-cli", "amneziad.service",
               "package-manifest.json", "runtime-dependencies.json", "runtime-dependencies.txt", "SHA256SUMS" };
    check(!hasSupportedHeadlessProvisioningFiles(native));
    std::printf("headless provisioning contract: %d failures\n", failures);
    return failures ? 1 : 0;
}
