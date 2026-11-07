# Shared by the full client and standalone component builds.
# Explicit release/build overrides retain precedence over this default.
if(NOT AMNEZIAVPN_VERSION)
    set(AMNEZIAVPN_VERSION 5.0.3.18 CACHE STRING "Client app version")
endif()
