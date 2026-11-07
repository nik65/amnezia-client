Each profile is a reviewable shell environment file. The controller must
source exactly one profile and add QMP and QGA Unix sockets under the dedicated
lab root. `NETWORK_MODE` is a controller contract: NAT is allowed only while a
guest is being provisioned and sealed; after sealing, no guest has WAN access.
The profiles intentionally use e1000 for the Windows installer. Switching to
VirtIO requires a signed driver validation step and a profile change reviewed
with the release candidate.
