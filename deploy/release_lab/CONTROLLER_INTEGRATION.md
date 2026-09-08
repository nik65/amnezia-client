# Controller integration contract

The controller owns lifecycle and evidence collection. It should map the
canonical JSON profile IDs to these assets:

| controller ID | seed/template | image source | display | NIC | post-seal network |
| --- | --- | --- | --- | --- | --- |
| `windows-x64` | `guest_templates/windows11/autounattend.xml.template` + `install-qga.cmd` | Microsoft 25H2 evaluation ISO, plus verified `virtio-win` support ISO for QGA | private VNC/QMP | e1000 | no WAN |
| `linux-x64-gui` | `guest_templates/linux-gui/user-data` | verified Ubuntu Noble cloud image | private VNC/QMP | e1000 | no WAN |
| `linux-headless-x64` | `guest_templates/linux-headless/user-data` | verified Ubuntu Noble cloud image | none | e1000 | no WAN |
| `server-router` | `guest_templates/server-router/user-data` | verified Ubuntu Noble cloud image | none | guest-only test NIC | no WAN |

`bootstrap_guest.py` is the guarded golden-image entrypoint. It verifies the
base SHA-256, prepares a new output directory, and prints a plan unless
`--execute` is explicitly supplied. With `--execute` it boots a temporary
guest with user-mode NAT, waits for the guest marker through QGA, disables the
provisioning NIC through QMP, powers down, and records the golden disk hash.
Windows additionally requires the verified support ISO and Microsoft-keyed
OVMF/swtpm; the helper creates fresh TPM state and OVMF variables per output.
The helper never mutates host networking and never launches a host Amnezia
installer.

Every QEMU invocation must include private Unix QMP and QGA sockets under the
dedicated lab state root, `-nographic` for headless lanes, and an explicit
network decision. An omitted `-netdev` means an isolated guest, while a
temporary user-mode NAT device is allowed only during provisioning before the
golden snapshot is sealed. The controller must record the transition and
detach the NAT device before running candidate install/update tests.

Windows requires OVMF Microsoft Secure Boot variables and a swtpm 2.0 device;
the first install uses SATA/e1000. During first logon, `install-qga.cmd` adds
the signed `vioserial/w11/amd64/vioser.inf` package with `pnputil` and installs
`guest-agent/qemu-ga-x86_64.msi`, both read from the separately attached
support ISO. Do not enable test-signing or silently add unsigned VirtIO
drivers. Linux GUI automation consumes a private VNC socket so
background tests do not create a host popup; a human can attach a viewer when
diagnosing a guest.

No receipt is accepted from a host path. For QEMU guests the controller writes
the run marker through QGA, waits for every guest assertion to exit, and builds
the receipt only from QGA readback and those completed assertions. Android's
adapter must emit the equivalent common receipt under its owned adapter root.
Provisioning users,
SSH keys, Windows labadmin passwords, candidate artifacts, and production
credentials are runtime inputs kept outside Git.
