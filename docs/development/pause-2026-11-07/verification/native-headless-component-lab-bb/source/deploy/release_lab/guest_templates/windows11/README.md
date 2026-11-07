# Windows guest transport

The Windows lane cannot be considered ready from `Autounattend.xml` alone.
Before the first QGA receipt, the operator must provide a signed QEMU guest
agent MSI and the matching signed VirtIO serial driver package from an approved
vendor source. Record both SHA-256 values outside Git. The controller attaches
the private QGA Unix socket through a `virtio-serial` device and the guest runs
the installed `qemu-ga` service. The first Windows install still uses SATA and
e1000; only the QGA channel uses VirtIO, with its signed driver explicitly
validated.

The answer media uses an explicit GPT/EFI/MSR/NTFS disk layout on disk 0 and
installs Windows to partition 3. It carries a top-level `install-qga.cmd` and
an `amnezia-lab-seed-<nonce>.txt` marker under volume label `AMNEZIALAB`; the
one-time `labadmin` AutoLogon scans CD letters for that exact marker, copies
the script to `C:\ProgramData\AmneziaLab`, and runs it. A `$OEM$\$1` copy is
kept as a fallback. `READY` is written only after the QGA service reports
`RUNNING`. The controller attaches the
verified stable `virtio-win.iso` as a second CD during first boot. The command
installs `vioserial\w11\amd64\*.inf` with `pnputil` and then
`guest-agent\qemu-ga-x86_64.msi` with `msiexec`; both must be from the verified
stable image. SATA/e1000 remain the Windows install devices. The current
provisioning runner intentionally prepares only answer media and marks no
Windows baseline as ready until QGA and the guest marker are observed through
the private QGA socket. It must fail closed when the media is absent or
unverified, never enable Windows test-signing, and never fetch arbitrary
GitHub releases. A private SSH/WinRM transport can be used only if the
controller explicitly implements and reviews that separate transport; host
file polling is not guest evidence.
