# Windows host Hyper-V alternative

The WSL QEMU Windows lane is currently blocked by a reproducible firmware/TCG
boot failure. This directory contains a manual host alternative. It is
separate from the WSL lab and is plan-only unless an operator explicitly uses
`-Enable`.

The first manual command, from an elevated PowerShell started by the user, is:

```powershell
powershell.exe -NoProfile -File .\deploy\release_lab\windows_host\enable_hyperv.ps1 -Enable -GrantCurrentOperatorHyperVAdministrators
```

The script calls only:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All -NoRestart
```

It never calls `Restart-Computer`, changes WSL, stops or reconnects the host
VPN, changes routes/DNS/firewall, creates a switch, creates a VM, or restores
network access. Enabling a Windows feature can itself interrupt services and
the manual restart can interrupt network connectivity; the script reports
`RestartNeeded`, and the user decides when to save work and restart. The script
requires Windows 11 Pro/Enterprise and an administrator token for `-Enable`.
The optional grant resolves the localized built-in `Hyper-V Administrators`
group by SID `S-1-5-32-578` and adds only the current operator SID; it never
adds arbitrary accounts. If that group is not present until after the feature
restart, the result records `grant_pending` instead of claiming success.

After the feature is enabled and the user has restarted manually, run the
read-only VM definition preview:

```powershell
pwsh -NoProfile -File .\deploy\release_lab\windows_host\prepare_hyperv_windows_vm.ps1 `
  -Iso C:\path\to\Windows11-25H2-evaluation-amd64.iso `
  -AnswerSeed C:\path\to\windows-answer.iso
```

The preview verifies the pinned Microsoft ISO SHA-256 and answer seed, then
prints a future Gen 2 definition: 4 vCPU, 8 GiB RAM, 128 GiB VHDX, Microsoft
Windows Secure Boot template, vTPM, and no physical/default network adapter.
If networking is required for a guest-only setup, the future command uses a
Private Hyper-V switch. The preview never calls `New-VM`, `New-VMSwitch`,
`Start-VM`, `Enable-VMTPM`, or any network cmdlet.

Windows guest automation uses PowerShell Direct after the VM is running. It
does not require a guest NIC and is supported for Windows 10 or later guests
with a configured user profile. The lab uses a local `labadmin` account with
normal UAC; credentials remain runtime inputs outside Git. After the one-time
manual feature enable/restart, the backend uses the enabled `Hyper-V
Administrators` group and a non-mutating Hyper-V management-plane probe, so
normal plan/status/start/stop/finalize/collect runs do not require a full
administrator token. The backend does not query DISM online, enable features,
or reboot the host.

## Sealed OS baseline

The Hyper-V OS baseline was completed and independently read back on
2026-09-09. Windows 11 EnterpriseEval 25H2/build 26200 is licensed with
positive evaluation grace. The VM is Off and its self-contained 128 GiB VHDX
has marker/VHD SHA-256
`8ded92f7c7a2f522dd6609f6afbb9e023515055ac3cd3db1309df9214e7275cb`; readback
also records Secure Boot `MicrosoftWindows`, first boot on the owned VHD, 0
DVD, 0 NIC, and automatic checkpoints disabled. This proves OS readiness for
the separate Hyper-V path. It does not connect the backend to `lab.py`, and it
does not prove thin/outer installer, interactive UI/UAC, reboot/rollback, or
self-hosted publication evidence.

Sources checked 2026-09-09:

* [Install Hyper-V](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/Install-Hyper-V) documents Windows Pro/Enterprise requirements, the elevated PowerShell command, and the restart needed to complete feature installation.
* [Manage Windows Virtual Machines with PowerShell Direct](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/powershell-direct) documents PowerShell Direct for Windows 10 or later guests without relying on network configuration.
* [Create a virtual machine in Hyper-V](https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/create-a-virtual-machine-in-hyper-v) documents Gen 2 VM creation prerequisites, memory/disk requirements, and optional virtual switch use.
