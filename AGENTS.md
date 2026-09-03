# Repository instructions

## Installer launch policy

Codex must never launch an AmneziaVPN installer autonomously. This includes
launching it from a build, release publication, update check, debugging step,
test, command-line operator mode, or `Start-Process`/equivalent wrapper.
If installation or an installer launch is needed, stop and ask the user to
launch it manually; do not infer permission from a request to build, publish,
or prepare an artifact.

## Release publication policy

Server-side release publication must be performed only by the self-hosted
Amnezia client flow. Do not add or run a standalone publisher, direct SSH/SCP
release upload, or equivalent server-side publication shortcut. Local manifest
and artifact generation is allowed; the resulting self-hosted client artifact
must be launched manually by the user when publication is required.

## Local workstation and orchestration policy

On this local PC only, Codex must never disconnect, reconnect, stop, restart,
or otherwise control an active VPN tunnel, the AmneziaVPN application or
service, or local VPN routes, DNS, or firewall. Codex must also never
uninstall, reinstall, launch, or otherwise initiate an AmneziaVPN/Amnezia
Client installer or local updater.

These prohibitions remain in force during release, publication, update,
debugging, testing, build, or operator requests; such requests do not grant
permission for those local actions. If any such action is needed, stop and
require the user to perform it manually.

The root agent is orchestration-only: it may read files and inspect status or
metadata, but must not write code or execute build, test, install, network, or
other executable commands. Delegate practical implementation, diagnostics,
builds, tests, and live checks to Luna/high subagents whenever available.

## Batched multi-agent audit policy

Before a consolidated implementation phase, complete one batch of 10
independent read-only audits by `gpt-5.6-luna` agents at `high` reasoning
effort. Each audit must cover a distinct area and must finish before the
consolidated code change begins.

Implement the agreed fixes as one consolidated change set. After the
consolidated release candidate is frozen, complete one final batch of 10
independent read-only reviews by `gpt-5.6-luna` agents at `high` reasoning
effort against that release candidate, before any build, release, or live
deployment.

Findings from the final batch are triaged and fixed together, followed by
focused verification proportional to the changes. Do not automatically start
another 10-agent cycle for every minor edit unless the user explicitly
requests another full batch. Batching must respect actual runtime
concurrency; when concurrency is lower than 10, run the batch in waves until
exactly 10 independent agents have completed. Do not count queued, failed,
interrupted, or duplicate reviews. The root agent only orchestrates this
process; practical auditing, implementation, review, builds, tests, and live
checks belong to the delegated Luna/high subagents.
