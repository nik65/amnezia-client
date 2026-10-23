# ServerX diagnostic collector route

This scoped Bash/systemd helper restores TCP 17866 diagnostics after the known
ServerX `amnezia-awg2` container is restarted or recreated. It never restarts,
stops, removes or changes the VPN parent, bridge collector, host routes, DNS or
firewall. It changes only the diagnostic NAT redirect inside that verified VPN
container and its owned diagnostic sidecar.

Runtime dependencies already verified on ServerX: Bash, Docker, jq, coreutils,
flock, awk and Linux procfs. The helper adds no Python dependency; the existing
collector remains its reviewed Python image and source.

## Identity and recovery

- Source name, image ID and AWG public key are pinned in `reconcile.sh`. A new
  Docker ID is accepted only when those logical-server identities still match.
- The collector image, source SHA-256, command line, bootstrap/scope environment
  and single writable `/data` mount are verified. The initial legacy sidecar
  is accepted only by its exact recorded Docker ID. Replacements require this
  helper's dedicated ownership label.
- The source PID, start time and actual network namespace are checked before
  and after the public-key query and around mutations. A listener is proven by
  the collector PID's exact command line and its own socket inode in procfs.
- A namespace lost on a restart of the same source ID restarts only the owned
  collector. A new source ID creates a labelled candidate in the new namespace.
  Its listener is proved before the old owned collector is removed. The live
  candidate is renamed to the active name; an interrupted rename is recoverable
  on the next timer invocation.
- Existing plain redirects are preserved. Missing rules are added with a unique
  ownership comment. Failed final verification rolls back only that confirmed
  marked addition in the same source epoch. An uncertain add or a changed epoch
  never causes a speculative delete; concurrent plain rules remain untouched.

The timer checks thirty seconds after boot and thirty seconds after each
completed invocation. It intentionally refuses an unreviewed image/key/source
change. Such upgrades require explicit review and repinning. Do not report
arbitrary future images or another publisher's sidecar as automatically covered.

## Deployment and verification

Install the exact reviewed `reconcile.sh` as root-owned mode 0700 at
`/usr/local/sbin/amnezia-client-logs-route-serverx`. Install the two matching unit
files into `/etc/systemd/system/`, then use `systemctl daemon-reload` and enable
the timer. The first live invocation must verify current root directory mode
0700, identities, source hash and the existing rule before any mutation. This
is server diagnostics maintenance, not application release publication.

Verify the service exit status, enabled/active timer, exact NAT rule/counter,
unchanged VPN parent PID/StartedAt, and real Android batches. A successful
command alone is not runtime or full release acceptance. Production container
recreation is not required for acceptance: exercise it in an isolated owned
Docker fixture and retain that evidence separately from the current live check.

Rollback: disable/stop only this timer; remove only these installed helper/unit
files if desired. Do not delete an existing NAT rule or collector merely because
the timer was disabled. They may be serving current clients.

## Focused tests

On Linux/WSL:

```
python3 deploy/serverx_client_logs_route/test_reconcile.py
```

Tests execute a copy with fixed fixture paths, a private fake Docker executable
and fake procfs. They never invoke real Docker, VPN operations or host networking.
The deployed helper has no path/environment override mechanism.
