# bux-guest

Guest agent (typically PID 1) inside a bux micro-VM.

## Workload isolation

| Phase | Mode | Behaviour |
|-------|------|-----------|
| **A** | `phase_a` | Direct `exec` in the agent mount/PID namespace (shared with agent). |
| **B** | `phase_b` | Primary OCI container via **libcontainer**; exec enters its namespaces with `nsenter`. |

Boot tries Phase B when `GuestBootConfig.primary_container` is true (default). Failure falls back to Phase A without aborting the agent. Ping reports `workload_isolation`.

Exec flag `ExecStart.in_container`:

- `None` — use container when Phase B ready
- `Some(true)` — require Phase B
- `Some(false)` — force Phase A
