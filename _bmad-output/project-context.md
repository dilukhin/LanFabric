---
project_name: 'LanFabric'
user_name: 'Dima'
date: '2026-06-09'
sections_completed:
  ['technology_stack', 'language_rules', 'workflow_rules', 'critical_rules', 'testing_rules']
status: 'complete'
optimized_for_llm: true
---

# Project Context for AI Agents

_This file contains critical rules and patterns that AI agents must follow when implementing code in this project. Focus on unobvious details that agents might otherwise miss._

---

## Technology Stack & Versions

### Python
- Python 3.12+ required for both client (`vcli-admin.py`) and server (`vsrv-admin.py`) modules
- Only Python standard library — no `requirements.txt`, no external PyPI dependencies
- No external Python package manager for project code

### Operating Systems
- **Server:** Ubuntu 22.04 or 24.04
- **Admin Client:** Windows or Linux
- Windows client must have `ssh`/`scp` and Python 3.12+; `winget` required for `install-client`

### Connectivity & Access
- Server must have SSH access and a user with `sudo`
- Backend: only `awg` (AmneziaWG) or `wg` (WireGuard)
- Backend is chosen at `init` and persisted at `/opt/vpn-admin/backend`
- Automatic fallback `awg -> wg` is forbidden

### Versioning
- Version defined as `__version__ = "major.minor.patch"` in both `vcli-admin.py` and `vsrv-admin.py`
- **Exact match:** all commands allowed
- **Patch differs (only patch):** regular server commands blocked, must run `patch`
- **Major or minor differs:** only `init` is allowed
- Updates must only increase version respecting major-minor-patch hierarchy
- Server module is updated via `patch` command; manual copy by user is forbidden

### Security-Sensitive Operations
- Network, systemd, iptables, sudoers, authorized_keys changes are security-sensitive and require explicit user intent

---

## Critical Implementation Rules

### Language-Specific Rules (Python)

**Module structure:**
- Maintain monolithic structure of `vcli-admin.py` and `vsrv-admin.py` — do not split into packages without a separate decision.

**Type system:**
- Do not add type hints without a separate decision — project style is bare Python.
- Do not add `dataclass`, `enum`, `pathlib`-only rewrites, classes, or abstractions unless necessary.

**Dependencies:**
- No external Python dependencies. Standard library only.
- Do not add `requirements.txt`, `pyproject.toml`, `poetry`, `ruff`, `black`, `mypy`, `pytest` without a separate decision.

**Code style:**
- Preserve existing formatting; do not mass auto-format.
- CLI command functions named as `cmd_xxx`.
- Module-level constants in `SNAKE_CASE`.
- Exception classes (only when needed) in `CamelCase`.

**Language & documentation:**
- Comments, docstrings, help text, log messages, and errors in Russian.
- Raise `RuntimeError` with a clear Russian message for standard errors.
- Use the existing `add_advice`/`flush_advice` pattern for user recommendations.

**Security:**
- Never log private keys, passwords, client config contents, or secret values.
- Use `shlex.quote` when constructing diagnostic or composite shell text for `subprocess`.
- For Windows-specific logic, always check `platform.system() == "Windows"`.
- For server-side Linux logic, do not add Windows-specific dependencies.

**CLI contract:**
- Do not change the public argparse CLI contract without a separate task.
- New `argparse` arguments must have `help` in Russian.
- New commands must be added as a separate `cmd_xxx` function and a separate subparser.
- For clean stdout commands (`backend`, `config`, `--version`), do not add extraneous log output to stdout.

**Compatibility:**
- Code must remain compatible with Python 3.12+.

---

### Development Workflow Rules

**Pre-change discipline:**
- Before any changes, run `git status`.
- Do not start edits if the working tree is dirty without explicit user permission.
- Use a separate branch or `git worktree` for each non-trivial task.

**Commit & push:**
- Do not commit without explicit user instruction.
- Do not push without explicit user instruction.
- Do not change `__version__` without explicit instruction.
- Do not change `README.md` without explicit instruction (unless the task is documentation).

**Scope discipline:**
- Do not modify code, README, and agent configurations simultaneously unless specified in the task.
- Work in small iterations: one task — one minimal diff.
- First formulate a brief plan, then change files.
- After changes, show the list of modified files and a brief diff-summary.
- At the end, run relevant checks if they exist or are specified.

**Failure handling:**
- If checks fail after two fix attempts, stop and write a report.

**Security-sensitive zones:**
- Before touching security-sensitive zones, prepare a plan and wait for confirmation.
- Security-sensitive zones: SSH trust, sudo trust, `authorized_keys`, `sudoers`, iptables, systemd, SQLite schema, key generation, `patch`/`init`/`remove`/`purge`/`trust`/`untrust`.
- Do not execute real destructive commands on a server without explicit user confirmation.
- Do not run `init`/`remove`/`purge`/`trust`/`untrust` on a real server without explicit user permission.

**Reporting:**
- At the end of each agent task, produce a report: goal, modified files, commands, results, risks, unresolved questions.
- All prompts, reports, and comments in Russian.

**Architectural decisions:**
- If a task requires an architectural decision, stop and request a decision from a higher-level model.
- For non-trivial changes, use OpenSpec-lite / task card: goal, context, scope of change, acceptance criteria, stop conditions.

---

### Critical Don't-Miss Rules

#### Versions & Updates
- `major`/`minor`/`patch` have strict semantic meaning.
- If `major` or `minor` differs between client and server, only `init` is allowed.
- If only `patch` differs, regular commands are blocked; must run `patch`.
- `patch` only copies the server module and must NOT do a full `init`.
- Do not change `__version__` without explicit instruction.

#### CLI & stdout
- Commands `backend`, `config`, and `--version` must produce clean stdout with no extraneous log output.
- Logs and recommendations must NOT leak into the client `.conf` file.
- With `--debug`, do NOT enable `ssh -v` for `config`/`backend`/`version` — it would corrupt stdout.
- All new CLI arguments must have Russian `help` messages.
- Do not change existing CLI contract without a separate task.

#### Windows full-tunnel
- For full-tunnel on Windows, a route to the Endpoint bypassing VPN is required.
- `endpoint-route` works only on Windows.
- `config <name>` on Windows must automatically check/add the Endpoint route if `AllowedIPs = 0.0.0.0/0`.
- If the route cannot be added, the user must receive a clear advisory and must not enable full-tunnel until fixed.

#### Backend
- Valid backends: only `awg` and `wg`.
- Default `init` uses `awg`.
- `init --no-amnezia` explicitly chooses `wg`.
- Silent fallback `awg -> wg` is forbidden.
- For `awg`, parameters `Jc`/`Jmin`/`Jmax`/`S1`/`S2`/`H1`-`H4` must be persisted at `/opt/vpn-admin/awg_params` and included in server `setconf` and client `config`.
- Do not guess backend by checking for binary existence.

#### Firewall
- User ACCEPT rules for `internet=1` and `blocked=0` must be placed **before** the general DROP rule.
- `sync` must rebuild peers and dynamic firewall rules from SQLite.
- `health` must check FORWARD rule ordering.
- NAT currently uses `eth0`; do not change to auto-detection without a separate task.

#### Trust & security
- Temporary SSH trust and temporary sudo trust must be cleaned up in `finally`.
- Temporary SSH key must have marker `lanfabric-temp`.
- Permanent trust must have marker `lanfabric-trust`.
- `untrust` must NOT delete foreign keys without LanFabric markers.
- `untrust --all-lanfabric` requires explicit confirmation `REMOVE-ALL-LANFABRIC-KEYS`.
- `trust` requires explicit confirmation `TRUST`.
- `remove` requires `REMOVE`.
- `purge` requires `PURGE`.
- `delete` requires repeating the username.
- Never log private keys, passwords, `.conf` contents, sudo passwords, or secret values.

#### Server & runtime
- `init` is destructive: clears runtime state and reinitializes the server.
- `start` must NOT do a full `init`.
- `stop` must NOT delete data.
- `remove` removes runtime and packages but preserves `/opt/vpn-admin` and `/etc/wireguard`.
- `purge` completely removes LanFabric and requires the most explicit confirmation.
- For `awg`, `wg-quick@wg0` is NOT used as the primary runtime.
- For `wg`, `wg-quick@wg0` is used.
- Server module runs under `sudo` on Ubuntu; client module runs locally on Windows/Linux.

#### User experience
- The project is designed for "dumb users": dangerous actions require confirmations, errors must provide the next step.
- After successful commands, add recommendations via `add_advice`/`flush_advice`.
- Do not leave the user without guidance after an SSH/sudo/backend/config error.
- `README.md` must match the actual argparse and command behavior.

#### Development
- Do not split `vcli-admin.py` and `vsrv-admin.py` into packages without an architectural decision.
- Do not add external Python dependencies.
- Do not add a test framework without a separate decision.
- Do not perform mass refactoring alongside other changes.
- If a change affects SSH/sudo/iptables/systemd/SQLite schema, stop and request confirmation from a higher-level model.

---

### Testing Rules

- The project is gradually moving toward TDD.
- If a task changes behavior, first add or update a test when practically possible.
- Do not add `pytest` without a separate decision; prefer standard `unittest` or simple stdlib-based tests.
- Tests must NOT require a real server if behavior can be verified locally.
- For CLI, test argparse, command construction, version compatibility, dry-run/safe paths.
- Integration tests with real SSH/server may only be run with explicit permission.
- Tests must NOT use real secrets, private keys, real servers, or destructive commands.

---

## Usage Guidelines

**For AI Agents:**
- Read this file before implementing any code.
- Follow ALL rules exactly as documented.
- When in doubt, prefer the more restrictive option.
- Update this file if new patterns emerge.

**For Humans:**
- Keep this file lean and focused on agent needs.
- Update when technology stack changes.
- Review periodically for outdated rules.
- Remove rules that become obvious over time.

_Last updated: 2026-06-09_
