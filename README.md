# safer

Sleep better while AI agents have shell access.

```text
$ safer bash -lc 'rm go.mod'
safer: command requires user attention (blocked)
capabilities: read-only
action: block
command: bash -lc 'rm go.mod'
findings:
- bash -c [data-delete]: file deletion command requires user attention (rm)
instruction: bring this to the user's attention. Do not retry, rephrase, or bypass this command without explicit user approval.
exit status 2
```

`safer` is a command wrapper for AI coding agents with full shell access to a workspace.

By default, `safer` allows only known read-only commands. Anything that writes data, deletes data, mutates a runtime environment, changes infrastructure, or is not understood by `safer` requires an explicit capability flag.

`safer` is not a sandbox, a permissions system, or a CI/CD policy engine. It is a pre-execution guardrail for local agent workspaces.

## Why

AI agents are increasingly given broad access to real development workspaces. They can edit files, run package managers, operate Docker, call `kubectl`, query databases, and push git branches.

That is powerful, but it means an agent can accidentally run commands like:

- `rm -rf`
- `psql -c 'DELETE FROM users'`
- `kubectl delete pod api-0`
- `terraform destroy`
- `git push --force-with-lease`
- `curl ... | sh`

`safer` makes risky commands visible to a human by printing a clear alert and exiting with a dedicated status code. The point is to make an AI-operated workspace safer when the AI can run shell commands.

## Install

```sh
go install github.com/crufter/safer@latest
```

From a checkout:

```sh
go install .
```

## Quick Start

Known reads pass by default:

```sh
safer bash -lc 'cat go.mod'
safer kubectl get pods -A
```

Grant data write capability for ordinary workspace/data changes:

```sh
safer --data-write git commit -m change
safer --dw npm install
```

Grant ephemeral environment capability for temporary runtime/session operations:

```sh
safer --env-ephemeral kubectl port-forward svc/api 8080:80
safer --ee docker restart api
```

Grant persistent environment capability for infrastructure or remote state changes:

```sh
safer --env-persistent terraform apply
safer --ep helm upgrade api ./chart
```

Grant data delete capability only when deletion/removal is intentional:

```sh
safer --data-delete rm stale.log
safer --dd npm uninstall left-pad
```

Unknown commands are blocked unless explicitly allowed:

```sh
safer --allow-unknown custom-tool status
```

Inspect without executing:

```sh
safer --dry-run --dw git commit -m change
```

Warn but still execute:

```sh
safer --action=warn --ee docker restart api
```

## Agent Integration

Tell your coding agent that `safer` starts read-only and extra capabilities must be explicit.

Recommended defaults:

```sh
export SAFER_ACTION=block
```

### Codex

Add this to your Codex instructions:

```text
Run shell commands through safer when they may change files, dependencies,
databases, containers, clusters, cloud resources, git state, or remote services.

By default, use:
  safer <command> [args...]

Grant only the needed capability:
  safer --dw <command> [args...]  for data/workspace writes
  safer --dd <command> [args...]  for data deletion/removal
  safer --ee <command> [args...]  for temporary runtime/session operations
  safer --ep <command> [args...]  for persistent infrastructure/environment changes

If safer blocks a command, stop and ask me before retrying, rephrasing, or
attempting a different command with the same effect.
```

If you maintain a repository-specific `AGENTS.md`, put the instruction there so Codex sees it every time it works in the repo:

```md
## Command Safety

Use `safer` for shell commands.

Grant only the minimum capability needed:

- `--dw` for data/workspace writes
- `--dd` for data deletion/removal
- `--ee` for temporary runtime/session operations
- `--ep` for persistent environment/infrastructure changes

When `safer` exits with status 2, stop and ask for approval.
```

### Claude Code

Add this to your Claude Code project instructions, for example in `CLAUDE.md`:

````md
## Command Safety

Run potentially risky shell commands through `safer`.

Default read-only:

```sh
safer <command> [args...]
```

Grant capabilities only when needed:

```sh
safer --dw <command> [args...]
safer --ee <command> [args...]
safer --ep <command> [args...]
```

If `safer` blocks a command, do not retry or bypass it. Ask for explicit approval.
````

Examples Claude Code can follow:

```sh
safer --dw git commit -m change
safer --ee kubectl port-forward svc/api 8080:80
safer --ep terraform apply
safer --dd psql -c 'DELETE FROM users WHERE id = 1'
```

### Shell Aliases

Aliases are useful for humans, but agent tools may not load your interactive shell profile. Prefer explicit `safer ...` commands in agent instructions.

For interactive use:

```sh
alias sdw='safer --dw'
alias sdd='safer --dd'
alias see='safer --ee'
alias sep='safer --ep'
```

## CLI

```text
safer [flags] <command> [args...]
```

Capability flags:

```text
      --data-write       allow non-destructive data/workspace/database writes
      --data-delete      allow data deletion/removal and destructive data actions
      --env-ephemeral    allow temporary runtime/session/environment operations
      --env-persistent   allow persistent environment/infrastructure changes
      --allow-unknown    allow unknown commands/subcommands
```

Short aliases:

```text
      --dw   alias for --data-write
      --dd   alias for --data-delete
      --ee   alias for --env-ephemeral
      --ep   alias for --env-persistent
```

Other flags:

```text
      --action string   alert action: block or warn
      --dry-run         inspect only; do not execute the command
  -h, --help            help for safer
```

Defaults:

- no capabilities: known read-only commands only
- `--action=block`

## Capabilities

### Default: read-only

No flag is needed. Known read-only commands pass. Data writes, data deletes, environment mutations, and unknown commands block.

### `--data-write`

Allows non-destructive data/workspace/database writes.

Examples:

- SQL: `INSERT`, `UPDATE`, `CREATE`, `MERGE`, `COPY`
- Shell: `cp`, `mv`, `mkdir`, `touch`, `tee`
- Git: `git add`, `git commit`, non-destructive ref changes
- Packages: `npm install`, `go mod tidy`, `cargo add`
- Local files: `terraform init`, `terraform fmt`, `terraform plan -out`

### `--data-delete`

Allows destructive data deletion/removal.

Examples:

- SQL: `DELETE`, `DROP`, `TRUNCATE`, `ALTER`, `GRANT`, `REVOKE`
- Shell: `rm`, `rmdir`, `unlink`, `truncate`, `dd`, `mkfs`
- Git: `git reset --hard`, `git clean -f`, `git push --force`
- Package removals: `npm uninstall`, `apt remove`, `brew uninstall`
- Shell patterns: `curl | sh`, `find -delete`, `xargs rm`

### `--env-ephemeral`

Allows temporary runtime/session/environment operations.

Examples:

- Kubernetes: `kubectl exec`, `kubectl debug`, `kubectl port-forward`, `kubectl proxy`, `kubectl rollout restart`
- Containers: `docker restart`, `docker compose up`
- Services: `systemctl restart`, `service restart`

### `--env-persistent`

Allows persistent environment/infrastructure changes.

Examples:

- Kubernetes: `kubectl apply`, `kubectl patch`, `kubectl scale`
- Helm: `helm install`, `helm upgrade`, `helm rollback`
- Infrastructure: `terraform apply`, `pulumi up`
- Cloud CLIs: create/update/start/stop style operations
- Remote repository state: `git push`, GitHub CLI mutations

### `--allow-unknown`

Allows commands or subcommands that `safer` does not understand. Keep this off unless the command is project-specific and you know its behavior.

## Configuration

`safer` can read defaults from the nearest `.saferrc`, walking from the current directory up to the filesystem root. CLI flags override environment variables, and environment variables override `.saferrc`.

Example `.saferrc`:

```ini
data_write=false
data_delete=false
env_ephemeral=false
env_persistent=false
allow_unknown=false
action=block
```

Supported keys:

- `data_write`
- `data_delete`
- `env_ephemeral`
- `env_persistent`
- `allow_unknown`
- `action`: `block` or `warn`

Environment variables:

```sh
SAFER_DATA_WRITE=true
SAFER_DATA_DELETE=true
SAFER_ENV_EPHEMERAL=true
SAFER_ENV_PERSISTENT=true
SAFER_ALLOW_UNKNOWN=true
SAFER_ACTION=block
```

Compatibility aliases:

- `--readonly` and `--careful` mean no capabilities.
- `--nondestructive` means `--data-write --env-ephemeral --env-persistent`.
- `--care`, `--level`, `--mode`, `SAFER_CARE`, `SAFER_LEVEL`, `SAFER_MODE`, and old `.saferrc` mode values are still accepted for compatibility.

## Output

When a command is blocked, `safer` prints an alert and exits with status `2`:

```text
safer: command requires user attention (blocked)
capabilities: read-only
action: block
command: kubectl rollout restart deployment/api
findings:
- command [env-ephemeral]: kubectl rollout changes workload state (kubectl rollout restart)
instruction: bring this to the user's attention. Do not retry, rephrase, or bypass this command without explicit user approval.
```

With `--action=warn`, `safer` prints the same alert and then executes the command.

## Supported Tools

`safer` has first-pass policies for:

- SQL clients: `psql`, `mysql`, `mariadb`, `sqlite3`
- Shells: `bash`, `sh`, `zsh`, `fish`
- Kubernetes and releases: `kubectl`, `k`, `helm`
- Containers: `docker`, `docker-compose`
- Version control and GitHub: `git`, `gh`
- Infrastructure: `terraform`, `tofu`, `pulumi`
- Package managers: `npm`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `poetry`, `cargo`, `go`, `apt`, `apt-get`, `dnf`, `yum`, `brew`
- Services and cloud CLIs: `systemctl`, `service`, `aws`, `gcloud`, `az`

It also inspects:

- Inline SQL flags such as `psql -c`, `psql -f`, and `mysql -e`
- SQLite SQL arguments and `.read` files
- Shell payloads passed to `bash -c`, `bash -lc`, `sh -c`, `zsh -c`, and script files
- Nested commands such as `bash -lc "psql -c 'DELETE FROM users'"`

## Exit Codes

- `0`: command passed inspection and completed successfully, or `--dry-run` passed
- `1`: `safer` usage or validation error
- `2`: command was blocked
- Any other code: exit code from the wrapped command

## Development

Run tests:

```sh
go test ./...
```

Run the CLI locally:

```sh
go run . --help
go run . --dry-run --ee kubectl rollout restart deployment/api
```

## Limitations

`safer` uses conservative heuristics. It cannot understand every shell construct, every tool-specific plugin, or every domain-specific command.

It also cannot help if the agent simply does not use it. Integrate it through agent instructions, repo instructions, wrapper scripts, or a shell environment that makes `safer` the normal path for environment-changing commands.

For strict isolation, use an actual sandbox, container, VM, restricted credentials, or read-only infrastructure permissions. `safer` is meant to make full-access AI workspaces safer by catching common risky commands early and making them explicit.
