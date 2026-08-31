# Agent integration

ActionLock is a local stdio MCP boundary. The hosted Vercel console is an inspection surface and cannot execute tools.

## Connection model

```text
agent MCP client
  -> ActionLock MCP server
     -> evidence and policy decision
     -> exact human approval when eligible
     -> allow-listed downstream MCP tool
     -> append-only local audit chain
```

Do not also expose the same downstream MCP server, shell, wallet, or social tool directly to the agent. That bypasses ActionLock.

## 1. Install

Use Node.js 20 or newer.

```bash
git clone https://github.com/Vegeta451/technocore-actionlock.git
cd technocore-actionlock
npm install
npm run check
```

## 2. Define the downstream policy

Copy `actionlock.config.example.json` to the ignored local file `actionlock.config.json`. Use absolute executable paths. Each exposed downstream tool must have a fixed capability, operation, target, and maximum argument size.

Keep `inheritEnv` empty unless the downstream server requires a specifically named variable. Never place secrets in this policy file.

## 3. Set the local secret

Generate at least 32 random bytes. Keep this value local and never commit it.

```bash
node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"
```

Set the output as `ACTIONLOCK_ROOT_SECRET`. Optionally set `ACTIONLOCK_CONFIG`, `ACTIONLOCK_STATE_DIR`, and `ACTIONLOCK_AUDIT_PATH` to absolute paths. `TECHNOCORE_ORIGIN` should remain `https://technocore.chat` outside loopback development.

## 4. Add ActionLock to the agent

Use the agent client's local stdio MCP settings. Replace the paths and secret locally:

```json
{
  "mcpServers": {
    "actionlock": {
      "command": "npm",
      "args": ["--prefix", "/absolute/path/technocore-actionlock", "run", "mcp"],
      "env": {
        "ACTIONLOCK_ROOT_SECRET": "<local-secret-at-least-32-bytes>",
        "ACTIONLOCK_CONFIG": "/absolute/path/actionlock.config.json"
      }
    }
  }
}
```

Restart the MCP client. It should discover only these ActionLock tools:

- `actionlock_read_room`
- `actionlock_list_policies`
- `actionlock_preview`
- `actionlock_execute`
- `actionlock_verify_audit`

## 5. Execute an approved call

1. Call `actionlock_read_room` and retain the short-lived evidence token.
2. Call `actionlock_list_policies`; an empty list means execution is disabled.
3. Call `actionlock_preview` with the exact server, tool, and arguments.
4. Review the action hash outside the agent process.
5. Run `npm run approve -- <action-hash>` locally.
6. Pass the returned one-time token to `actionlock_execute` without changing any argument.
7. Call `actionlock_verify_audit` after execution.

Approvals expire after 120 seconds and are consumed before the downstream call starts. Shell, wallet, and social actions derived from remote content remain blocked rather than approval-eligible.
