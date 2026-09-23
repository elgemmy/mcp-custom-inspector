# Odoo helpdesk tools over MCP

Two small Odoo AI tools, built as server actions and exposed through Odoo's MCP server, plus three Probe paths that test them as a black box.

| Tool | Writes | What it does |
|---|---|---|
| `create_helpdesk_ticket` | yes | Creates one ticket from a subject, description, priority, team name, and customer email |
| `list_helpdesk_teams` | no (Readonly Tool) | Lists the helpdesk teams the calling user can see |

## What this example demonstrates

- **Scoped tools rather than a generic `create_record`.** An agent given `create_record` can write any field on any model it can reach. A tool that only creates tickets, and only takes the five fields that matter, is much easier to review, test, and trust.
- **Errors are teaching signals.** When the code raises `UserError("No helpdesk team matches 'Billing'.")`, the agent reads that message and can correct itself, for example by calling `list_helpdesk_teams` first. A silent fallback teaches it nothing and leaves a misrouted ticket behind.
- **The readonly flag.** `list_helpdesk_teams` is marked Readonly Tool, so MCP clients see it as safe to call without asking. `create_helpdesk_ticket` is not.
- **Permissions do not change over MCP.** The server action runs with the calling user's access rights (no `sudo()`), so an MCP client sees exactly the teams and tickets that user would see in the Odoo UI.

## Files

```
tools/<tool>/code.py      the Execute Code body
tools/<tool>/schema.json  the AI input schema
tools/<tool>/meta.json    tool name, description, MCP and readonly flags
paths/smoke.json          both tools exposed, happy path
paths/validation.json     business-rule rejections (unknown team, blank subject, bad priority)
paths/malformed.json      inputs that break the schema; a clean rejection is a pass
```

## Server action contract

- Type **Execute Code**.
- Each schema property is injected into the code as a local variable of the same name.
- The tool's return value is whatever the code writes to `ai['result']`.
- `env` and `UserError` are available in the evaluation context.
- The action runs with the calling user's access rights.

Every property in `create_helpdesk_ticket`'s schema is required, and optional fields take an empty string. That guarantees every local variable exists when the code runs.

## Manual setup in the Odoo UI

For each folder under `tools/`:

1. Settings → Technical → Server Actions → New. Name it with `server_action_name` from `meta.json`, model **AI Tool** (`ai.tool`, where Odoo's own AI tools live), type **Execute Code**.
2. Paste `code.py` into the code editor.
3. On the **Usage** tab, enable **Use in AI**, set the tool name and the AI tool description from `meta.json`.
4. Enter the schema: add one row per property from `schema.json` (name, type, description, required), or use **Edit** to paste the JSON directly.
5. Tick **Available in MCP**. For `list_helpdesk_teams`, also tick **Readonly Tool**.
6. Save.

The helpdesk teams used by the paths are **Technical Support**, **Accounts & Invoicing**, and **Onboarding**. No team name may contain "billing": `validation.json` relies on `Billing` matching nothing. `smoke.json` and `validation.json` use the customer email `contact@brasserie-confluent.example`; create that contact, or edit the paths to use one of yours.

## Running the paths with Probe

The paths carry no server block, so pass the MCP endpoint with `--url`. Odoo's MCP server supports OAuth with dynamic client registration, which is the default route: log in once, approve in the browser, and keep the token in a file.

```bash
python3 mcp_probe.py login --url "$ODOO_MCP_URL" > .odoo-token
ODOO_MCP_TOKEN=$(cat .odoo-token) python3 mcp_probe.py run examples/odoo-helpdesk/paths/smoke.json --url "$ODOO_MCP_URL" --bearer-env ODOO_MCP_TOKEN
```

If OAuth is not available, use an Odoo API key of the user the calls should run as, through the environment:

```bash
python3 mcp_probe.py run examples/odoo-helpdesk/paths/validation.json --url "$ODOO_MCP_URL" --bearer-env ODOO_API_KEY
```

Add `--trace runs/odoo.jsonl` to append a `call` event per step with the `expect` object and an outcome of `success`, `tool_error`, `protocol_error`, or `transport_error`. Probe does not judge `expect` objects, so these runs exit 0 unless the transport fails; read the outcomes in the summary or the trace. `.odoo-token` is gitignored.

`smoke.json` and `validation.json` create tickets. Run them against a test database.

## Findings

Recorded by inspection. Items marked *not yet verified* need the demo database and must not be guessed.

1. **Probe path format and existing features.** Paths are `{name, description, server, handshake, timeout, steps}`, with raw `send` steps and `method`/`params` sugar steps. The string `expect` (`result`/`error`/`none`/`timeout`) already existed and flips the exit code; it cannot tell a tool error (`result.isError: true`) from success. An auth header was possible only through `--header`, which puts the token on the command line; there was no trace. `--bearer-env`, `--trace`, and the object form of `expect` were added for this example.
2. **AI Tool model and field names.** Odoo's own AI tools are server actions on `ai.tool` (an abstract model with no table), so these tools use it too. Fields on `ir.actions.server`: `use_in_ai` (Use in AI), `ai_tool_name`, `ai_tool_description`, `ai_tool_schema` (AI Schema), `use_in_mcp` (Available in MCP), `is_readonly` (Readonly Tool), and `code`. Checked on Odoo 20.1 (`saas~20.1` master, 2026-09-23).
3. **Schema storage.** `ai_tool_schema` is JSON text, and `enum` and `maxLength` survive a round trip.
4. **Empty schema.** Accepted: `list_helpdesk_teams` with `{"type": "object", "properties": {}, "required": []}` is listed and callable over MCP.
5. **How `UserError` surfaces over MCP.** As a tool error: `result.isError: true` with the message as the text content, never a JSON-RPC `error`. Odoo JSON-encodes the text, so it arrives with surrounding quotes (`"\"No helpdesk team matches 'Billing'.\""`). An unknown tool name is a tool error too.
6. **Server-side validation of `tools/call` arguments.** Odoo checks the schema before the code runs for types (`The type of the parameter 'priority' is incorrect`), required properties, `enum` (`Wrong value super-urgent, should be in: …`), and unknown properties (`Missing definition for assignee`). It does **not** enforce `maxLength`: a 500-character subject reached the code, which truncated it to 200. `arguments` sent as a JSON string instead of an object is not caught cleanly and leaks a Python error (`'str' object has no attribute 'update'`). All rejections are tool errors.
7. **Private team.** *Not verified*: the runs used an administrator, who sees every team.
8. **External API.** JSON-2 (`/json/2/<model>/<method>`) is available on Odoo 20.1.
9. **`ticket_ref`.** Present on `helpdesk.ticket` (`#00035`).
10. **Probe invocation.** `python3 mcp_probe.py` from the repository root, as in the README and skill (the file is also executable).
11. **Unknown customer email.** The ticket is created with `partner_email`, but Helpdesk then creates a contact with that email and an empty name. The code's "no contact" intent does not hold.
12. **OAuth.** `mcp_probe.py login` works unchanged: discovery from the 401, dynamic client registration, and PKCE. MCP is at `/mcp`, and the authorization server is `/oauth/mcp`, advertising scope `mcp`.
