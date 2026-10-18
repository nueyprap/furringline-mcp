# AGENTS.md — furringline-mcp

How an agent builds, tests and ships this repo alone. Keep every command exact and copy-pasteable.
The `agents-md` check fails when a `##` heading below is missing, so keep all twelve, even when the
answer is "None". Where a fact is truly unknown, write what exists and add a line that starts with
`Needs Narathip:` and asks one clear question.

This repository is **public**. Write nothing private here: no internal paths, no secret values or
vault item names, no names of private repositories.

Last updated: 2026-10-18 by claude-code.

## What this repo is

The public install files that let AI tools connect to the FURRINGLINE MCP server
`https://mcp.furringline.com` (read-only product search, prices before VAT, stock and material
calculators; no sign-in). It holds no server code. Outside users install from it, so a bad manifest
breaks their install.

| File | Used by |
|---|---|
| `.claude-plugin/plugin.json`, `.mcp.json` | Claude Code plugin |
| `.cursor-plugin/plugin.json`, `mcp.json` | Cursor plugin (Cursor Marketplace) |
| `gemini-extension.json`, `GEMINI.md` | Gemini CLI extension (`gemini extensions install https://github.com/nueyprap/furringline-mcp`) |
| `server.json` | Official MCP Registry entry `com.furringline.mcp/furringline` |
| `README.md` | Install guide for every tool |
| `assets/logo.png`, `LICENSE` (MIT) | Logo and license |

## Build

None. There is nothing to build or install.

## Test

No tests. The check is that every tracked JSON file parses (the same check Night Shift runs):

```bash
for f in $(git ls-files '*.json'); do python3 -m json.tool "$f" >/dev/null || { echo "bad JSON: $f"; exit 1; }; done
```

Also make sure the server URL is the same in every manifest:

```bash
grep -n 'mcp.furringline.com' .mcp.json mcp.json gemini-extension.json server.json
```

## Typecheck and lint

None beyond the JSON check above.

## Run locally

Nothing runs here. To try the server, use an install command from `README.md`, for example:

```bash
claude mcp add --transport http furringline https://mcp.furringline.com
```

## Deploy

- There is no deploy. A merge to `main` changes what tools see when they install straight from this
  GitHub repo (Gemini CLI, plugin installs from the repo).
- The server itself (`https://mcp.furringline.com`) is built and deployed elsewhere; nothing in this
  repo changes it.
- Version fields: `version` is `1.0.0` in `server.json`, `gemini-extension.json`,
  `.claude-plugin/plugin.json` and `.cursor-plugin/plugin.json`. Git tag: `v1.0.0`.
- Listings that copied these files at submission time: MCP Registry (`server.json`, version 1.0.0,
  published), Claude Connectors Directory, Claude plugin directory, Cursor Marketplace. A change here
  does not reach those listings until it is published to them again.

Needs Narathip: how should this be released? Options I see: (1) on every manifest change, bump the
version in all four manifests together, merge, tag `vX.Y.Z` with a GitHub release, then publish
`server.json` again to the MCP Registry with its `mcp-publisher` tool; (2) treat `main` as the
release and bump versions and the registry only when the server address, tools or listing text
change; (3) freeze this repo and change it only with a directory resubmission.

## Smoke test after deploy

After a merge, check that the server the manifests point to answers, and that the registry entry is
still there:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://mcp.furringline.com/docs
# expect 200
curl -s -X POST https://mcp.furringline.com -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
# expect a JSON result listing search_products, get_product, list_categories, list_calculators, calculate_materials
curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=com.furringline.mcp/furringline'
# expect the entry with "version":"1.0.0" (or the version just published)
```

## Rollback

Revert the merge commit on `main` with a pull request (`git revert -m 1 <merge sha>`). If a broken
version was also published to the MCP Registry, publish the fixed `server.json` with a higher
version; registry versions cannot be overwritten.

## Secrets

This repo needs no secrets to work. The workflows use two GitHub Actions secrets, set by the owner:

| Name | Where it lives | Used for |
|---|---|---|
| `TYPESAFE_API_KEY` | GitHub Actions secret | `jev-gate` workflow |
| `NIGHT_SHIFT_ALERT_KEY` | GitHub Actions secret | Night Shift merge alerts |

Never put a key, token or private address in any file here. Everything in this repo is public.

## Monitoring and alerts

None in this repo. The server `https://mcp.furringline.com` is monitored outside this repo. Nothing
watches the directory listings.

## How changes merge

Branch from `main` and open a pull request. When `main` has required status checks, set the pull
request to merge itself when they pass: `gh pr merge <n> --auto --merge`. Until then, wait for
`gh pr checks <n> --watch` to pass, then `gh pr merge <n> --merge`. Never force-push, never rebase a
shared branch; on a conflict, merge `main` into your branch. Night Shift (see
`.night-shift/README.md`) may also merge small `fix`, `docs` and `chore` changes; it may not touch
`LICENSE` or `assets/**`.

## Do not

- Never print, commit or log a secret.
- Do not add anything private: internal paths, vault item names, private repository names, staff
  emails other than `hello@furringline.com`.
- Do not change the server URL, the `name` fields or `com.furringline.mcp/furringline` without
  Narathip's yes; installs and directory listings depend on them.
- Do not change `LICENSE` or `assets/logo.png`.
- Do not edit `.night-shift/**`, `.jev/**` or the managed workflows here; they are installed from
  the shared tooling.
