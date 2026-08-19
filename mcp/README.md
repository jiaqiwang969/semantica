# Semantica MCP compatibility entry

`python -m mcp` is the repository compatibility command for Semantica's MCP
server. It delegates every request to the canonical implementation in
`semantica.mcp_server`; it does not maintain a second tool or resource registry.

For installed use, prefer:

```bash
python -m semantica.mcp_server
```

The compatibility command is protocol-equivalent:

```bash
python -m mcp
```

Both commands use newline-delimited JSON-RPC 2.0 over stdio and expose the same
server version, tool schemas, handlers, resource definitions, package manifest
allowlist, and structured errors.

## Built-in semantic packages

The canonical MCP registry includes these package operations:

- `list_chapter_packages`
- `get_chapter_package`
- `verify_book_sources`
- `run_chapter_package`
- `verify_chapter_package`

Discovery covers the 29 chapter packages from the two books plus the fixed
`semantica.chapter_packages.vol2.normative` domain package.

`verify_book_sources` accepts an explicit ontology-engineering checkout root
and hash-checks its authoritative chapter and TeX sources; it is read-only and
returns a blocked DTO on drift.

Package manifests are available through:

- `semantica://packages/registry`
- `semantica://packages/manifest/{allowlisted-package-id}`

Manifest resource input is resolved only against built-in package IDs. It is
never interpreted as a filesystem path.

## Client configuration

```json
{
  "mcpServers": {
    "semantica": {
      "command": "python",
      "args": ["-m", "semantica.mcp_server"]
    }
  }
}
```

Use `tools/list` and `resources/list` for the authoritative live inventory;
hard-coded inventories in this compatibility directory are intentionally not
maintained.
