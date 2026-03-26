# misp-modules-cli

`misp-modules-cli` is a lightweight command-line client for querying [MISP expansion modules](https://github.com/MISP/misp-modules) from a local or remote `misp-modules` service.

It can:

- Auto-detect likely MISP attribute types from a raw value.
- Query matching expansion modules.
- Restrict queries to one or more specific modules.
- List supported input types from live module introspection.
- Store per-module configuration (API keys, usernames, etc.) in a local config file.

## Requirements

- Python 3.10+ (recommended)
- `misp-modules` running and reachable (default: `http://127.0.0.1:6666`)
- Python dependency:
  - `requests`

Install dependency:

```bash
python3 -m pip install requests
```

## Quick start

### 1) List supported input types

```bash
python3 bin/cli.py --list-supported-types
python3 bin/cli.py --list-supported-types --verbose-types
```

### 2) Query with automatic type guessing

```bash
python3 bin/cli.py --value 8.8.8.8 --show-guesses
python3 bin/cli.py --value CVE-2024-3094 --show-guesses
```

### 3) Query with an explicit MISP type

```bash
python3 bin/cli.py --type domain --value circl.lu
```

### 4) Restrict to selected modules

```bash
python3 bin/cli.py --type domain --value circl.lu --module circl_passivedns
python3 bin/cli.py --type domain --value circl.lu --module circl_passivedns,dns
python3 bin/cli.py --type domain --value circl.lu --module circl_passivedns --module dns
```

### 5) Emit unified JSON output from all queried modules

```bash
python3 bin/cli.py --value 8.8.8.8 --unified-output
python3 bin/cli.py --type domain --value circl.lu --module circl_passivedns,dns --unified-output
```

### 6) Emit markdown report output with summary + full query details

```bash
# Print markdown report to stdout
python3 bin/cli.py --value 8.8.8.8 --markdown-output

# Write markdown report to a file
python3 bin/cli.py --type domain --value circl.lu --markdown-output report.md
```

## Module configuration

Some modules require settings (for example credentials or API keys). You can store these once in a local config file.

### Interactive configuration

```bash
python3 bin/cli.py --configure-module circl_passivedns
```

### Non-interactive configuration

```bash
python3 bin/cli.py --configure-module circl_passivedns \
  --set username=my-user \
  --set password=my-pass
```

### Config file location

Default path:

```text
~/.config/misp-modules-cli/config.json
```

Override it per run:

```bash
python3 bin/cli.py --config-file /path/to/config.json ...
```

## Useful options

- `--url` – base URL of `misp-modules` service.
- `--describe-types-url` – URL to MISP `describeTypes.json`.
- `--show-guesses` – show guessed attribute types.
- `--all-guesses` – query all guessed types (instead of only the best match).
- `--raw` – print raw JSON responses.
- `--show-empty-results` – include empty module responses in output (hidden by default).
- `--unified-output` – print one merged JSON object containing all module query results.
- `--markdown-output [PATH]` – print a markdown report (or write it to `PATH`) with summary, query timestamps, query parameters, and responses.
- `--module` – limit queries to specific module name(s).
- `--cache-file` – cache file path for module responses.
- `--cache-ttl-seconds` – cache TTL in seconds (default: `43200`, i.e. 12 hours).
- `--purge-cache` – delete the local cache file and exit.

## Response cache

To reduce API calls and improve response times, module query responses are cached locally by default.

- Default cache file:

```text
~/.cache/misp-modules-cli/cache.json
```

- Default TTL: 12 hours (`43200` seconds)

You can override the cache TTL per run:

```bash
python3 bin/cli.py --value 8.8.8.8 --cache-ttl-seconds 3600
```

Purge the local cache:

```bash
python3 bin/cli.py --purge-cache
```

See all CLI options:

```bash
python3 bin/cli.py --help
```

## Exit behavior

- Returns non-zero when required input is missing or API/introspection cannot be fetched.
- Prints errors and diagnostic information to stderr.

## License

This project is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](./LICENSE).
