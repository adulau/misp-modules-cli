# misp-modules-cli

A convenient command line interface to [misp-modules](https://github.com/MISP/misp-modules).

# Requirements

- [misp-modules](https://github.com/MISP/misp-modules)

# Usage

## List supported MISP attribute types

- `python3 cli.py --list-supported-types`

## List supported MISP attribute types along with their respective MISP module

- `python3 cli.py --list-supported-types --verbose-types`

## Querying the misp-modules

~~~bash
python3 cli.py --value 8.8.8.8 --show-guesses
python3 cli.py --value CVE-2024-3094 --show-guesses
python3 cli.py --type domain --value circl.lu
python3 cli.py --type domain --value circl.lu --module circl_passivedns
python3 cli.py --type domain --value circl.lu --module circl_passivedns,dns
python3 cli.py --type domain --value circl.lu --module circl_passivedns --module dns
~~~

## Configuring module credentials/settings

Some modules require credentials (for example `circl_passivedns`). You can configure these settings once using module introspection and store them in a config file for future runs.

~~~bash
# interactive prompt for settings exposed by the module
python3 cli.py --configure-module circl_passivedns

# non-interactive configuration
python3 cli.py --configure-module circl_passivedns \
  --set username=my-user \
  --set password=my-pass
~~~

By default the CLI stores this in `~/.config/misp-modules-cli/config.json`.
You can use `--config-file /path/to/file.json` to override this location.
