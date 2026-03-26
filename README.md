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
~~~


