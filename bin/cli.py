#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


DEFAULT_MODULES_URL = "http://127.0.0.1:6666"
DEFAULT_DESCRIBE_TYPES_URL = (
    "https://raw.githubusercontent.com/MISP/MISP/refs/heads/2.5/describeTypes.json"
)
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/misp-modules-cli/config.json")


def fetch_json(url: str, timeout: int = 20) -> Any:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def fetch_modules(base_url: str, timeout: int = 20) -> List[Dict[str, Any]]:
    data = fetch_json(f"{base_url.rstrip('/')}/modules", timeout=timeout)
    if not isinstance(data, list):
        raise RuntimeError("Unexpected /modules response: expected a JSON list")
    return data


def fetch_describe_types(describe_types_url: str, timeout: int = 20) -> Dict[str, Any]:
    data = fetch_json(describe_types_url, timeout=timeout)
    if not isinstance(data, dict) or "result" not in data:
        raise RuntimeError("Unexpected describeTypes.json format")
    return data["result"]


def get_valid_types(describe_types: Dict[str, Any]) -> set[str]:
    types = describe_types.get("types", [])
    return set(types) if isinstance(types, list) else set()


def get_expansion_modules(modules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [m for m in modules if m.get("type") == "expansion"]


def get_supported_input_types(modules: List[Dict[str, Any]]) -> set[str]:
    supported = set()
    for module in get_expansion_modules(modules):
        mispattributes = module.get("mispattributes", {})
        inputs = mispattributes.get("input", [])
        if isinstance(inputs, list):
            supported.update(t for t in inputs if isinstance(t, str))
    return supported


def get_type_to_modules_map(modules: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    mapping: Dict[str, List[str]] = {}
    for module in get_expansion_modules(modules):
        name = module.get("name", "<unknown>")
        mispattributes = module.get("mispattributes", {})
        inputs = mispattributes.get("input", [])
        if not isinstance(inputs, list):
            continue
        for attr_type in inputs:
            if not isinstance(attr_type, str):
                continue
            mapping.setdefault(attr_type, []).append(name)

    for attr_type in mapping:
        mapping[attr_type] = sorted(set(mapping[attr_type]))
    return mapping


def find_modules_for_type(modules: List[Dict[str, Any]], attr_type: str) -> List[Dict[str, Any]]:
    matches = []
    for module in get_expansion_modules(modules):
        mispattributes = module.get("mispattributes", {})
        inputs = mispattributes.get("input", [])
        if isinstance(inputs, list) and attr_type in inputs:
            matches.append(module)
    return matches


def is_ipv4(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv4Address)
    except ValueError:
        return False


def is_ipv6(value: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(value), ipaddress.IPv6Address)
    except ValueError:
        return False


def looks_like_domain(value: str) -> bool:
    if len(value) > 253 or " " in value or "/" in value or "@" in value:
        return False
    if value.endswith("."):
        value = value[:-1]
    labels = value.split(".")
    if len(labels) < 2:
        return False
    label_re = re.compile(r"^[A-Za-z0-9-]{1,63}$")
    return all(
        label_re.match(label) and not label.startswith("-") and not label.endswith("-")
        for label in labels
    )


def looks_like_hostname(value: str) -> bool:
    return looks_like_domain(value)


def looks_like_url(value: str) -> bool:
    try:
        p = urlparse(value)
        return p.scheme in {"http", "https", "ftp"} and bool(p.netloc)
    except Exception:
        return False


def looks_like_email(value: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value))


def looks_like_asn(value: str) -> bool:
    return bool(re.match(r"^(AS)?\d{1,10}$", value, re.IGNORECASE))


def looks_like_cve(value: str) -> bool:
    return bool(re.match(r"^CVE-\d{4}-\d{4,}$", value, re.IGNORECASE))


def looks_like_uuid(value: str) -> bool:
    return bool(re.match(
        r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$",
        value
    ))


def looks_like_md5(value: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F]{32}$", value))


def looks_like_sha1(value: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F]{40}$", value))


def looks_like_sha256(value: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F]{64}$", value))


def looks_like_sha512(value: str) -> bool:
    return bool(re.match(r"^[0-9a-fA-F]{128}$", value))


def looks_like_filename_hash(value: str) -> Tuple[bool, List[str]]:
    candidates = []
    if "|" not in value:
        return False, candidates
    left, right = value.split("|", 1)
    if not left:
        return False, candidates
    if looks_like_md5(right):
        candidates.append("filename|md5")
    if looks_like_sha1(right):
        candidates.append("filename|sha1")
    if looks_like_sha256(right):
        candidates.append("filename|sha256")
    return (len(candidates) > 0), candidates


def looks_like_domain_ip(value: str) -> bool:
    if "|" not in value:
        return False
    left, right = value.split("|", 1)
    return looks_like_domain(left) and (is_ipv4(right) or is_ipv6(right))


def guess_attribute_types(value: str, valid_types: set[str], supported_input_types: set[str]) -> List[Tuple[str, str]]:
    v = value.strip()
    guesses: List[Tuple[str, str, int]] = []

    def add(t: str, reason: str, score: int) -> None:
        if t in valid_types:
            guesses.append((t, reason, score))

    if v in valid_types:
        add(v, "value exactly matches a MISP attribute type", 100)

    if looks_like_cve(v):
        add("vulnerability", "matches CVE syntax", 95)

    if is_ipv4(v):
        add("ip-src", "matches IPv4 syntax", 90)
        add("ip-dst", "matches IPv4 syntax", 90)

    if is_ipv6(v):
        add("ip-src", "matches IPv6 syntax", 90)
        add("ip-dst", "matches IPv6 syntax", 90)

    if looks_like_url(v):
        add("url", "matches URL syntax", 95)
        add("link", "looks like a retrievable URL", 70)

    if looks_like_email(v):
        add("email", "matches email syntax", 95)
        add("email-src", "matches email syntax", 80)
        add("email-dst", "matches email syntax", 80)

    if looks_like_domain_ip(v):
        add("domain|ip", "matches domain|ip syntax", 95)

    ok_filename_hash, filename_hash_types = looks_like_filename_hash(v)
    if ok_filename_hash:
        for t in filename_hash_types:
            add(t, "matches filename|hash syntax", 95)

    if looks_like_md5(v):
        add("md5", "32 hex characters", 95)
    if looks_like_sha1(v):
        add("sha1", "40 hex characters", 95)
    if looks_like_sha256(v):
        add("sha256", "64 hex characters", 95)
    if looks_like_sha512(v):
        add("sha512", "128 hex characters", 95)

    if looks_like_uuid(v):
        add("uuid", "matches UUID syntax", 85)

    if looks_like_asn(v):
        add("AS", "matches ASN syntax", 90)

    if looks_like_domain(v):
        add("domain", "looks like a domain name", 85)
        add("hostname", "looks like a hostname", 80)

    if re.match(r"^[A-Fa-f0-9:]+$", v) and ":" in v:
        add("ip-src", "contains ':' and resembles IPv6", 50)
        add("ip-dst", "contains ':' and resembles IPv6", 50)

    best: Dict[str, Tuple[str, int]] = {}
    for t, reason, score in guesses:
        if t not in best or score > best[t][1]:
            best[t] = (reason, score)

    ranked = sorted(
        [(t, reason, score) for t, (reason, score) in best.items()],
        key=lambda x: (-x[2], x[0])
    )

    ranked.sort(key=lambda x: (x[0] not in supported_input_types, -x[2], x[0]))

    return [(t, reason) for t, reason, _score in ranked]


def build_payload(module_name: str, attr_type: str, value: str) -> Dict[str, Any]:
    return {
        "module": module_name,
        attr_type: value
    }


def query_module(
    base_url: str,
    module_name: str,
    attr_type: str,
    value: str,
    module_config: Optional[Dict[str, Any]] = None,
    timeout: int = 60
) -> Dict[str, Any]:
    payload = build_payload(module_name, attr_type, value)
    if module_config:
        payload.update(module_config)
    r = requests.post(
        f"{base_url.rstrip('/')}/query",
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )
    r.raise_for_status()
    return r.json()


def print_matches_for_type(attr_type: str, modules: List[Dict[str, Any]]) -> None:
    print(f"\n### Attribute type: {attr_type}")
    if not modules:
        print("No expansion modules support this type.")
        return
    print(f"Found {len(modules)} module(s):")
    for module in modules:
        name = module.get("name", "<unknown>")
        desc = module.get("meta", {}).get("description", "")
        print(f"  - {name}: {desc}")


def list_supported_types(modules: List[Dict[str, Any]], valid_types: set[str], verbose: bool = False) -> None:
    mapping = get_type_to_modules_map(modules)

    if not mapping:
        print("No supported input attribute types found in installed expansion modules.")
        return

    print("Supported input attribute types from installed expansion modules:\n")
    for attr_type in sorted(mapping):
        marker = "valid" if attr_type in valid_types else "unknown"
        print(f"- {attr_type} [{marker}] ({len(mapping[attr_type])} module(s))")
        if verbose:
            for module_name in mapping[attr_type]:
                print(f"    - {module_name}")


def get_module_config_keys(module: Dict[str, Any]) -> List[str]:
    moduleconfig = module.get("meta").get("config")
    print(moduleconfig)
    if isinstance(moduleconfig, list):
        return [k for k in moduleconfig if isinstance(k, str)]
    if isinstance(moduleconfig, dict):
        return [k for k in moduleconfig.keys() if isinstance(k, str)]
    return []


def load_config(config_path: str) -> Dict[str, Any]:
    if not os.path.exists(config_path):
        return {"modules": {}}

    with open(config_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise RuntimeError(f"Invalid config format in {config_path}: expected JSON object")
    modules_cfg = data.get("modules", {})
    if not isinstance(modules_cfg, dict):
        raise RuntimeError(f"Invalid config format in {config_path}: 'modules' must be an object")
    return data


def save_config(config_path: str, config: Dict[str, Any]) -> None:
    config_dir = os.path.dirname(config_path)
    if config_dir:
        os.makedirs(config_dir, exist_ok=True)
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, sort_keys=True)
        f.write("\n")


def parse_set_args(values: Optional[List[str]]) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for raw in values or []:
        if "=" not in raw:
            raise ValueError(f"Invalid --set value '{raw}'. Expected KEY=VALUE.")
        key, value = raw.split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"Invalid --set value '{raw}'. KEY must not be empty.")
        parsed[key] = value
    return parsed


def configure_module(
    modules: List[Dict[str, Any]],
    config_path: str,
    module_name: str,
    set_values: Dict[str, str]
) -> int:
    module = next((m for m in modules if m.get("name") == module_name), None)
    if module is None:
        print(f"[!] Module '{module_name}' was not found in introspection (/modules).", file=sys.stderr)
        return 1

    config_keys = get_module_config_keys(module)
    if not config_keys:
        print(f"Module '{module_name}' does not declare configurable settings via introspection.")
        return 0

    updates: Dict[str, str] = {}
    for key in config_keys:
        if key in set_values:
            updates[key] = set_values[key]
            continue
        current = "<unset>"
        try:
            cfg = load_config(config_path)
            module_cfg = cfg.get("modules", {}).get(module_name, {})
            if isinstance(module_cfg, dict) and key in module_cfg:
                current = "<configured>"
        except Exception:
            pass
        prompt = f"Set value for '{key}' (leave blank to keep {current}): "
        value = input(prompt).strip()
        if value:
            updates[key] = value

    config = load_config(config_path)
    modules_cfg = config.setdefault("modules", {})
    if not isinstance(modules_cfg, dict):
        raise RuntimeError(f"Invalid config format in {config_path}: 'modules' must be an object")
    module_cfg = modules_cfg.setdefault(module_name, {})
    if not isinstance(module_cfg, dict):
        module_cfg = {}
        modules_cfg[module_name] = module_cfg

    module_cfg.update(updates)
    save_config(config_path, config)

    print(f"Saved configuration for module '{module_name}' to {config_path}.")
    print("Configured keys:")
    for key in sorted(module_cfg.keys()):
        print(f"  - {key}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Query misp-modules expansion modules using either an explicit MISP type or a guessed type from free text."
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_MODULES_URL,
        help=f"Base URL of the misp-modules service (default: {DEFAULT_MODULES_URL})",
    )
    parser.add_argument(
        "--describe-types-url",
        default=DEFAULT_DESCRIBE_TYPES_URL,
        help="URL to MISP describeTypes.json",
    )
    parser.add_argument(
        "--type",
        dest="attr_type",
        help="Explicit MISP attribute type, e.g. ip-src, domain, vulnerability",
    )
    parser.add_argument(
        "--value",
        help="Free text or attribute value to query",
    )
    parser.add_argument(
        "--all-guesses",
        action="store_true",
        help="Query all guessed matching types instead of only the best one",
    )
    parser.add_argument(
        "--show-guesses",
        action="store_true",
        help="Show guessed attribute types before querying",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Print raw JSON responses",
    )
    parser.add_argument(
        "--list-supported-types",
        action="store_true",
        help="List input attribute types supported by installed expansion modules and exit",
    )
    parser.add_argument(
        "--verbose-types",
        action="store_true",
        help="With --list-supported-types, also list the modules supporting each type",
    )
    parser.add_argument(
        "--config-file",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to CLI configuration file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--configure-module",
        help="Configure a module's settings discovered via introspection and save them to --config-file",
    )
    parser.add_argument(
        "--set",
        action="append",
        help="With --configure-module, provide KEY=VALUE (can be repeated) to avoid prompts",
    )

    args = parser.parse_args()

    try:
        modules = fetch_modules(args.url)
    except Exception as e:
        print(f"[!] Unable to fetch module introspection from {args.url}/modules: {e}", file=sys.stderr)
        return 1

    try:
        describe_types = fetch_describe_types(args.describe_types_url)
        valid_types = get_valid_types(describe_types)
    except Exception as e:
        print(f"[!] Unable to fetch describeTypes.json: {e}", file=sys.stderr)
        return 1

    if args.list_supported_types:
        list_supported_types(modules, valid_types, verbose=args.verbose_types)
        return 0

    if args.configure_module:
        try:
            set_values = parse_set_args(args.set)
            return configure_module(modules, args.config_file, args.configure_module, set_values)
        except Exception as e:
            print(f"[!] Unable to configure module: {e}", file=sys.stderr)
            return 1

    if not args.value:
        print("[!] --value is required unless --list-supported-types is used", file=sys.stderr)
        return 1

    try:
        config = load_config(args.config_file)
        module_configs = config.get("modules", {}) if isinstance(config, dict) else {}
    except Exception as e:
        print(f"[!] Unable to load config file {args.config_file}: {e}", file=sys.stderr)
        return 1

    supported_input_types = get_supported_input_types(modules)

    if args.attr_type:
        candidate_types = [(args.attr_type, "explicitly provided by user")]
    else:
        candidate_types = guess_attribute_types(args.value, valid_types, supported_input_types)

        if args.show_guesses:
            if candidate_types:
                print("Guessed attribute types:")
                for t, reason in candidate_types:
                    supported = "yes" if t in supported_input_types else "no"
                    print(f"  - {t} (reason: {reason}, supported by installed module: {supported})")
            else:
                print("No likely attribute type could be guessed.")
                return 1

        if not candidate_types:
            print("No likely MISP attribute type could be guessed from the input.")
            return 1

    candidate_types = [(t, r) for t, r in candidate_types if t in valid_types]
    if not candidate_types:
        print("No valid MISP attribute type found.")
        return 1

    if not args.attr_type and not args.all_guesses:
        candidate_types = candidate_types[:1]

    any_queried = False

    for attr_type, reason in candidate_types:
        matching_modules = find_modules_for_type(modules, attr_type)
        print_matches_for_type(attr_type, matching_modules)

        if not matching_modules:
            continue

        if not args.attr_type:
            print(f"Reason: {reason}")

        for module in matching_modules:
            name = module.get("name", "<unknown>")
            print(f"\n=== {name} / {attr_type} ===")
            module_config: Dict[str, Any] = {}
            if isinstance(module_configs, dict):
                loaded_module_config = module_configs.get(name, {})
                if isinstance(loaded_module_config, dict):
                    module_config = loaded_module_config
            expected_keys = get_module_config_keys(module)
            missing_keys = [k for k in expected_keys if k not in module_config]
            if missing_keys:
                print(
                    f"note: missing config keys for module '{name}': {', '.join(sorted(missing_keys))}. "
                    f"Run with --configure-module {name} to save them in {args.config_file}."
                )
            try:
                response = query_module(args.url, name, attr_type, args.value, module_config=module_config)
                any_queried = True
                if args.raw:
                    print(json.dumps(response, indent=2, sort_keys=True))
                else:
                    if isinstance(response, dict) and "error" in response:
                        print(f"error: {response['error']}")
                    else:
                        print(json.dumps(response, indent=2, sort_keys=True))
            except requests.HTTPError as e:
                print(f"HTTP error: {e}")
            except Exception as e:
                print(f"query failed: {e}")

    if not any_queried:
        print("\nNo module query was executed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
