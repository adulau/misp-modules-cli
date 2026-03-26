#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import re
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests


DEFAULT_MODULES_URL = "http://127.0.0.1:6666"
DEFAULT_DESCRIBE_TYPES_URL = (
    "https://raw.githubusercontent.com/MISP/MISP/refs/heads/2.5/describeTypes.json"
)
DEFAULT_CONFIG_PATH = os.path.expanduser("~/.config/misp-modules-cli/config.json")
DEFAULT_CACHE_PATH = os.path.expanduser("~/.cache/misp-modules-cli/cache.json")
DEFAULT_CACHE_TTL_SECONDS = 12 * 60 * 60


def log(message: str = "") -> None:
    print(message, file=sys.stderr)


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


def uses_misp_standard_format(module: Dict[str, Any]) -> bool:
    mispattributes = module.get("mispattributes", {})
    module_format = mispattributes.get("format")
    return isinstance(module_format, str) and module_format.lower() == "misp_standard"


def build_payload(
    module: Dict[str, Any],
    module_name: str,
    attr_type: str,
    value: str
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"module": module_name}
    if uses_misp_standard_format(module):
        payload["attribute"] = {
            "type": attr_type,
            "value": value,
            "uuid": str(uuid.uuid4()),
        }
    else:
        payload[attr_type] = value
    return payload


def query_module(
    base_url: str,
    module: Dict[str, Any],
    module_name: str,
    attr_type: str,
    value: str,
    module_config: Optional[Dict[str, Any]] = None,
    timeout: int = 60
) -> Dict[str, Any]:
    payload = build_payload(module, module_name, attr_type, value)
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
    log(f"\n### Attribute type: {attr_type}")
    if not modules:
        log("No expansion modules support this type.")
        return
    log(f"Found {len(modules)} module(s):")
    for module in modules:
        name = module.get("name", "<unknown>")
        desc = module.get("meta", {}).get("description", "")
        log(f"  - {name}: {desc}")


def list_supported_types(modules: List[Dict[str, Any]], valid_types: set[str], verbose: bool = False) -> None:
    mapping = get_type_to_modules_map(modules)

    if not mapping:
        log("No supported input attribute types found in installed expansion modules.")
        return

    log("Supported input attribute types from installed expansion modules:\n")
    for attr_type in sorted(mapping):
        marker = "valid" if attr_type in valid_types else "unknown"
        log(f"- {attr_type} [{marker}] ({len(mapping[attr_type])} module(s))")
        if verbose:
            for module_name in mapping[attr_type]:
                log(f"    - {module_name}")


def get_module_config_keys(module: Dict[str, Any]) -> List[str]:
    moduleconfig = module.get("meta").get("config")
    if isinstance(moduleconfig, list):
        return [k for k in moduleconfig if isinstance(k, str)]
    if isinstance(moduleconfig, dict):
        return [k for k in moduleconfig.keys() if isinstance(k, str)]
    return []


def parse_modules_args(values: Optional[List[str]]) -> List[str]:
    modules: List[str] = []
    for raw in values or []:
        for candidate in raw.split(","):
            name = candidate.strip()
            if not name:
                continue
            modules.append(name)
    deduped: List[str] = []
    seen = set()
    for name in modules:
        if name in seen:
            continue
        seen.add(name)
        deduped.append(name)
    return deduped


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


def load_cache(cache_path: str) -> Dict[str, Any]:
    if not os.path.exists(cache_path):
        return {"entries": {}}
    with open(cache_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise RuntimeError(f"Invalid cache format in {cache_path}: expected JSON object")
    entries = data.get("entries", {})
    if not isinstance(entries, dict):
        raise RuntimeError(f"Invalid cache format in {cache_path}: 'entries' must be an object")
    return data


def save_cache(cache_path: str, cache: Dict[str, Any]) -> None:
    cache_dir = os.path.dirname(cache_path)
    if cache_dir:
        os.makedirs(cache_dir, exist_ok=True)
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, sort_keys=True)
        f.write("\n")


def purge_cache(cache_path: str) -> int:
    if os.path.exists(cache_path):
        os.remove(cache_path)
        log(f"Purged cache file: {cache_path}")
    else:
        log(f"No cache file found at {cache_path}. Nothing to purge.")
    return 0


def make_cache_key(base_url: str, module_name: str, attr_type: str, value: str, module_config: Dict[str, Any]) -> str:
    key_payload = {
        "base_url": base_url.rstrip("/"),
        "module": module_name,
        "type": attr_type,
        "value": value,
        "module_config": module_config,
    }
    return json.dumps(key_payload, sort_keys=True, separators=(",", ":"))


def get_cached_response(
    cache: Dict[str, Any],
    key: str,
    now: int,
    ttl_seconds: int
) -> Optional[Dict[str, Any]]:
    entries = cache.get("entries", {})
    if not isinstance(entries, dict):
        return None
    entry = entries.get(key)
    if not isinstance(entry, dict):
        return None
    cached_at = entry.get("cached_at")
    response = entry.get("response")
    if not isinstance(cached_at, int) or response is None:
        return None
    if now - cached_at > ttl_seconds:
        return None
    return {"cached_at": cached_at, "response": response}


def set_cached_response(cache: Dict[str, Any], key: str, response: Dict[str, Any], now: int) -> None:
    entries = cache.setdefault("entries", {})
    if not isinstance(entries, dict):
        cache["entries"] = {}
        entries = cache["entries"]
    entries[key] = {
        "cached_at": now,
        "response": response,
    }


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
        log(f"Module '{module_name}' does not declare configurable settings via introspection.")
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

    log(f"Saved configuration for module '{module_name}' to {config_path}.")
    log("Configured keys:")
    for key in sorted(module_cfg.keys()):
        log(f"  - {key}")
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
    parser.add_argument(
        "--module",
        action="append",
        dest="modules",
        help="Only query specific module(s); can be repeated or passed as comma-separated names",
    )
    parser.add_argument(
        "--cache-file",
        default=DEFAULT_CACHE_PATH,
        help=f"Path to local response cache file (default: {DEFAULT_CACHE_PATH})",
    )
    parser.add_argument(
        "--cache-ttl-seconds",
        type=int,
        default=DEFAULT_CACHE_TTL_SECONDS,
        help=f"Cache TTL in seconds (default: {DEFAULT_CACHE_TTL_SECONDS}, i.e., 12 hours)",
    )
    parser.add_argument(
        "--purge-cache",
        action="store_true",
        help="Delete the local cache file and exit",
    )

    args = parser.parse_args()

    if args.cache_ttl_seconds < 0:
        print("[!] --cache-ttl-seconds must be >= 0", file=sys.stderr)
        return 1

    if args.purge_cache:
        return purge_cache(args.cache_file)

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
    selected_modules = parse_modules_args(args.modules)

    if selected_modules:
        available_modules = {
            m.get("name")
            for m in modules
            if isinstance(m.get("name"), str)
        }
        missing_modules = [m for m in selected_modules if m not in available_modules]
        if missing_modules:
            print(
                "[!] Unknown module name(s): "
                + ", ".join(sorted(missing_modules))
                + ". Use /modules introspection to list available names.",
                file=sys.stderr,
            )
            return 1

    if args.attr_type:
        candidate_types = [(args.attr_type, "explicitly provided by user")]
    else:
        candidate_types = guess_attribute_types(args.value, valid_types, supported_input_types)

        if args.show_guesses:
            if candidate_types:
                log("Guessed attribute types:")
                for t, reason in candidate_types:
                    supported = "yes" if t in supported_input_types else "no"
                    log(f"  - {t} (reason: {reason}, supported by installed module: {supported})")
            else:
                log("No likely attribute type could be guessed.")
                return 1

        if not candidate_types:
            log("No likely MISP attribute type could be guessed from the input.")
            return 1

    candidate_types = [(t, r) for t, r in candidate_types if t in valid_types]
    if not candidate_types:
        log("No valid MISP attribute type found.")
        return 1

    if not args.attr_type and not args.all_guesses:
        candidate_types = candidate_types[:1]

    any_queried = False
    cache_dirty = False
    try:
        cache = load_cache(args.cache_file)
    except Exception as e:
        print(f"[!] Unable to load cache file {args.cache_file}: {e}", file=sys.stderr)
        return 1

    for attr_type, reason in candidate_types:
        matching_modules = find_modules_for_type(modules, attr_type)
        if selected_modules:
            matching_modules = [
                m for m in matching_modules
                if m.get("name") in selected_modules
            ]
        print_matches_for_type(attr_type, matching_modules)

        if not matching_modules:
            continue

        if not args.attr_type:
            log(f"Reason: {reason}")

        for module in matching_modules:
            name = module.get("name", "<unknown>")
            log(f"\n=== {name} / {attr_type} ===")
            module_config: Dict[str, Any] = {}
            config: Dict[str, Any] = {}
            if isinstance(module_configs, dict):
                loaded_module_config = module_configs.get(name, {})
                if isinstance(loaded_module_config, dict):
                    config = loaded_module_config
                    module_config["config"] = config
            expected_keys = get_module_config_keys(module)
            missing_keys = [k for k in expected_keys if k not in config]
            if missing_keys:
                log(
                    f"note: missing config keys for module '{name}': {', '.join(sorted(missing_keys))}. "
                    f"Run with --configure-module {name} to save them in {args.config_file}."
                )
            try:
                cache_key = make_cache_key(args.url, name, attr_type, args.value, module_config)
                cached = get_cached_response(
                    cache,
                    cache_key,
                    now=int(time.time()),
                    ttl_seconds=args.cache_ttl_seconds,
                )
                if cached is not None:
                    response = cached["response"]
                    log("cache: hit")
                else:
                    response = query_module(
                        args.url,
                        module,
                        name,
                        attr_type,
                        args.value,
                        module_config=module_config
                    )
                    set_cached_response(cache, cache_key, response, now=int(time.time()))
                    cache_dirty = True
                    log("cache: miss")
                any_queried = True
                if args.raw:
                    print(json.dumps(response, indent=2, sort_keys=True))
                else:
                    if isinstance(response, dict) and "error" in response:
                        log(f"error: {response['error']}")
                    else:
                        print(json.dumps(response, indent=2, sort_keys=True))
            except requests.HTTPError as e:
                log(f"HTTP error: {e}")
            except Exception as e:
                log(f"query failed: {e}")

    if cache_dirty:
        try:
            save_cache(args.cache_file, cache)
        except Exception as e:
            print(f"[!] Unable to save cache file {args.cache_file}: {e}", file=sys.stderr)
            return 1

    if not any_queried:
        log("\nNo module query was executed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
