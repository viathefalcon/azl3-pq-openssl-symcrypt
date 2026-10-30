#!/usr/bin/env python3
import collections
import pathlib
import re
import sys


MODES = ("default-only", "symcrypt-only", "symcrypt-preferred")
FIELDS = ("mode", "algorithm", "parameter", "operation", "status", "provider", "detail")
TABLE_HEADER = "| " + " | ".join(field.capitalize() for field in FIELDS) + " |"
TABLE_SEPARATOR = "| " + " | ".join("---" for _ in FIELDS) + " |"
ENTITY = re.compile(r"&(#\d+|amp|lt|gt);")
SUMMARY = re.compile(r"Summary: (\d+) ok, (\d+) unsupported, (\d+) not_run, (\d+) errors\.")
EXCHANGE = ("keygen", "peer_keygen", "derive", "peer_derive", "shared_secret_check")
SIGNATURE = ("keygen", "sign", "verify", "verify_invalid")
KEM = ("keygen", "encapsulate", "decapsulate", "shared_secret_check")

CASES = {
    **{("ECDH", group): EXCHANGE for group in ("P-256", "P-384", "P-521")},
    **{("ECDSA", group): SIGNATURE for group in ("P-256", "P-384", "P-521")},
    **{(name, ""): EXCHANGE for name in ("X25519", "X448")},
    **{(name, ""): SIGNATURE for name in ("Ed25519", "Ed448")},
    **{("ML-KEM", parameter): KEM for parameter in ("512", "768", "1024")},
    **{("ML-DSA", parameter): SIGNATURE for parameter in ("44", "65", "87")},
    **{
        ("SLH-DSA", f"{family}-{parameter}{variant}"): SIGNATURE
        for family in ("SHA2", "SHAKE")
        for parameter in ("128", "192", "256")
        for variant in ("s", "f")
    },
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def decode_cell(value: str) -> str:
    require("|" not in value and "\\" not in value, "invalid unescaped Markdown cell")
    decoded = []
    position = 0
    names = {"amp": "&", "lt": "<", "gt": ">"}
    while True:
        start = value.find("&", position)
        if start < 0:
            decoded.append(value[position:])
            return "".join(decoded)
        decoded.append(value[position:start])
        entity = ENTITY.match(value, start)
        if entity is None:
            raise ValueError("invalid Markdown entity")
        name = entity.group(1)
        if name.startswith("#"):
            codepoint = int(name[1:])
            require(codepoint <= 0x10FFFF, "invalid Markdown entity")
            decoded.append(chr(codepoint))
        else:
            decoded.append(names[name])
        position = entity.end()


def parse_report(text: str):
    lines = text.splitlines()
    require(len(lines) >= 6, "missing environment, table, or summary")
    require(lines[0].startswith("OpenSSL: "), "invalid environment record")
    version = decode_cell(lines[0][len("OpenSSL: "):])
    require(
        lines[1] == "" and lines[2] == TABLE_HEADER and lines[3] == TABLE_SEPARATOR,
        "invalid Markdown table header",
    )
    require(lines[-2] == "", "missing summary separator")
    match = SUMMARY.fullmatch(lines[-1])
    if match is None:
        raise ValueError("invalid summary record")
    summary = dict(zip(("ok", "unsupported", "not_run", "errors"), map(int, match.groups())))

    records = []
    for line in lines[4:-2]:
        require(line.startswith("| ") and line.endswith(" |"), "invalid result row")
        cells = line[2:-2].split(" | ")
        require(len(cells) == len(FIELDS), "invalid result shape")
        row = dict(zip(FIELDS, map(decode_cell, cells)))
        row["provider"] = row["provider"] or None
        row["detail"] = row["detail"] or None
        records.append(row)
    return version, records, summary


def validate(path: pathlib.Path) -> None:
    version, records, summary = parse_report(path.read_text(encoding="utf-8-sig"))
    require(
        version.startswith("OpenSSL 3.6.5 "),
        "unexpected OpenSSL version",
    )

    rows = {}
    counts = collections.Counter()
    for row in records:
        key = (row["mode"], row["algorithm"], row["parameter"], row["operation"])
        require(key not in rows, f"duplicate result: {key}")
        require(row["status"] in ("ok", "unsupported", "not_run", "error"), f"invalid status: {key}")
        require(row["detail"] is None or isinstance(row["detail"], str), f"invalid detail: {key}")
        rows[key] = row
        counts[row["status"]] += 1

    expected = {
        (mode, algorithm, parameter, operation)
        for mode in MODES
        for (algorithm, parameter), operations in CASES.items()
        for operation in operations
    }
    require(set(rows) == expected, f"result matrix differs: missing={expected - set(rows)}, extra={set(rows) - expected}")
    require(counts["error"] == 0, "one or more operations failed")
    require(
        all(summary.get(status) == counts[status] for status in ("ok", "unsupported", "not_run")),
        "summary counts do not match results",
    )
    require(summary.get("errors") == counts["error"], "error summary does not match results")

    symcrypt_pq = False
    for (mode, algorithm, parameter, operation), row in rows.items():
        status = row["status"]
        provider = row["provider"]
        if mode != "symcrypt-only":
            require(status == "ok", f"required operation did not succeed: {(mode, algorithm, parameter, operation)}")
        if status != "ok":
            require(mode == "symcrypt-only" and provider is None, "invalid unsupported/skipped result")
            require(row["detail"], "unsupported/skipped result lacks a reason")
            continue
        if operation == "shared_secret_check":
            require(provider is None, "local secret comparison was attributed to a provider")
            continue
        if mode == "default-only":
            require(provider == "default", "default-only operation used another provider")
        elif mode == "symcrypt-only":
            require(provider == "symcryptprovider", "strict SymCrypt operation used another provider")
            if algorithm in ("ML-KEM", "ML-DSA") and operation in ("encapsulate", "sign"):
                symcrypt_pq = True
        else:
            require(provider in ("default", "symcryptprovider"), "unexpected preferred-mode provider")
            strict = rows[("symcrypt-only", algorithm, parameter, operation)]
            if strict["status"] == "ok":
                require(provider == "symcryptprovider", "preferred mode failed to prefer a supported SymCrypt operation")

    for (algorithm, parameter), operations in CASES.items():
        strict_rows = [rows[("symcrypt-only", algorithm, parameter, operation)] for operation in operations]
        if algorithm in ("ECDH", "ECDSA", "X25519", "ML-KEM", "ML-DSA"):
            require(
                all(row["status"] == "ok" for row in strict_rows),
                f"required SymCrypt operation unavailable: {(algorithm, parameter)}",
            )
        if any(row["status"] == "not_run" for row in strict_rows):
            require(any(row["status"] == "unsupported" for row in strict_rows), "skipped operation lacks an unsupported prerequisite")
    require(symcrypt_pq, "no post-quantum operation was serviced by SymCrypt")
    print(f"Validated {len(rows)} results: {counts['ok']} ok, {counts['unsupported']} unsupported, {counts['not_run']} not run.")


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python tests/validate_results.py <results.md>", file=sys.stderr)
        return 2
    try:
        validate(pathlib.Path(sys.argv[1]))
    except (OSError, ValueError, TypeError, KeyError) as error:
        print(f"Result validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
