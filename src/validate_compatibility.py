#!/usr/bin/env python3
"""Fail the build when ELF dependencies do not resolve to the intended stack."""

import os
import pathlib
import re
import subprocess


ROOT = pathlib.Path("/usr/src/app/runtime/openssl")
DEPENDENCY = re.compile(r"^\s*(\S+) => (\S+) \(", re.MULTILINE)


def validate_dependencies(output: str, expected: dict[str, pathlib.Path]) -> None:
    if "undefined symbol:" in output or "not found" in output:
        raise ValueError(f"Unresolved ELF dependencies:\n{output}")
    resolved = dict(DEPENDENCY.findall(output))
    for name, path in expected.items():
        actual = resolved.get(name)
        if actual is None or pathlib.Path(actual).resolve() != path.resolve():
            raise ValueError(f"{name}: expected {path}, got {actual}")


def main() -> None:
    environment = dict(os.environ, LD_BIND_NOW="1")
    targets = {
        ROOT / "bin/openssl": {
            "libcrypto.so.3": ROOT / "lib/libcrypto.so.3",
            "libssl.so.3": ROOT / "lib/libssl.so.3",
        },
        ROOT / "lib/ossl-modules/symcryptprovider.so": {
            "libcrypto.so.3": ROOT / "lib/libcrypto.so.3",
            "libsymcrypt.so.103": pathlib.Path("/usr/lib/libsymcrypt.so.103.8.0"),
        },
        pathlib.Path("/usr/src/app/provider-probe"): {
            "libcrypto.so.3": ROOT / "lib/libcrypto.so.3",
        },
        pathlib.Path("/build/config-check"): {
            "libcrypto.so.3": ROOT / "lib/libcrypto.so.3",
            "libsymcrypt.so.103": pathlib.Path("/usr/lib/libsymcrypt.so.103.8.0"),
        },
    }
    print(pathlib.Path("/build/base-crypto-packages.txt").read_text(), end="")
    for target, expected in targets.items():
        result = subprocess.run(
            ["ldd", "-r", str(target)], env=environment,
            capture_output=True, text=True, check=True,
        )
        validate_dependencies(result.stdout + result.stderr, expected)
        print(f"Resolved all ELF relocations: {target}")
        for name, path in expected.items():
            print(f"  {name} => {path.resolve()}")


if __name__ == "__main__":
    main()
