#!/usr/bin/env python3
import hashlib
import json
import pathlib
import sys


def main() -> None:
    lock_path = pathlib.Path(sys.argv[1])
    downloads = pathlib.Path(sys.argv[2])
    with lock_path.open(encoding="utf-8") as lock_file:
        lock = json.load(lock_file)

    expected = sys.argv[3:]
    archives = [source["archive"] for source in lock["sources"]]
    if not expected or len(set(expected)) != len(expected) or sorted(archives) != sorted(expected):
        raise ValueError("The lock file must list exactly the archives used by the build")

    for source in lock["sources"]:
        if "/" in source["archive"] or "\\" in source["archive"]:
            raise ValueError(f"Invalid archive filename: {source['archive']}")
        archive = downloads / source["archive"]
        digest = hashlib.sha512()
        with archive.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        if digest.hexdigest() != source["sha512"]:
            raise ValueError(f"SHA-512 mismatch: {archive}")
        print(f"Verified {source['name']} {source['version']}", flush=True)


if __name__ == "__main__":
    main()
