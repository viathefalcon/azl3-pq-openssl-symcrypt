import contextlib
import hashlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import validate_results


ROOT = pathlib.Path(__file__).resolve().parent.parent


def example_records():
    rows = []
    counts = {"ok": 0, "unsupported": 0, "not_run": 0, "error": 0}
    for mode in validate_results.MODES:
        for (algorithm, parameter), operations in validate_results.CASES.items():
            available_in_symcrypt = algorithm not in ("X448", "Ed25519", "Ed448", "SLH-DSA")
            for operation in operations:
                status = "ok"
                if mode == "symcrypt-only" and not available_in_symcrypt:
                    status = "unsupported" if operation == "keygen" else "not_run"
                if operation == "shared_secret_check" or status != "ok":
                    provider = None
                elif mode == "default-only" or (mode == "symcrypt-preferred" and not available_in_symcrypt):
                    provider = "default"
                else:
                    provider = "symcryptprovider"
                rows.append(
                    {
                        "type": "result",
                        "mode": mode,
                        "algorithm": algorithm,
                        "parameter": parameter,
                        "operation": operation,
                        "status": status,
                        "provider": provider,
                        "detail": None if status == "ok" else "not available",
                    }
                )
                counts[status] += 1
    return (
        [{"type": "environment", "openssl_version": "OpenSSL 3.6.5 test"}]
        + rows
        + [{"type": "summary", "ok": counts["ok"], "unsupported": counts["unsupported"],
            "not_run": counts["not_run"], "errors": counts["error"]}]
    )


def markdown_cell(value):
    if value is None:
        return ""
    replacements = {"&": "&amp;", "<": "&lt;", ">": "&gt;", "|": "&#124;", "\\": "&#92;"}
    return "".join(
        replacements.get(char, f"&#{ord(char)};" if ord(char) < 0x20 or ord(char) == 0x7f else char)
        for char in value
    )


def markdown_report(records):
    lines = [
        "OpenSSL: " + markdown_cell(records[0]["openssl_version"]),
        "",
        validate_results.TABLE_HEADER,
        validate_results.TABLE_SEPARATOR,
    ]
    for row in records[1:-1]:
        lines.append("| " + " | ".join(markdown_cell(row[field]) for field in validate_results.FIELDS) + " |")
    summary = records[-1]
    lines.extend(
        [
            "",
            f"Summary: {summary['ok']} ok, {summary['unsupported']} unsupported, "
            f"{summary['not_run']} not_run, {summary['errors']} errors.",
        ]
    )
    return "\n".join(lines) + "\n"


class ResultValidationTests(unittest.TestCase):
    def validate(self, records):
        self.validate_text(markdown_report(records))

    def validate_text(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "results.md"
            path.write_text(text, encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()):
                validate_results.validate(path)

    def test_complete_matrix_passes(self):
        self.validate(example_records())

    def test_escaped_cells_round_trip(self):
        records = example_records()
        detail = "pipe | slash \\ amp & angle <tag>\nsecond\tline\x01\x7f"
        records[1]["detail"] = detail
        report = markdown_report(records)
        self.assertIn("&#124;", report)
        self.assertIn("&#92;", report)
        self.assertIn("&amp;", report)
        _, rows, _ = validate_results.parse_report(report)
        self.assertEqual(rows[0]["detail"], detail)
        self.validate_text(report)

    def test_missing_operation_fails(self):
        records = example_records()
        del records[1]
        with self.assertRaisesRegex(ValueError, "result matrix differs"):
            self.validate(records)

    def test_invalid_environment_record_fails(self):
        report = markdown_report(example_records()).replace("OpenSSL: ", "Version: ", 1)
        with self.assertRaisesRegex(ValueError, "invalid environment record"):
            self.validate_text(report)

    def test_invalid_table_header_fails(self):
        report = markdown_report(example_records()).replace("| Mode |", "| Scenario |", 1)
        with self.assertRaisesRegex(ValueError, "invalid Markdown table header"):
            self.validate_text(report)

    def test_invalid_result_shape_fails(self):
        lines = markdown_report(example_records()).splitlines()
        lines[4] = lines[4].replace(" | ", " ", 1)
        with self.assertRaisesRegex(ValueError, "invalid result shape"):
            self.validate_text("\n".join(lines))

    def test_unescaped_pipe_fails(self):
        report = markdown_report(example_records()).replace("ECDH", "EC|DH", 1)
        with self.assertRaisesRegex(ValueError, "invalid unescaped Markdown cell"):
            self.validate_text(report)

    def test_summary_mismatch_fails(self):
        records = example_records()
        records[-1]["ok"] += 1
        with self.assertRaisesRegex(ValueError, "summary counts do not match"):
            self.validate(records)

    def test_json_is_not_accepted_as_markdown(self):
        with self.assertRaisesRegex(ValueError, "missing environment, table, or summary"):
            self.validate_text(json.dumps(example_records()))

    def test_wrong_operation_provider_fails(self):
        records = example_records()
        target = next(
            row for row in records
            if row.get("mode") == "symcrypt-preferred"
            and row.get("algorithm") == "ML-KEM"
            and row.get("operation") == "encapsulate"
        )
        target["provider"] = "default"
        with self.assertRaisesRegex(ValueError, "failed to prefer"):
            self.validate(records)

    def test_cryptographic_error_fails(self):
        records = example_records()
        records[1]["status"] = "error"
        with self.assertRaisesRegex(ValueError, "operations failed"):
            self.validate(records)

    def test_provider_on_local_comparison_fails(self):
        records = example_records()
        target = next(row for row in records if row.get("operation") == "shared_secret_check")
        target["provider"] = "default"
        with self.assertRaisesRegex(ValueError, "local secret comparison"):
            self.validate(records)

    def test_missing_expected_symcrypt_implementation_fails(self):
        records = example_records()
        targets = [
            row for row in records
            if row.get("mode") == "symcrypt-only"
            and row.get("algorithm") == "ECDH"
            and row.get("parameter") == "P-256"
        ]
        for index, row in enumerate(targets):
            row["status"] = "unsupported" if index == 0 else "not_run"
            row["provider"] = None
            row["detail"] = "not available"
        records[-1]["ok"] -= len(targets)
        records[-1]["unsupported"] += 1
        records[-1]["not_run"] += len(targets) - 1
        with self.assertRaisesRegex(ValueError, "required SymCrypt operation unavailable"):
            self.validate(records)


class SourceValidationTests(unittest.TestCase):
    def test_hash_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            archive = root / "source.tar.gz"
            archive.write_bytes(b"verified source")
            lock = root / "lock.json"
            lock.write_text(
                json.dumps(
                    {"sources": [{"name": "example", "version": "1", "archive": archive.name,
                                  "sha512": hashlib.sha512(archive.read_bytes()).hexdigest()}]}
                ),
                encoding="utf-8",
            )
            command = [sys.executable, str(ROOT / "src" / "verify_sources.py"), str(lock), str(root), archive.name]
            good = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertEqual(good.returncode, 0, good.stderr)
            omitted = subprocess.run(command[:-1], capture_output=True, text=True, check=False)
            self.assertNotEqual(omitted.returncode, 0)
            self.assertIn("exactly the archives used by the build", omitted.stderr)
            archive.write_bytes(b"modified source")
            bad = subprocess.run(command, capture_output=True, text=True, check=False)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn("SHA-512 mismatch", bad.stderr)


if __name__ == "__main__":
    unittest.main()
