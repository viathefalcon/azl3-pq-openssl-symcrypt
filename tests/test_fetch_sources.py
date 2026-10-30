import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
POWERSHELL = shutil.which("powershell.exe")

MOCK_VCPKG_SOURCE = r"""
using System;
using System.IO;

public static class MockVcpkg
{
    public static int Main(string[] args)
    {
        if (Environment.GetEnvironmentVariable("VCPKG_ROOT") != Environment.GetEnvironmentVariable("MOCK_EXPECT_ROOT") ||
            Environment.GetEnvironmentVariable("VCPKG_DISABLE_METRICS") != "1")
        {
            Console.Error.WriteLine("incorrect vcpkg environment: root={0}, expected={1}, metrics={2}",
                Environment.GetEnvironmentVariable("VCPKG_ROOT"),
                Environment.GetEnvironmentVariable("MOCK_EXPECT_ROOT"),
                Environment.GetEnvironmentVariable("VCPKG_DISABLE_METRICS"));
            return 10;
        }
        if (args.Length == 1 && args[0] == "version")
        {
            Console.WriteLine("vcpkg version unit-test");
            return 0;
        }
        if (args.Length != 5 || args[0] != "x-download" ||
            args[2] != "--sha512=" + Environment.GetEnvironmentVariable("MOCK_SHA512") ||
            args[3] != "--url=" + Environment.GetEnvironmentVariable("MOCK_URL") ||
            args[4] != "--x-asset-sources=clear")
            return 3;

        File.AppendAllText(Environment.GetEnvironmentVariable("MOCK_LOG"), "download\n");
        if (Environment.GetEnvironmentVariable("MOCK_FAIL") == "1")
            return 9;
        if (Environment.GetEnvironmentVariable("MOCK_EMPTY") == "1")
            return 0;
        File.Copy(Environment.GetEnvironmentVariable("MOCK_ASSET"), args[1], true);
        return 0;
    }
}
"""

MOCK_DOWNLOAD_WRAPPER = r"""
$ErrorActionPreference = 'Stop'
function Invoke-WebRequest {
    param([string] $Uri, [string] $OutFile, [switch] $UseBasicParsing)
    if ($Uri -ne $env:MOCK_TOOL_URL) { throw 'Unexpected vcpkg URL' }
    [System.IO.File]::AppendAllText($env:MOCK_TOOL_LOG, "download`n")
    if ($env:MOCK_TOOL_FAIL -eq '1') {
        [System.IO.File]::WriteAllText($OutFile, 'partial download')
        throw 'Mock vcpkg download failed'
    }
    if ($env:MOCK_TOOL_EMPTY -eq '1') { return }
    [System.IO.File]::Copy($env:MOCK_TOOL, $OutFile, $true)
}

$previousRoot = $env:VCPKG_ROOT
$previousMetrics = $env:VCPKG_DISABLE_METRICS
$previousProtocol = [Net.ServicePointManager]::SecurityProtocol
try {
    & (Join-Path $PSScriptRoot 'fetch-sources.ps1') @args
} finally {
    if ($env:VCPKG_ROOT -ne $previousRoot -or $env:VCPKG_DISABLE_METRICS -ne $previousMetrics -or
        [Net.ServicePointManager]::SecurityProtocol -ne $previousProtocol) {
        throw 'The fetch script did not restore the vcpkg environment'
    }
}
"""


@unittest.skipUnless(os.name == "nt" and POWERSHELL, "requires Windows PowerShell")
class FetchSourcesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory(prefix="vcpkg test executable ")
        cls.addClassCleanup(cls.fixture.cleanup)
        cls.fixture_executable = pathlib.Path(cls.fixture.name) / "vcpkg.exe"
        env = os.environ.copy()
        env.pop("PSMODULEPATH", None)
        env["MOCK_SOURCE"] = MOCK_VCPKG_SOURCE
        env["MOCK_EXE"] = str(cls.fixture_executable)
        result = subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-Command",
                "Add-Type -TypeDefinition $env:MOCK_SOURCE -OutputAssembly $env:MOCK_EXE "
                "-OutputType ConsoleApplication",
            ],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Could not compile mock vcpkg: {result.stderr}")

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fetch sources ")
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.addCleanup(self.temporary.cleanup)
        shutil.copy2(ROOT / "fetch-sources.ps1", self.root)
        self.asset = self.root / "upstream asset"
        self.asset.write_bytes(b"known upstream content")
        self.archive = self.root / "downloads" / "source.tar.gz"
        self.log = self.root / "download log"
        self.tool_asset = self.root / "upstream vcpkg.exe"
        shutil.copy2(self.fixture_executable, self.tool_asset)
        self.executable = self.root / ".vcpkg" / "vcpkg.exe"
        self.tool_log = self.root / "vcpkg download log"
        self.wrapper = self.root / "run-fetch.ps1"
        self.wrapper.write_text(MOCK_DOWNLOAD_WRAPPER, encoding="ascii")
        (self.root / "sources.lock.json").write_text(
            json.dumps(
                {
                    "vcpkg": {
                        "version": "unit-test",
                        "url": "https://example.com/vcpkg.exe",
                        "sha256": hashlib.sha256(self.tool_asset.read_bytes()).hexdigest(),
                    },
                    "sources": [
                        {
                            "name": "example",
                            "version": "1",
                            "archive": self.archive.name,
                            "url": "https://example.com/source.tar.gz",
                            "sha512": hashlib.sha512(self.asset.read_bytes()).hexdigest(),
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env.pop("PSMODULEPATH", None)
        self.env.pop("MOCK_FAIL", None)
        self.env.pop("MOCK_EMPTY", None)
        self.env.pop("MOCK_TOOL_FAIL", None)
        self.env.pop("MOCK_TOOL_EMPTY", None)
        self.env["MOCK_LOG"] = str(self.log)
        self.env["MOCK_ASSET"] = str(self.asset)
        self.env["MOCK_URL"] = "https://example.com/source.tar.gz"
        self.env["MOCK_SHA512"] = hashlib.sha512(self.asset.read_bytes()).hexdigest()
        self.env["MOCK_TOOL"] = str(self.tool_asset)
        self.env["MOCK_TOOL_URL"] = "https://example.com/vcpkg.exe"
        self.env["MOCK_TOOL_LOG"] = str(self.tool_log)
        self.env["MOCK_EXPECT_ROOT"] = str(self.executable.parent)
        self.env["VCPKG_ROOT"] = str(self.root / "unrelated vcpkg root")
        self.env["VCPKG_EXE"] = str(self.root / "unrelated vcpkg.exe")
        self.env["VCPKG_SDK_ROOT"] = str(self.root / "unrelated sdk")
        self.env["VCPKG_DISABLE_METRICS"] = "previous value"
        self.env["X_VCPKG_ASSET_SOURCES"] = "x-block-origin"

    def fetch(self, *arguments):
        return subprocess.run(
            [
                POWERSHELL,
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(self.wrapper),
                *arguments,
            ],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )

    def test_bootstraps_locally_and_fetches_without_external_asset_sources(self):
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.executable.read_bytes(), self.tool_asset.read_bytes())
        self.assertEqual(self.tool_log.read_text().splitlines(), ["download"])
        self.assertEqual(self.archive.read_bytes(), self.asset.read_bytes())
        self.assertEqual(self.log.read_text().splitlines(), ["download"])
        self.assertEqual(list(self.executable.parent.glob("*.download")), [])

    def test_verified_cache_does_not_require_metadata_or_a_download(self):
        self.archive.parent.mkdir()
        self.archive.write_bytes(self.asset.read_bytes())
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.tool_log.read_text().splitlines(), ["download"])
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.tool_log.read_text().splitlines(), ["download"])
        self.assertFalse(self.log.exists())

    def test_absent_vcpkg_environment_is_restored(self):
        self.env.pop("VCPKG_ROOT")
        self.env.pop("VCPKG_DISABLE_METRICS")
        result = self.fetch()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_external_tool_options_are_rejected(self):
        for option in ("-VcpkgExe", "-SdkRoot"):
            result = self.fetch(option, str(self.root / "unrelated"))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("A parameter cannot be found", result.stderr)
            self.assertFalse(self.tool_log.exists())

    def test_corrupted_vcpkg_cache_is_rejected_before_execution(self):
        self.executable.parent.mkdir()
        self.executable.write_bytes(b"corrupted tool")
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incorrect SHA-256", result.stderr)
        self.assertEqual(self.executable.read_bytes(), b"corrupted tool")
        self.assertFalse(self.tool_log.exists())
        self.assertFalse(self.log.exists())

    def test_failed_or_invalid_tool_download_preserves_the_cache(self):
        self.executable.parent.mkdir()
        self.executable.write_bytes(b"cached tool")
        self.tool_asset.write_bytes(b"incorrect tool download")
        result = self.fetch("-Refresh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incorrect SHA-256", result.stderr)
        self.assertEqual(self.executable.read_bytes(), b"cached tool")
        self.assertEqual(list(self.executable.parent.glob("*.download")), [])

        for flag, message in (
            ("MOCK_TOOL_FAIL", "Mock vcpkg download failed"),
            ("MOCK_TOOL_EMPTY", "vcpkg download did not create"),
        ):
            self.env[flag] = "1"
            result = self.fetch("-Refresh")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(message, result.stderr)
            self.assertEqual(self.executable.read_bytes(), b"cached tool")
            self.assertEqual(list(self.executable.parent.glob("*.download")), [])
            del self.env[flag]
        self.assertEqual(self.tool_log.read_text().splitlines(), ["download"] * 3)
        self.assertFalse(self.log.exists())

    def test_refresh_replaces_a_stale_project_local_tool(self):
        self.executable.parent.mkdir()
        self.executable.write_bytes(b"stale tool")
        self.archive.parent.mkdir()
        self.archive.write_bytes(b"stale archive")
        result = self.fetch("-Refresh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.executable.read_bytes(), self.tool_asset.read_bytes())
        self.assertEqual(self.archive.read_bytes(), self.asset.read_bytes())
        self.assertEqual(self.tool_log.read_text().splitlines(), ["download"])
        self.assertEqual(self.log.read_text().splitlines(), ["download"])

    def test_unexpected_vcpkg_version_fails_before_source_download(self):
        lock_path = self.root / "sources.lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["vcpkg"]["version"] = "other-version"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Expected vcpkg tool version other-version", result.stderr)
        self.assertFalse(self.log.exists())

    def test_corrupted_cache_is_rejected(self):
        self.archive.parent.mkdir()
        self.archive.write_bytes(b"corrupted")
        result = self.fetch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incorrect SHA-512", result.stderr)
        self.assertEqual(self.archive.read_bytes(), b"corrupted")

    def test_refresh_verifies_before_replacing_the_cache(self):
        self.archive.parent.mkdir()
        self.archive.write_bytes(b"known upstream content")
        self.asset.write_bytes(b"corrupted download")
        result = self.fetch("-Refresh")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incorrect SHA-512", result.stderr)
        self.assertEqual(self.archive.read_bytes(), b"known upstream content")
        self.assertEqual(list(self.archive.parent.glob("*.download")), [])

        self.archive.write_bytes(b"stale cached content")
        self.asset.write_bytes(b"known upstream content")
        result = self.fetch("-Refresh")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.archive.read_bytes(), self.asset.read_bytes())
        self.assertEqual(self.log.read_text().splitlines(), ["download", "download"])
        self.assertEqual(list(self.archive.parent.glob("*.download")), [])

    def test_failed_or_missing_download_does_not_replace_the_cache(self):
        self.archive.parent.mkdir()
        self.archive.write_bytes(self.asset.read_bytes())
        for expected_calls, flag in enumerate(("MOCK_FAIL", "MOCK_EMPTY"), start=1):
            self.env[flag] = "1"
            result = self.fetch("-Refresh")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("could not fetch", result.stderr)
            self.assertEqual(self.log.read_text().splitlines(), ["download"] * expected_calls)
            self.assertEqual(self.archive.read_bytes(), self.asset.read_bytes())
            self.assertEqual(list(self.archive.parent.glob("*.download")), [])
            del self.env[flag]


if __name__ == "__main__":
    unittest.main()
