"""Container-only tests of the Azure Linux provider-selection port."""

import os
import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path("/usr/src/app/runtime/openssl")
SIDECAR = ROOT / "ssl/symcrypt_prov.cnf"
MODULE = ROOT / "lib/ossl-modules/symcryptprovider.so"
HOST_SHIM = pathlib.Path("/build/fips-host-flag.so")


@unittest.skipUnless(HOST_SHIM.is_file() and (ROOT / "bin/openssl").is_file(),
                     "requires the built container and host-flag test shim")
class FipsIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.sidecar = SIDECAR.read_bytes()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = pathlib.Path(self.temporary.name)
        self.flag = self.directory / "fips_enabled"
        self.flag.write_text("0\n")
        self.environment = dict(
            os.environ, LD_BIND_NOW="1", LD_PRELOAD=str(HOST_SHIM),
            TEST_FIPS_FLAG_FILE=str(self.flag),
            OPENSSL_CONF=str(ROOT / "ssl/openssl.cnf"),
            OPENSSL_MODULES=str(MODULE.parent),
        )
        self.environment.pop("OPENSSL_FORCE_FIPS_MODE", None)
        self.addCleanup(SIDECAR.write_bytes, self.sidecar)

    def providers(self, expected, success=True, fips_properties=False):
        result = subprocess.run(
            [str(ROOT / "bin/openssl"), "list", "-providers"],
            env=self.environment, capture_output=True, text=True, check=False,
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            actual = {line.strip() for line in result.stdout.splitlines()
                      if line.startswith("  ") and not line.startswith("    ")}
            self.assertEqual(actual, set(expected), result.stdout)
            properties = subprocess.run(
                ["/build/fips-properties", str(int(fips_properties))],
                env=self.environment, capture_output=True, text=True, check=False,
            )
            self.assertEqual(properties.returncode, 0, properties.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertIn("error:", result.stderr)

    def hide_module(self):
        hidden = MODULE.with_suffix(".so.test-hidden")
        self.assertFalse(hidden.exists())
        MODULE.rename(hidden)
        self.addCleanup(hidden.rename, MODULE)

    def test_non_fips_automatically_loads_symcrypt(self):
        self.providers(("default", "symcryptprovider"))

    def test_kernel_flag_automatically_loads_symcrypt(self):
        self.flag.write_text("1\n")
        self.providers(("default", "symcryptprovider"))

    def test_unreadable_kernel_flag_is_non_fips(self):
        self.flag.unlink()
        SIDECAR.unlink()
        self.providers(("default",))

    def test_non_fips_without_sidecar_uses_default(self):
        SIDECAR.unlink()
        self.providers(("default",))

    def test_non_fips_missing_module_is_best_effort(self):
        self.hide_module()
        self.providers(("default",))

    def test_forced_mode_uses_presence_not_value(self):
        for value in ("1", "0", ""):
            with self.subTest(value=value):
                self.environment["OPENSSL_FORCE_FIPS_MODE"] = value
                self.providers(("default", "symcryptprovider"))

    def test_fips_without_sidecar_loads_module_by_name(self):
        SIDECAR.unlink()
        self.flag.write_text("1\n")
        self.providers(("default", "symcryptprovider"))

    def test_fips_fails_without_either_provider(self):
        self.hide_module()
        SIDECAR.unlink()
        self.flag.write_text("1\n")
        self.providers((), success=False)

    def test_override_fails_without_either_provider(self):
        self.hide_module()
        SIDECAR.unlink()
        self.environment["OPENSSL_FORCE_FIPS_MODE"] = "0"
        self.providers((), success=False)

    def test_fips_parsed_sidecar_preserves_upstream_nonfatal_failure(self):
        self.hide_module()
        self.flag.write_text("1\n")
        self.providers(("default",))

    def test_malformed_sidecar_fails_in_fips_mode(self):
        SIDECAR.write_text("[invalid\n")
        self.flag.write_text("1\n")
        self.providers((), success=False)

    def test_already_activated_provider_skips_sidecar(self):
        config = self.directory / "explicit.cnf"
        config.write_text(
            "openssl_conf = init\nconfig_diagnostics = 1\n"
            "[init]\nproviders = providers\n"
            "[providers]\ndefault = default_section\nsymcryptprovider = symcrypt\n"
            "[default_section]\nactivate = 1\n"
            f"[symcrypt]\nactivate = 1\nmodule = {MODULE}\n"
        )
        self.environment["OPENSSL_CONF"] = str(config)
        self.flag.write_text("1\n")
        SIDECAR.write_text("[invalid\n")
        self.providers(("default", "symcryptprovider"))

    def fips_standin_config(self):
        # Legacy is only a loader fixture, not a FIPS implementation.
        config = ROOT / "ssl/fipsmodule.cnf"
        self.assertFalse(config.exists())
        config.write_text(
            "[fips_sect]\nactivate = 1\nidentity = fips\n"
            f"module = {MODULE.parent / 'legacy.so'}\n"
        )
        self.addCleanup(config.unlink)

    def test_fips_fallback_loads_base_and_enables_properties(self):
        SIDECAR.unlink()
        self.hide_module()
        self.fips_standin_config()
        self.flag.write_text("1\n")
        self.providers(("default", "fips", "base"), fips_properties=True)

    def test_fips_fallback_by_name_without_sidecars(self):
        SIDECAR.unlink()
        self.hide_module()
        standin = MODULE.parent / "fips.so"
        self.assertFalse(standin.exists())
        standin.symlink_to(MODULE.parent / "legacy.so")
        self.addCleanup(standin.unlink)
        self.flag.write_text("1\n")
        self.providers(("default", "fips", "base"), fips_properties=True)

    def test_symcrypt_has_priority_over_fips_standin(self):
        self.fips_standin_config()
        self.flag.write_text("1\n")
        self.providers(("default", "symcryptprovider"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
