import importlib.util
import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("compatibility", ROOT / "src/validate_compatibility.py")
compatibility = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compatibility)


class CompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"libsymcrypt.so.103": pathlib.Path("/usr/lib/libsymcrypt.so.103.8.0")}
        self.good = " libsymcrypt.so.103 => /usr/lib/libsymcrypt.so.103.8.0 (0x1234)\n"

    def test_expected_dependency_passes(self):
        compatibility.validate_dependencies(self.good, self.expected)

    def test_wrong_library_fails(self):
        with self.assertRaisesRegex(ValueError, "expected"):
            compatibility.validate_dependencies(self.good.replace("/usr/lib/", "/private/"), self.expected)

    def test_missing_dependency_fails(self):
        with self.assertRaisesRegex(ValueError, "got None"):
            compatibility.validate_dependencies("", self.expected)

    def test_unresolved_symbol_fails(self):
        with self.assertRaisesRegex(ValueError, "Unresolved ELF"):
            compatibility.validate_dependencies(self.good + "undefined symbol: SymCryptExample", self.expected)

    def test_library_not_found_fails(self):
        with self.assertRaisesRegex(ValueError, "Unresolved ELF"):
            compatibility.validate_dependencies("libsymcrypt.so.103 => not found", self.expected)


if __name__ == "__main__":
    unittest.main()
