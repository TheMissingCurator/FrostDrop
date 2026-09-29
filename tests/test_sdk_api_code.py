import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / filename)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


reference = load("sdk_api_reference", "sdk-api-reference.py")
analysis = load("sdk_code_analysis", "analyze-sdk-protection.py")


def image(symbol="VirtualProtect", relocation=False):
    data = bytearray(0x2400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 60, 0x100)
    data[0x100:0x104] = b"PE\0\0"
    struct.pack_into("<HHI", data, 0x104, 0x8664, 1, 123)
    struct.pack_into("<H", data, 0x114, 240)
    opt = 0x118
    struct.pack_into("<H", data, opt, 0x20b)
    struct.pack_into("<Q", data, opt + 24, 0x180000000)
    struct.pack_into("<II", data, opt + 56, 0x4000, 0x400)
    struct.pack_into("<I", data, opt + 108, 16)
    struct.pack_into("<II", data, opt + 112, 0x1000, 0x180)
    section = opt + 240
    struct.pack_into("<IIII", data, section + 8, 0x2000, 0x1000, 0x2000, 0x400)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    struct.pack_into("<IIIII", data, 0x400 + 20, 1, 1, 0x1100, 0x1120, 0x1140)
    struct.pack_into("<I", data, 0x500, 0x1200)
    struct.pack_into("<I", data, 0x520, 0x1160)
    struct.pack_into("<H", data, 0x540, 0)
    name = symbol.encode() + b"\0"
    data[0x560:0x560 + len(name)] = name
    data[0x600:0x6b0] = b"\x90" * 176
    if relocation:
        struct.pack_into("<II", data, opt + 112 + 40, 0x1400, 12)
        struct.pack_into("<IIHH", data, 0x800, 0x1000, 12, 0xa208, 0)
        struct.pack_into("<Q", data, 0x608, 0x180000020)
    return data


def code_line(api="kernel32.VirtualProtect", phase="begin", hex_data=None):
    length = analysis.CODE_APIS[api]
    if hex_data is None:
        hex_data = (b"\x90" * length).hex()
    return (f"SDK_API_CODE tick_ms=1 process=312 thread=316 detail=phase={phase},unix_ms=123000,"
            f"api={api},status=ok,entry=0x180001200,allocation=0x180000000,rva=0x1200,"
            f"timestamp=123,image_size=0x4000,length={length},code_hex={hex_data}\n")


def jump_line(phase="begin"):
    return (f"SDK_JUMP_CODE tick_ms=1 process=312 thread=316 detail=phase={phase},status=ok,"
            "entry=0x180001200,target=0x180005000,allocation=0x180005000,protect=0x20,"
            "memory_type=0x20000,length=128,code_hex=" + "90" * 128 + "\n")


def path_line(status="complete", completed=1, jumped=1):
    return (f"SDK_PROTECT_PATH tick_ms=1 process=312 thread=316 detail=phase=write-failed,status={status},"
            "thread=316,entry=0x180001200,jump=0x180005000,returned=0x18000223d,target=0x143471510,"
            f"length=50,requested=0x8,entered=1,jumped={jumped},completed={completed},ntstatus=0xc0000022,win32_error=5\n")


class CodeTest(unittest.TestCase):
    def test_jump_and_return_parser_bounds_and_redaction(self):
        value = analysis.path_record(jump_line().replace("\n", ",TOKEN=SECRET\n"))
        self.assertEqual(len(value["bytes"]), 128)
        self.assertNotIn("TOKEN", value)
        self.assertEqual(analysis.path_record(path_line())["ntstatus"], 0xc0000022)
        for line in (jump_line().replace("length=128", "length=2048"),
                     jump_line().replace("memory_type=0x20000", "memory_type=0x1000000"),
                     jump_line().replace("protect=0x20", "protect=0x120"),
                     jump_line().replace("target=0x180005000", "target=0x1000"),
                     path_line().replace("ntstatus=0xc0000022", "ntstatus=0x1c0000022"),
                     path_line().replace("completed=1", "completed=2"),
                     path_line().replace("entered=1", "entered=0")):
            self.assertIsNone(analysis.path_record(line))

    @patch.object(analysis, "disassemble_code", return_value="bounded fixture")
    def test_return_report_requires_correlated_call_and_code(self, _):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "project-isac-stack-probe.log"
            displacement = (0x180005000 - 0x180001205).to_bytes(4, "little", signed=True)
            nt = code_line("ntdll.NtProtectVirtualMemory", hex_data=(b"\xe9" + displacement + b"\x90" * 27).hex())
            kb = code_line("kernelbase.VirtualProtect").replace("entry=0x180001200", "entry=0x180002200").replace("rva=0x1200", "rva=0x2200")
            call = ("SDK_PROTECT_CALL tick_ms=1 process=312 thread=316 detail=phase=begin,target=0x143471510,length=50,requested=0x8\n")
            valid = nt + kb + call + jump_line() + path_line()
            path.write_text(valid)
            report = "\n".join(analysis.path_report(root))
            self.assertIn("Observed raw NtProtect return NTSTATUS=0xc0000022", report)
            self.assertIn("does not identify who installed", report)
            for text in (valid.replace(call, ""), valid.replace(call, call.replace("thread=316", "thread=999")),
                         valid.replace(path_line(), path_line("incomplete", 0)),
                         valid.replace("jump=0x180005000", "jump=0x180005001")):
                path.write_text(text)
                report = "\n".join(analysis.path_report(root))
                self.assertNotIn("Observed raw NtProtect return", report)
            path.write_text(valid.replace(path_line(), path_line(jumped=0)))
            self.assertIn("jump destination was not hit", "\n".join(analysis.path_report(root)))

    def test_pe_export_code_and_relocation_metadata(self):
        pe = reference.PE(image(relocation=True))
        self.assertEqual(pe.export_rva("VirtualProtect"), 0x1200)
        self.assertTrue(pe.executable(0x1200, 176))
        self.assertEqual(pe.relocations(0x1200, 24), [{"offset": 8, "width": 8}])
        with self.assertRaises(ValueError):
            pe.export_rva("Missing")
        with self.assertRaises(ValueError):
            pe.raw(0x3fff, 24)

    def test_pe_rejects_malformed_forwarded_and_unbacked_windows(self):
        for mutate in (lambda data: data.__setitem__(slice(0, 2), b"NO"),
                       lambda data: struct.pack_into("<I", data, 60, 0xffffff),
                       lambda data: struct.pack_into("<H", data, 0x106, 200),
                       lambda data: struct.pack_into("<I", data, 0x500, 0x1100)):
            data = image()
            mutate(data)
            with self.assertRaises(ValueError):
                reference.PE(data).export_rva("VirtualProtect")
        data = image(relocation=True)
        struct.pack_into("<I", data, 0x804, 7)
        with self.assertRaises(ValueError):
            reference.PE(data).relocations(0x1200, 24)

    def test_reference_only_allowlisted_files_and_no_paths(self):
        with tempfile.TemporaryDirectory(prefix="SECRET_PATH-") as directory:
            prefix = Path(directory)
            system = prefix / "drive_c/windows/system32"
            system.mkdir(parents=True)
            for _, (module, symbol, _) in reference.APIS.items():
                (system / module).write_bytes(image(symbol))
            (system / "game.exe").write_text("SECRET_ACCOUNT_TOKEN")
            result = reference.reference(prefix)
            self.assertEqual(set(result["apis"]), set(reference.APIS))
            self.assertTrue(all(item["status"] == "ok" for item in result["apis"].values()))
            self.assertNotIn("SECRET", json.dumps(result))
        missing = reference.reference(Path("/nonexistent/SECRET"))
        self.assertNotIn("SECRET", json.dumps(missing))
        self.assertTrue(all(item["status"] == "reference-unavailable" for item in missing["apis"].values()))

    def test_live_parser_rejects_arbitrary_api_and_malformed_bytes(self):
        value = analysis.code_record(code_line().replace("\n", ",TOKEN=SECRET\n"))
        self.assertEqual(len(value["bytes"]), 24)
        self.assertNotIn("TOKEN", value)
        for line in (code_line().replace("api=kernel32.VirtualProtect", "api=game.Payload"),
                     code_line(hex_data="00"), code_line(hex_data="GG" * 24),
                     code_line().replace("rva=0x1200", "rva=0x1300"),
                     code_line().replace("length=24", "length=10000")):
            self.assertIsNone(analysis.code_record(line))

    def test_relocation_adjustment_and_identity_validation(self):
        record = analysis.code_record(code_line())
        disk = reference.PE(image(relocation=True))
        ref = {"status": "ok", "timestamp": 123, "image_size": 0x4000, "rva": 0x1200,
               "length": 24, "image_base": 0x180000000, "code_hex": disk.raw(0x1200, 24).hex(),
               "relocations": disk.relocations(0x1200, 24)}
        record["allocation"] += 0x100000
        adjusted = analysis.expected_code(ref, record)
        self.assertEqual(int.from_bytes(adjusted[8:16], "little"), 0x180100020)
        for changes in ({"timestamp": 999}, {"relocations": [{"offset": 23, "width": 8}]},
                        {"relocations": ref["relocations"] * 2}):
            with self.assertRaises(ValueError):
                analysis.expected_code({**ref, **changes}, record)

    @patch.object(analysis, "disassemble_code", return_value="safe fixture disassembly")
    def test_report_match_difference_changed_reference_and_missing_coverage(self, _):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prefix = root / "prefix"
            system = prefix / "drive_c/windows/system32"
            system.mkdir(parents=True)
            for _, (module, symbol, _) in reference.APIS.items():
                (system / module).write_bytes(image(symbol))
            ref = reference.reference(prefix)
            for name in ("sdk-api-reference.json", "sdk-api-reference-after.json"):
                (root / name).write_text(json.dumps(ref))
            log = root / "project-isac-stack-probe.log"
            log.write_text("".join(code_line(api) for api in reference.APIS))
            report = "\n".join(analysis.code_report(root))
            self.assertEqual(report.count("matches the stable prefix DLL"), 3)
            self.assertIn("not an execution trace", report)
            log.write_text(code_line(hex_data="cc" + "90" * 23))
            report = "\n".join(analysis.code_report(root))
            self.assertIn("LIVE/REFERENCE DIFFERENCE", report)
            self.assertIn("does not establish Ubisoft/DRM", report)
            self.assertIn("Missing pre-call code coverage", report)
            ref["apis"]["kernel32.VirtualProtect"]["file_sha256"] = "0" * 64
            (root / "sdk-api-reference-after.json").write_text(json.dumps(ref))
            report = "\n".join(analysis.code_report(root))
            self.assertIn("Reference comparison unavailable", report)
            self.assertNotIn("LIVE/REFERENCE DIFFERENCE", report)

    @unittest.skipUnless(shutil.which("objdump"), "objdump unavailable")
    def test_disassembly_only_bounded_fixture_instructions(self):
        output = analysis.disassemble_code(b"\xb8\x05\x00\x00\x00\xc3", 0x1000)
        self.assertIn("mov", output)
        self.assertIn("ret", output)
        self.assertNotIn("/tmp", output)


if __name__ == "__main__":
    unittest.main()
