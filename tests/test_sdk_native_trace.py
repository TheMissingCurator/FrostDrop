import importlib.util
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("sdk_native_trace", ROOT / "tools/analyze-sdk-native-trace.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


def trace(api="NtSetContextThread", kind="SysCall", timestamp="123.005", pid="0138", tid="013c", context="00104000"):
    args = {"NtSetContextThread": f"fffffffffffffffe,{context}", "NtGetContextThread": f"fffffffffffffffe,{context}",
            "NtProtectVirtualMemory": "ffffffffffffffff,00105000,00105008,00000008,00105010",
            "NtQueryVirtualMemory": "ffffffffffffffff,143471510,00000000,00105000,00000030,00105010"}[api]
    body = f"SysCall  {api}({args})" if kind == "SysCall" else f"SysRet   {api}() retval=c0000022"
    return f"{timestamp}:{pid}:{tid}:{body}\n"


def marker(operation="set", phase="begin", tick=123000, tag="SDK_NATIVE_CONTEXT"):
    fields = (f"operation={operation},phase={phase},unix_ms=999,context=0x104000,flags=0x100010,"
              "ok=0,win32_error=5,unchanged=1,enabled_slots=0x0") if tag == "SDK_NATIVE_CONTEXT" else (
        f"phase={phase},target=0x143471510,length=50,requested=0x8,win32_error=5")
    return f"{tag} tick_ms={tick} process=312 thread=316 detail={fields}\n"


class NativeTraceTest(unittest.TestCase):
    def test_numeric_dispatcher_parser_and_allowlist(self):
        value = native.native_record(trace())
        self.assertEqual((value["pid"], value["tid"], value["args"][1]), (312, 316, 0x104000))
        self.assertEqual(native.native_record(trace(kind="SysRet"))["ntstatus"], 0xc0000022)
        for line in (trace().replace("NtSetContextThread", "SecretFunction"),
                     trace().replace("00104000", "TOKEN"), trace().replace(",00104000", ""),
                     trace() + "ACCOUNT_TOKEN=SECRET", trace().replace("00104000", "0" * 17),
                     trace(kind="SysRet").replace("retval=c0000022", "retval=SECRET")):
            self.assertIsNone(native.native_record(line))

    def test_marker_parser_bounds_and_redaction(self):
        value = native.marker_record(marker().replace("\n", ",TOKEN=SECRET\n"))
        self.assertNotIn("TOKEN", value)
        self.assertEqual(value["context"], 0x104000)
        for line in (marker(operation="secret"), marker(phase="wrong"),
                     marker().replace("flags=0x100010", "flags=0x10001f"),
                     marker().replace("ok=0", "ok=2"),
                     marker().replace("context=0x104000", "context=-1"),
                     marker(tag="SDK_NATIVE_PROTECT_BOUNDARY").replace("length=50", "length=9000")):
            self.assertIsNone(native.marker_record(line))

    def report(self, markers, logs):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "project-isac-stack-probe.log").write_text(markers)
            for index, log in enumerate(logs):
                (root / f"steam-{index}.log").write_text(log)
            return native.analyze(root), native.collect(root)

    def test_context_return_requires_pointer_thread_and_operation_window(self):
        markers = marker() + marker(phase="end", tick=123010)
        good = trace() + trace(kind="SysRet", timestamp="123.009")
        report, data = self.report(markers, [good])
        self.assertIn("Observed NtSetContextThread return NTSTATUS=0xc0000022", report)
        self.assertEqual(data["matched_returns"]["NtSetContextThread"], 1)
        for log in (good.replace("013c", "0140"), good.replace("00104000", "00106000"),
                    good.replace("123.005", "122.000"), good.replace("123.009", "124.000")):
            report, _ = self.report(markers, [log])
            self.assertNotIn("Observed NtSetContextThread return", report)

    def test_no_pairing_across_logs_or_wrong_thread(self):
        markers = marker() + marker(phase="end", tick=123010)
        _, data = self.report(markers, [trace(), trace(kind="SysRet")])
        self.assertEqual(data["matched_returns"]["NtSetContextThread"], 0)
        self.assertEqual(data["orphan_returns"], 1)
        _, data = self.report(markers, [trace() + trace(kind="SysRet", tid="0140")])
        self.assertEqual(data["matched_returns"]["NtSetContextThread"], 0)

    def test_mismatched_marker_identity_and_entry_without_return(self):
        markers = marker() + marker(phase="end", tick=123010).replace("context=0x104000", "context=0x106000")
        report, data = self.report(markers, [trace() + trace(kind="SysRet")])
        self.assertFalse(data["windows"])
        self.assertIn("Incomplete operation windows", report)
        self.assertNotIn("Observed NtSetContextThread return", report)
        report, _ = self.report(marker() + marker(phase="end", tick=123010), [trace()])
        self.assertIn("native entries=1 native paired calls=0", report)
        self.assertNotIn("Observed NtSetContextThread return", report)

    def test_context_nested_calls_pair_lifo(self):
        markers = marker() + marker(phase="end", tick=123010)
        log = trace() + trace(context="00106000", timestamp="123.006") + trace(kind="SysRet", timestamp="123.007") + trace(kind="SysRet", timestamp="123.008")
        report, data = self.report(markers, [log])
        self.assertEqual(data["matched_returns"]["NtSetContextThread"], 2)
        self.assertIn("native paired calls=1", report)

    def test_protection_pointer_slots_alone_do_not_identify_target(self):
        markers = marker(tag="SDK_NATIVE_PROTECT_BOUNDARY") + marker(tag="SDK_NATIVE_PROTECT_BOUNDARY", phase="end", tick=123010)
        pair = trace("NtProtectVirtualMemory") + trace("NtProtectVirtualMemory", kind="SysRet", timestamp="123.009")
        report, _ = self.report(markers, [pair])
        self.assertIn("native paired candidates=1", report)
        self.assertNotIn("Observed target-correlated", report)
        decoded = "123.006:0138:013c:trace:virtual:NtProtectVirtualMemory 0xffffffffffffffff 0x143471510 00000032 00000008\n"
        log = trace("NtProtectVirtualMemory") + decoded + trace("NtProtectVirtualMemory", kind="SysRet", timestamp="123.009")
        report, _ = self.report(markers, [log])
        self.assertIn("Observed target-correlated native NtProtectVirtualMemory return NTSTATUS=0xc0000022", report)
        report, _ = self.report(markers, [log.replace("0x143471510", "0x143471511")])
        self.assertNotIn("Observed target-correlated", report)

    def test_absent_trace_is_not_proof_and_startup_is_not_sdk_call(self):
        report, _ = self.report("", [trace() + trace(kind="SysRet")])
        self.assertIn("Missing native-operation markers", report)
        self.assertNotIn("Observed NtSetContextThread return", report)
        report, _ = self.report(marker() + marker(phase="end", tick=123010), ["SECRET_TOKEN=account\n"])
        self.assertIn("absence is not evidence of interception", report)
        self.assertNotIn("SECRET", report)


if __name__ == "__main__":
    unittest.main()
