"""GDB driver test entry; only used with the tiny non-game test executable."""
import importlib.util
from pathlib import Path
import gdb
import os

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("driver", root / "tools/sdk_adapter_gdb.py")
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
if Path(gdb.current_progspace().filename).name != "sdk-debugger-fixture":
    raise RuntimeError("This entry is exclusively a synthetic fixture")
import sdk_adapter_transport as transport
# Synthetic-only relocation: production always uses the attested main-image RVA.
transport.CERT_RVA = int(gdb.parse_and_eval("&fixture_certificate_site")) - 1
instance = driver.Driver(isolation_check=lambda _inferior: None, fixture=True)
instance.transport_chain = b"\0\0\4TEST"
if os.environ.get("ISAC_FIXTURE_TRACE") == "1":
    import sdk_backend_trace
    sdk_backend_trace.SITES = {name: (int(gdb.parse_and_eval("&fixture_" + name + "_site")) - 1, b"\x90")
                              for name in sdk_backend_trace.SITES}
    instance.backend_trace_requested = True
if os.environ.get("ISAC_FIXTURE_HANDOFF") == "1":
    import sdk_backend_trace
    sdk_backend_trace.HANDOFF_SITES = {
        name: (int(gdb.parse_and_eval("&fixture_" + name + "_site")) - 1, b"\x90")
        for name in sdk_backend_trace.HANDOFF_SITES}
    sdk_backend_trace.GETTERS = {
        int(gdb.parse_and_eval("&fixture_getter" + format(offset, "x"))) - 1: (offset, signature)
        for offset, signature in sdk_backend_trace.GETTERS.values()}
    instance.backend_trace_requested = True
    instance.backend_trace_profile = "handoff"
if os.environ.get("ISAC_FIXTURE_CHANNEL") == "1":
    import sdk_backend_trace
    sdk_backend_trace.CHANNEL_SITES = {
        name: (int(gdb.parse_and_eval("&fixture_route_" + name + "_site")) - 1, b"\x90")
        for name in sdk_backend_trace.CHANNEL_SITES}
    # Synthetic-only instruction check. Production still attests all five
    # prologue/predicate signatures and the exact stack-depth contracts.
    sdk_backend_trace.CHANNEL_AUXILIARY = {
        int(gdb.parse_and_eval("&fixture_route_channel_site")) - 1: b"\x90"}
    instance.backend_trace_requested = True
    instance.backend_trace_profile = "channel"
if os.environ.get("ISAC_FIXTURE_NAME") == "1":
    import sdk_backend_trace
    sdk_backend_trace.NAME_SITES = {
        name: (int(gdb.parse_and_eval("&fixture_name_" + name + "_site")) - 1, b"\x90")
        for name in sdk_backend_trace.NAME_SITES}
    sdk_backend_trace.NAME_GETTER_RVAS = {
        "temporary": int(gdb.parse_and_eval("&fixture_getter48")) - 1,
        "record": int(gdb.parse_and_eval("&fixture_getter30")) - 1,
        "collection": int(gdb.parse_and_eval("&fixture_count")) - 1}
    sdk_backend_trace.NAME_AUXILIARY = {
        sdk_backend_trace.NAME_GETTER_RVAS["temporary"]: bytes.fromhex("48 8b 41 48 c3"),
        sdk_backend_trace.NAME_GETTER_RVAS["record"]: bytes.fromhex("48 8b 41 30 c3"),
        sdk_backend_trace.NAME_GETTER_RVAS["collection"]: bytes.fromhex("8b 41 08 c3")}
    instance.backend_trace_requested = True
    instance.backend_trace_profile = "name-lineage"
instance.run()
