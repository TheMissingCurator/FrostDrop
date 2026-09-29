from pathlib import Path
import runpy
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.channels import ChannelSetup
from isac_protocol.framing import decode_outbound_envelope
from isac_protocol.transport import TransportStreamDecoder
from isac_protocol.type0014 import decode_type0014, encode_type0014
from isac_protocol.codec import DecodeError


class Type0014Tests(unittest.TestCase):
    def test_bounded_rejection(self):
        for body in (b'', b'\0' * 129):
            with self.assertRaises(DecodeError):
                decode_type0014(body)

    def test_retail_and_local_cover_window_round_trip(self):
        retail = (ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/'
                  'tutorial-private/tutorial-1200.bin')
        local = (ROOT / 'evidence/20260928-134503-951950-sdk-adapter-linux/'
                 'transport-private/backend-0001-client-root.bin')
        if not retail.exists() or not local.exists():
            self.skipTest('private cover comparison captures unavailable')
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        origin = retail_character = None
        retail_cover = []
        for tick, kind, _, _, payload in records(retail):
            if origin is None:
                origin = tick
            if kind != 2:
                continue
            for frame in decode_outbound_envelope(payload).frames:
                if frame.type_id == 0x000c and len(frame.body) == 147:
                    retail_character = frame.body[:16]
                elif frame.type_id == 0x0014 and 99_000 < tick - origin < 112_000:
                    value = decode_type0014(frame.body)
                    self.assertEqual(encode_type0014(value), frame.body)
                    retail_cover.append(value)
        self.assertEqual(len(retail_cover), 3)
        self.assertTrue(all(value.reference_0 == retail_character for value in retail_cover))
        decoder, channels = TransportStreamDecoder(), ChannelSetup()
        local_character = None
        local_cover = []
        for frame in decoder.feed(local.read_bytes()):
            event = channels.handle(frame)
            if event.channel != 10:
                continue
            for inner in event.inner_frames:
                if inner.type_id == 0x000c:
                    local_character = inner.body[:16]
                elif local_character is not None and inner.type_id == 0x0014:
                    value = decode_type0014(inner.body)
                    self.assertEqual(encode_type0014(value), inner.body)
                    self.assertEqual(value.reference_0, local_character)
                    local_cover.append(value)
        self.assertEqual(len(local_cover), 28)
        # Exact static cover-object reference and the first retail entry shape
        # both occur locally. This does not itself prove a completion gate.
        matching = [value for value in local_cover
            if value.reference_1 == retail_cover[0].reference_1
            and value.signed_0 == retail_cover[0].signed_0
            and value.signed_1 == retail_cover[0].signed_1
            and value.signed_2 == retail_cover[0].signed_2
            and value.bytes_0_3 == retail_cover[0].bytes_0_3]
        self.assertTrue(matching)
        self.assertTrue(any(abs(value.vector_1[0].value - 372.3) < 0.2
                            and abs(value.vector_1[2].value - 639.0) < 0.2
                            for value in matching))
