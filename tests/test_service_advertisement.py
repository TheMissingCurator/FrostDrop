from collections import Counter
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_backend.services import local_service_advertisements
from isac_protocol.codec import DecodeError, encode_length_prefixed_bytes as lp
from isac_protocol.service_advertisement import (
    ServiceAdvertisement, decode_service_advertisement, encode_service_advertisement,
)
from isac_protocol.transport import TransportFrame, TransportStreamDecoder, encode_transport_frame


class AdvertisementTests(unittest.TestCase):
    def test_independent_wire_vector_has_one_outer_delimiter(self):
        record = ServiceAdvertisement(b"n", ((b"type", b"auth"), (b"process_guid", b"p")))
        expected = bytes.fromhex("3a05016e02047479706504617574680c70726f636573735f677569640170")
        self.assertEqual(encode_transport_frame(encode_service_advertisement(record)), expected)
        self.assertEqual(decode_service_advertisement(TransportStreamDecoder().feed(expected)[0]), record)

    def test_bounds_duplicates_embedded_nuls_and_empty_fields(self):
        for record in (ServiceAdvertisement(b"", ()),
                       ServiceAdvertisement(b"x" * 63, ((b"k" * 63, b"v" * 511),) * 24),
                       ServiceAdvertisement(b"a\0b", ((b"k", b"v\0x"), (b"k", b""), (b"", b"z")))):
            self.assertEqual(decode_service_advertisement(encode_service_advertisement(record)), record)
        for record in (ServiceAdvertisement(b"x" * 64, ()),
                       ServiceAdvertisement(b"n", ((b"k", b"v"),) * 25),
                       ServiceAdvertisement(b"n", ((b"k" * 64, b"v"),)),
                       ServiceAdvertisement(b"n", ((b"k", b"v" * 512),))):
            with self.assertRaises(ValueError):
                encode_service_advertisement(record)

    def test_malformed_truncated_and_wrong_protocol_frames(self):
        valid = encode_service_advertisement(ServiceAdvertisement(b"n", ((b"type", b"auth"),)))
        for body in (b"", lp(b"x" * 64) + b"\0", lp(b"n") + b"\x19",
                     lp(b"n") + b"\1" + lp(b"k" * 64) + lp(b"v"),
                     lp(b"n") + b"\1" + lp(b"k") + lp(b"v" * 512), valid.body + b"\0"):
            with self.assertRaises(DecodeError):
                decode_service_advertisement(TransportFrame(False, 5, body))
        for size in range(len(valid.body)):
            with self.assertRaises(DecodeError):
                decode_service_advertisement(TransportFrame(False, 5, valid.body[:size]))
        for frame in (TransportFrame(True, 5, valid.body), TransportFrame(False, 6, valid.body)):
            with self.assertRaises(DecodeError):
                decode_service_advertisement(frame)

    def test_local_catalog_shape_stability_and_fragmented_transport(self):
        records = local_service_advertisements()
        self.assertEqual(records, local_service_advertisements())
        self.assertEqual(len(records), 24)
        names = {r.name for r in records}
        processes = {dict(r.attributes)[b"process_guid"] for r in records}
        self.assertEqual(len(names), 24)
        self.assertEqual(len(processes), 24)
        self.assertFalse(names & processes)
        for value in names | processes:
            self.assertRegex(value, rb"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{16}$")
        for record in records:
            self.assertEqual([k for k, _ in record.attributes], [b"type", b"process_guid"])
        self.assertEqual(Counter(dict(r.attributes)[b"type"] for r in records), Counter({
            b"profile_client": 2, b"group": 2, b"chat": 2, b"push_message": 2,
            b"auth": 2, b"server_list": 2, b"match": 1, b"last_stand_match": 1,
            b"messaging": 2, b"survival_session": 1, b"profile_cache_front": 2,
            b"leaderboard_client_handler": 1, b"money": 2, b"user_logs": 1, b"survival_match": 1,
        }))
        decoder = TransportStreamDecoder()
        frames = []
        for record in records:
            for byte in encode_transport_frame(encode_service_advertisement(record)):
                frames.extend(decoder.feed(bytes([byte])))
        decoder.finish()
        self.assertEqual(tuple(map(decode_service_advertisement, frames)), records)


if __name__ == "__main__":
    unittest.main()
