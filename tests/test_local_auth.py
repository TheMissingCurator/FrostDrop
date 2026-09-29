from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_backend.auth import AuthSession, decode_local_auth_request, experimental_login_response
from isac_backend.channels import Registration
from isac_backend.sdk_services import SDKServices, ACCOUNT_ID
from isac_protocol.codec import DecodeError, encode_length_prefixed_bytes
from isac_protocol.control_messages import decode_type0003
from isac_protocol.framing import MessageFrame, decode_length_prefixed_frame
from isac_protocol.transport import channel_payload


class LocalAuthTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 27, tzinfo=timezone.utc)
        self.sdk = SDKServices(lambda: self.now)
        self.session = self.sdk.create_session()
        self.ticket = self.session["ticket"].encode()
        self.validator = Mock(side_effect=lambda ticket: self.sdk.validate_ticket(ticket.decode()))
        self.auth = AuthSession(self.validator, lambda: self.now.timestamp())
        self.registration = Registration(1, b"auth", next(iter(self.auth.auth_targets)))
        self.request = MessageFrame(2, encode_length_prefixed_bytes(self.ticket) + bytes(14))

    def test_issued_expired_revoked_and_forged_sdk_tickets(self):
        profile = self.sdk.validate_ticket(self.session["ticket"])
        self.assertEqual(profile.profile_id, ACCOUNT_ID)
        for invalid in (None, [], "retail-token", "isac-local-" + "0" * 64):
            self.assertIsNone(self.sdk.validate_ticket(invalid))
        self.now += timedelta(hours=3)
        self.assertIsNone(self.sdk.validate_ticket(self.session["ticket"]))
        other = self.sdk.create_session()
        del self.sdk.sessions[other["sessionId"]]
        self.assertIsNone(self.sdk.validate_ticket(other["ticket"]))

    def test_partial_request_schema_is_bounded_and_preserves_unknown_tail(self):
        self.assertEqual(decode_local_auth_request(self.request.body), self.ticket)
        for body in (b"", self.request.body[:-1], self.request.body + b"\0",
                     b"\x80" * 90, bytes(90), b"\x4b" + b"x" * 75 + bytes(14)):
            with self.assertRaises(DecodeError):
                decode_local_auth_request(body)

    def test_reply_on_registered_channel_contains_local_profile_not_sdk_ticket(self):
        result = self.auth.handle(17, self.registration, self.request)
        self.assertEqual(result.stage, "auth-experimental-reply-sent")
        channel, payload = channel_payload(result.response)
        self.assertEqual(channel, 17)  # No channel-zero assumption.
        frame = decode_length_prefixed_frame(payload)
        self.assertEqual(frame.type_id, 3)
        reply = decode_type0003(frame.body, None)
        self.assertEqual(reply.identity.value.decode(), ACCOUNT_ID)
        self.assertEqual(reply.bytes_0, b"ProjectISAC")
        self.assertEqual(reply.bundle.entries, ())
        blobs = (reply.timed_blob_0, reply.timed_blob_1, reply.timed_blob_2)
        self.assertEqual([len(b.bytes_0) for b in blobs], [240, 240, 272])
        self.assertEqual(len({b.bytes_0 for b in blobs}), 3)
        self.assertTrue(all(b.bytes_0.startswith(b"isac-experimental-") and b.uint64_0 == 8640 for b in blobs))
        self.assertNotIn(self.ticket, frame.body)

    def test_only_exact_auth_binding_can_get_a_reply(self):
        for registration in (Registration(1, b"other", self.registration.target),
                             Registration(1, b"auth", b"unknown")):
            self.assertEqual(self.auth.handle(0, registration, self.request).stage, "unbound-observe-only")
        self.assertEqual(self.auth.handle(0, self.registration, MessageFrame(5, b"" )).stage, "auth-unknown-message")
        self.validator.assert_not_called()
        bad = self.auth.handle(0, self.registration, MessageFrame(2, b"bad"))
        self.assertEqual(bad.stage, "auth-unsupported-request")
        self.validator.assert_not_called()

    def test_duplicate_conflict_revoke_close_and_attempt_limit(self):
        self.auth.handle(0, self.registration, self.request)
        self.assertEqual(self.auth.handle(0, self.registration, self.request).stage, "auth-duplicate-ignored")
        changed = MessageFrame(2, self.request.body[:-1] + b"\1")
        self.assertEqual(self.auth.handle(0, self.registration, changed).stage, "auth-conflicting-request")
        self.auth.close(0)
        self.assertEqual(self.auth.handle(1, self.registration, self.request).stage, "auth-experimental-reply-sent")
        del self.sdk.sessions[self.session["sessionId"]]
        self.assertEqual(self.auth.handle(1, self.registration, self.request).stage, "auth-ticket-rejected")
        for _ in range(4):
            last = self.auth.handle(1, self.registration, self.request)
        self.assertEqual(last.stage, "auth-attempt-limit")
        self.assertIsNone(last.response)

    def test_expiry_caps_reply_and_failed_validation_never_sends(self):
        profile = self.sdk.validate_ticket(self.session["ticket"])
        reply = decode_type0003(experimental_login_response(profile, profile.expires_at - 20).body, None)
        self.assertEqual(reply.timed_blob_1.uint64_0, 20)
        with self.assertRaises(ValueError):
            experimental_login_response(profile, profile.expires_at)
        self.auth.validator = lambda _: None
        self.assertIsNone(self.auth.handle(0, self.registration, self.request).response)


if __name__ == "__main__":
    unittest.main()
