"""Protocol 556, independently corroborated by five historical PCAP flows."""
from isac_protocol.codec import Cursor, DecodeError, encode_uvarint
from isac_protocol.transport import TransportFrame, encode_protocol_version, encode_transport_frame


def latency_greeting() -> bytes:
    return encode_protocol_version(556) + encode_transport_frame(
        TransportFrame(False, 0, encode_uvarint(200)))


class LatencySession:
    def __init__(self):
        self.next_sequence = 0
        self.complete = False

    def handle(self, frame: TransportFrame) -> TransportFrame | None:
        if self.complete or frame.control:
            raise DecodeError("unexpected latency message")
        cursor = Cursor(frame.body)
        if frame.type_id == 1:
            sequence = cursor.read_uvarint(maximum_bits=32)
            if cursor.remaining or sequence != self.next_sequence or sequence >= 3:
                raise DecodeError("invalid latency sequence")
            self.next_sequence += 1
            return TransportFrame(False, 2, encode_uvarint(sequence))
        if frame.type_id == 3:
            values = tuple(cursor.read_uvarint(maximum_bits=32) for _ in range(5))
            if cursor.remaining or self.next_sequence != 3 or values[0] != 3:
                raise DecodeError("invalid latency summary")
            self.complete = True
            return None
        raise DecodeError("unsupported latency message")
