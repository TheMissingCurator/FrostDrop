#!/usr/bin/env python3
"""Summarize targeted profile captures without printing account/character data."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from isac_protocol.codec import Cursor, DecodeError
from isac_protocol.character_record import decode_character_record, encode_character_record


def decode(event, body):
    if event == 'agent_submit':
        if len(body) != 16 or not any(body):
            raise DecodeError('invalid character-only submit marker')
        return {'identifier': body}
    c = Cursor(body)
    result = {"request_id": c.read_uvarint(maximum_bits=32)}
    def flag():
        v = c.read_u8_varint()
        if v > 1:
            raise DecodeError("noncanonical flag")
        return bool(v)
    if event == "create_request":
        result.update(flag_5=flag(), flag_4=flag())
    elif event == "create_reply":
        result["status"] = c.read_uvarint(maximum_bits=32)
        if result["status"] == 0:
            result["identifier"] = c.read(16)
    elif event == "profile_list":
        result.update(success=flag(), flag_128=flag(), flag_129=flag(),
                      uint32_8=c.read_uvarint(maximum_bits=32),
                      bytes_130=c.read_length_prefixed_bytes(maximum_length=63))
        count = c.read_uvarint(maximum_bits=32)
        if count > 8:
            raise DecodeError("profile count exceeds capture bound")
        result["profiles"] = []
        for _ in range(count):
            entry = {"identifier": c.read(16), "uint32_10": c.read_uvarint(maximum_bits=32),
                     "flag_14": flag(), "uint64_18": c.read_uvarint(), "uint64_20": c.read_uvarint(),
                     "bytes_80": c.read_length_prefixed_bytes(maximum_length=63),
                     "bytes_28": c.read_length_prefixed_bytes(maximum_length=63),
                     "flags_d8_to_db": tuple(flag() for _ in range(4)), "flag_300": flag(),
                     "blob_e0": c.read_length_prefixed_bytes(maximum_length=10000)}
            result["profiles"].append(entry)
    elif event == "token_handoff":
        result.update(status=c.read_uvarint(maximum_bits=32),
                      bytes_8=c.read_length_prefixed_bytes(maximum_length=63),
                      bytes_60=c.read_length_prefixed_bytes(maximum_length=63),
                      flag_b8=flag(), flag_920=flag())
    else:
        raise DecodeError("unknown capture event")
    if c.remaining:
        raise DecodeError("trailing capture bytes")
    return result


def summarize(path):
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError("oversized capture")
    created, requests = set(), set()
    ended = False
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            print(f"line={line_no} unreadable-record (possibly interrupted write)")
            continue
        event = record.get("event")
        if event in ("starting", "ready", "coverage", "end", "refused"):
            if event == "end":
                ended = True
            # Print only known scalar diagnostics; never arbitrary source strings.
            if event != "coverage":
                print("observer=" + event)
            continue
        if not record.get("complete"):
            print(f"line={line_no} incomplete-field-capture; not decoded")
            continue
        if event not in ("create_request", "create_reply", "profile_list", "token_handoff", "agent_submit"):
            print(f"line={line_no} unsupported-event")
            continue
        expected = ("handoff-metadata-v1" if event == "token_handoff" else
                    "character-id-only-v1" if event == "agent_submit" else
                    "reconstructed-body-v1")
        if record.get("encoding") != expected:
            raise ValueError("unsupported capture encoding")
        body = bytes.fromhex(record["data_hex"])
        if len(body) > 98304:
            raise ValueError("oversized record")
        data = decode(event, body)
        fields = (f"event={event} captured_bytes={len(body)}"
                  if event == 'agent_submit' else
                  f"event={event} request_id={data['request_id']} captured_bytes={len(body)}")
        if event == "create_request":
            requests.add(data["request_id"])
        elif event == "create_reply":
            fields += f" status={data['status']} request_seen={data['request_id'] in requests}"
            if "identifier" in data:
                created.add(data["identifier"])
        elif event == 'agent_submit':
            fields += f" created_id_match={data['identifier'] in created}"
        elif event == "profile_list":
            profiles = data["profiles"]
            created_profiles = [p for p in profiles if p['identifier'] in created]
            fields += f" success={data['success']} profiles={len(profiles)}"
            fields += f" newly_created_present={bool(created_profiles)}"
            fields += f" newly_created_customized={[p['flags_d8_to_db'][2] for p in created_profiles]}"
            fields += f" character_blob_lengths={[len(p['blob_e0']) for p in profiles]}"
            shapes = []
            for p in profiles:
                try:
                    record = decode_character_record(p['blob_e0'])
                    shapes.append({'version': 8, 'nodes': len(record.nodes),
                                   'float_slots': len(record.float_bits_458),
                                   'pairs': len(record.pairs_4d8),
                                   'roundtrip': encode_character_record(record) == p['blob_e0']})
                except (DecodeError, ValueError):
                    shapes.append({'decoded': False})
            fields += f" character_blob_shapes={shapes}"
        else:
            fields += f" status={data['status']} scope=handoff-metadata-only"
        print(fields)
    if not ended:
        print("No end record: capture may still be running or ended abruptly; absence is not proof.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    paths = (sorted((args.capture / "profile-private").glob("profile-*.jsonl"))
             + sorted((args.capture / "finalization-private").glob("finalization-*.jsonl"))) if args.capture.is_dir() else [args.capture]
    if not paths:
        parser.error("no profile capture files")
    try:
        for path in paths:
            print(path.name)
            summarize(path)
    except (OSError, ValueError, KeyError, TypeError) as error:
        # No body snippets or account strings in diagnostics.
        parser.exit(1, f"Capture inspection failed ({type(error).__name__}).\n")


if __name__ == "__main__":
    main()
