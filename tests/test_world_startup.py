from dataclasses import replace
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from isac_backend.world_startup import ExperimentalWorldTemplate, read_template, walk
from isac_backend.world_continuation import ExperimentalWorldContinuation, read_continuation
from isac_backend.world_agent import ExperimentalAgentResponse, read_agent_response
from isac_backend.character_template import ExperimentalCharacterTemplate, read_character_template
from isac_backend.world_tutorial import ExperimentalTutorialActivation, read_tutorial_activation
from isac_backend.world_tutorial_objective import ExperimentalFirstObjective
from isac_backend.world_tutorial_cover import ExperimentalCoverCompletion
from isac_backend.world_tutorial_stages import (ExperimentalStageProgression,
    _read_shot_parts, decode_shot_echo)
from isac_backend.world_tutorial_next import ExperimentalNextActivity
from isac_backend.channels import Registration
from isac_protocol.codec import CompactReference, Cursor, ReferenceTable, decode_reference
from isac_protocol.codec import WireFloat32
from isac_protocol.agent_submission import AgentSubmission, encode_agent_submission
from isac_protocol.character_record import CharacterNode, decode_character_record, starting_character_record
from isac_protocol.world_messages import decode_type014d, Type0007Collection, Type0007TaggedBytes
from isac_protocol.world_start import decode_world_start
from isac_protocol.framing import InboundFrameStreamDecoder, MessageFrame, decode_outbound_envelope
from isac_protocol.game_connect import decode_game_connect_reply
from isac_protocol.transport import channel_payload
from isac_protocol.type0088 import Type0088Item, decode_type0088, encode_type0088
from isac_protocol.type00e6 import decode_type00e6
from isac_protocol.type0014 import decode_type0014, decode_type0014_compact, encode_type0014
from isac_protocol.transport import TransportStreamDecoder
from isac_backend.channels import ChannelSetup

fixture = runpy.run_path(str(ROOT / 'tests/test_world_start.py'))['startup_fixture']


def template_fixture():
    value = fixture()
    ref = lambda n: CompactReference(n.to_bytes(16, 'little'))
    items = (Type0088Item(reference_0=ref(1000), reference_1=ref(2000),
        signed_0=0, byte_0=0, byte_1=0, signed_1=0, signed_2=0, signed_3=0,
        signed_4=0, signed_5=0, signed_6=0, byte_2=0, signed_7=0, signed_8=0,
        signed_9=0, reference_2=ref(0), reference_3=ref(0), flags=0,
        children=(), auxiliary=(), trailing_byte=0, trailing_signed=0),)
    tail = replace(value.core.core_tail, fixed_bytes_4f0=ref(100).value,
        tagged_bytes_500=Type0007TaggedBytes(2, b'12345678-1234-1234-1234-123456789abc'),
        references_670_680=(ref(102), ref(102)),
        collections=tuple(Type0007Collection(c.parent_offset, (items[0].reference_0,))
            if c.parent_offset == 0x540 else c for c in value.core.core_tail.collections))
    core = replace(value.core, reference_20=ref(1), reference_4b8=ref(2),
        reference_4e0=ref(100), reference_2a0=ref(101), bytes_2b0=b'Private retail name',
        bytes_3b8=b'soldier', core_tail=tail, items_4d0=items, collection_count_4d0=len(items))
    return ExperimentalWorldTemplate(replace(value, core=core))


class WorldStartupTests(unittest.TestCase):
    def test_retail_intro_shot_reply_delta_is_bounded_to_child_status_byte(self):
        retail = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        if not retail.exists():
            self.skipTest('private retail tutorial capture unavailable')
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        decoders, events = {}, []
        for tick, kind, source, _, payload in records(retail):
            if kind == 1:
                frames = decoders.setdefault(source, InboundFrameStreamDecoder()).feed(payload)
                events.extend((tick, 'in', frame) for frame in frames
                              if frame.type_id in (0x006a, 0x00e6))
            elif kind == 2:
                events.extend((tick, 'out', frame)
                              for frame in decode_outbound_envelope(payload).frames
                              if frame.type_id == 0x006a)
        switch_stage = next(tick for tick, direction, frame in events
                            if direction == 'in' and frame.type_id == 0x00e6
                            and len(frame.body) == 177)
        shots = {}
        for tick, direction, frame in events:
            if not switch_stage - 3600 < tick < switch_stage - 3200 or frame.type_id != 0x006a:
                continue
            parts = _read_shot_parts(frame.body, None if direction == 'out'
                                      else ReferenceTable(assume_existing=True))
            shots[(direction, parts[1][0])] = parts
        self.assertEqual(set(shots), {(direction, counter)
            for direction in ('in', 'out') for counter in (31, 30, 29)})
        for counter in (31, 30, 29):
            request, reply = shots[('out', counter)], shots[('in', counter)]
            self.assertEqual(request[1:3], reply[1:3])
            self.assertEqual(len(request[3]), len(reply[3]))
            for index, (sent, echoed) in enumerate(zip(request[3], reply[3])):
                self.assertEqual(sent[0], echoed[0])
                self.assertEqual(sent[2][:-1], echoed[2][:-1])
                self.assertEqual(sent[-1], echoed[-1])
                expected = 0 if index and sent[2][-1] == 0x80 else sent[2][-1]
                self.assertEqual(echoed[2][-1], expected)

    def test_retail_cover_echo_is_compact_version_of_matching_cover_report(self):
        retail = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        if not retail.exists():
            self.skipTest('private retail tutorial capture unavailable')
        cover = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-cover-completion.py'))['prepare'](retail)
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        decoder, table = InboundFrameStreamDecoder(maximum_frame_length=16777216), ReferenceTable()
        request = None
        for tick, kind, _, _, payload in records(retail):
            if kind == 2:
                for frame in decode_outbound_envelope(payload).frames:
                    if frame.type_id == 0x0014 and cover.matches(frame.body, frame.body[:16]):
                        request = (tick, decode_type0014(frame.body))
            elif kind == 1:
                for frame in decoder.feed(payload):
                    if frame.type_id == 0x014d:
                        decode_type014d(frame.body, table)
                    elif (frame.type_id == 0x0014 and request is not None
                          and 0 < tick - request[0] <= 1000):
                        echo = decode_type0014_compact(frame.body, table)
                        self.assertEqual(replace(echo, float_0=request[1].float_0), request[1])
                        self.assertLess(abs(echo.float_0.value - request[1].float_0.value), 0.001)
                        return
        self.fail('missing matching retail compact cover echo')

    def test_raw_template_round_trip_and_private_repr(self):
        template = template_fixture()
        raw = template.to_bytes()
        self.assertEqual(ExperimentalWorldTemplate.from_bytes(raw).to_bytes(), raw)
        self.assertNotIn('Private retail', repr(template))
        for bad in (b'', raw[:-1], raw+b'\0', b'ISACWST1' + bytes(262144)):
            with self.assertRaises(ValueError):
                ExperimentalWorldTemplate.from_bytes(bad)

    def test_binding_replaces_aliases_and_preserves_assets_pose_and_unknowns(self):
        template = template_fixture()
        character, account = uuid.uuid4().bytes, str(uuid.uuid4())
        bound = template.bind(character, account, 'Local Agent')
        core, tail = bound.core, bound.core.core_tail
        self.assertEqual(core.reference_4e0.value, character)
        self.assertEqual(tail.fixed_bytes_4f0, character)
        self.assertEqual(tail.tagged_bytes_500.data, account.encode('ascii'))
        self.assertEqual(core.bytes_2b0, b'Local Agent')
        self.assertEqual(tail.references_670_680[0], tail.references_670_680[1])
        self.assertNotEqual(tail.references_670_680, template.world.core.core_tail.references_670_680)
        self.assertEqual(tail.collections[0].rows[0], core.items_4d0[0].reference_0)
        before = template.world.core
        for name in ('reference_20', 'reference_4b8', 'vector_290', 'float_29c', 'signed_288', 'bytes_3b8'):
            self.assertEqual(getattr(core, name), getattr(before, name))
        self.assertEqual([i.reference_1 for i in core.items_4d0], [i.reference_1 for i in before.items_4d0])
        self.assertNotEqual(core.items_4d0[0].reference_0.value, before.items_4d0[0].reference_0.value)
        self.assertTrue(all(r.token is None and r.side_value is None for r in walk(bound)))

    def test_bad_local_identity_or_collisions_refused(self):
        template = template_fixture()
        args = (uuid.uuid4().bytes, str(uuid.uuid4()), 'Local')
        for identifier in (bytes(16), b'bad', template.world.core.reference_20.value):
            with self.assertRaises(ValueError):
                template.bind(identifier, *args[1:])
        for account, name in (('not-a-uuid', 'Local'), (args[1], ''), (args[1], 'bad\0name')):
            with self.assertRaises(ValueError):
                template.bind(args[0], account, name)
        with self.assertRaises(ValueError):
            template.bind(*args, new_identifier=lambda: bytes(16))
        with self.assertRaises(ValueError):
            template.bind(*args, new_identifier=lambda: b'x' * 16)

    def test_private_file_requirements(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'template'
            path.write_bytes(template_fixture().to_bytes())
            path.chmod(0o600)
            self.assertEqual(read_template(path).to_bytes(), path.read_bytes())
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_template(path)
            link = Path(directory) / 'link'
            link.symlink_to(path)
            with self.assertRaises(OSError):
                read_template(link)

    def test_private_tutorial_preparation_and_rebinding(self):
        path = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        if not path.exists():
            self.skipTest('private tutorial unavailable')
        prepare = runpy.run_path(str(ROOT / 'tools/prepare-world-startup.py'))['prepare']
        load = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot']
        original = load(path).world
        template = ExperimentalWorldTemplate.from_bytes(prepare(path))
        self.assertEqual(len(template.world.core.items_4d0), 199)
        private_ids = {original.core.reference_4e0.value, original.core.reference_2a0.value,
            *(r.value for r in original.core.core_tail.references_670_680),
            *(i.reference_0.value for i in original.core.items_4d0)}
        self.assertFalse(private_ids & {r.value for r in walk(template.world)})
        self.assertNotEqual(template.world.core.core_tail.tagged_bytes_500.data,
                            original.core.core_tail.tagged_bytes_500.data)
        self.assertNotEqual(template.world.core.bytes_2b0, original.core.bytes_2b0)
        self.assertEqual(template.world.core.reference_20.value, original.core.reference_20.value)


class WorldStartupAdmissionTests(unittest.TestCase):
    def setUp(self):
        import test_server_list
        self.fixture = test_server_list.ServerListSessionTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.server = self.fixture.server
        self.server.world_template = template_fixture()
        self.joined = self.fixture.join()
        self.registration = Registration(56, b'game', self.joined.instance_name)
        self.frame = self.fixture.instance_connect(self.joined)

    def admit(self, frame=None):
        return self.fixture.handle(frame or self.frame, 43, self.registration)

    def test_complete_batch_dictionary_and_binding_reconnect_and_duplicate(self):
        event = self.admit()
        self.assertEqual(event.stage, 'instance-experimental-startup-batch-sent')
        channel, payload = channel_payload(event.response)
        self.assertEqual(channel, 43)
        stream = InboundFrameStreamDecoder()
        frames = stream.feed(payload)
        self.assertEqual(stream.buffered_bytes, 0)
        self.assertEqual(tuple(f.type_id for f in frames), (2, 0x102, 0x14d, 7, 0x00dd, 0x102))
        self.assertEqual(frames[4].body, bytes.fromhex('b44800'))
        self.assertEqual(event.response_types, tuple(f.type_id for f in frames))
        self.assertFalse(decode_game_connect_reply(frames[0].body).rejected)
        table = ReferenceTable()
        decode_type014d(frames[2].body, table)
        count = len(table.entries)
        world = decode_world_start(frames[3].body, table)
        self.assertEqual(len(table.entries), count)
        character = self.server.instances[self.joined.instance_name].character
        self.assertEqual(world.core.reference_4e0.value, character.identifier)
        self.assertEqual(world.core.core_tail.fixed_bytes_4f0, character.identifier)
        self.assertEqual(world.core.core_tail.tagged_bytes_500.data, character.owner.profile_id.encode('ascii'))
        self.assertIsNone(self.admit().response)
        self.assertEqual(self.admit(MessageFrame(0x123, b'unknown')).stage, 'instance-world-message-unimplemented')
        self.server.close(43)
        self.assertEqual(self.admit().response, event.response)

    def test_generation_failure_is_atomic(self):
        with patch.object(ExperimentalWorldTemplate, 'startup_frames', side_effect=ValueError('fixture')):
            with self.assertRaises(ValueError):
                self.admit()
        self.assertEqual(self.server.admissions, {})
        self.assertEqual(self.server.world_batches, {})
        self.assertIsNotNone(self.admit().response)

    def test_character_handoff_sends_private_first_gate_once(self):
        placeholder = b'C' * 16
        account = b'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        name = b'OldAgent1'
        private_body = placeholder + account
        continuation = ExperimentalWorldContinuation(placeholder, account, name, (
            MessageFrame(0x102, b''), MessageFrame(0xf4, bytes([len(name)]) + name + b'\1'),
            MessageFrame(0x6c, private_body),
            MessageFrame(0x1b7, bytes([len(name)]) + name + b'\7soldier' + private_body),
            MessageFrame(0x12, b'\0'),
            MessageFrame(0x102, b'')))
        self.assertEqual(ExperimentalWorldContinuation.from_bytes(continuation.to_bytes()), continuation)
        self.server.world_continuation = continuation
        character = self.server.instances[self.joined.instance_name].character
        request = MessageFrame(9, character.identifier)
        self.assertEqual(self.admit(request).stage, 'instance-not-authenticated')
        self.admit()
        self.assertEqual(self.admit(MessageFrame(9, b'x' * 16)).stage,
                         'instance-world-handoff-character-rejected')
        event = self.admit(request)
        self.assertEqual(event.stage, 'instance-experimental-first-gate-sent')
        channel, payload = channel_payload(event.response)
        self.assertEqual(channel, 43)
        frames = InboundFrameStreamDecoder().feed(payload)
        self.assertEqual([frame.type_id for frame in frames], [0x102, 0xf4, 0x6c, 0x1b7, 0x12, 0x102])
        self.assertIn(character.identifier, frames[2].body)
        self.assertIn(character.owner.profile_id.encode('ascii'), frames[2].body)
        self.assertIn(character.owner.display_name.encode('utf-8'), frames[1].body)
        self.assertEqual(frames[1].body[0], len(character.owner.display_name.encode('utf-8')))
        self.assertNotIn(placeholder, payload)
        self.assertEqual(self.admit(request).stage, 'instance-world-handoff-duplicate-ignored')
        self.server.close(43)
        self.admit()
        self.assertEqual(self.admit(request).stage, 'instance-experimental-first-gate-sent')

    def test_private_tutorial_continuation_rebinds_against_actual_startup(self):
        import types
        path = ROOT / 'private/tutorial-first-gate.isacwct'
        source = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        if not path.exists():
            self.skipTest('private first-gate artifact unavailable')
        continuation = read_continuation(path)
        self.assertEqual(len(continuation.frames), 322)
        if source.exists():
            prepared = runpy.run_path(str(ROOT / 'tools/prepare-world-continuation.py'))['prepare'](source)
            original = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
            for known in (original.created, original.world.core.core_tail.tagged_bytes_500.data,
                          original.world.core.bytes_2b0):
                self.assertNotIn(known, prepared)
        character = types.SimpleNamespace(identifier=uuid.uuid4().bytes,
            owner=types.SimpleNamespace(profile_id=str(uuid.uuid4()), display_name='ProjectISAC'))
        startup = read_template(ROOT / 'private/tutorial-startup.isacwst').startup_frames(character)
        bound = continuation.bind(character, startup[0].body)
        self.assertEqual(bound[-2].type_id, 0x12)
        self.assertEqual(bound[-1].type_id, 0x102)
        for old in (continuation.character_placeholder, continuation.account_placeholder,
                    continuation.name_placeholder):
            self.assertFalse(any(old in frame.body for frame in bound))

    def test_agent_submission_requires_handoff_and_matching_character_and_is_one_shot(self):
        placeholder = b'C' * 16
        account = b'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        name = b'OldAgent1'
        self.server.world_continuation = ExperimentalWorldContinuation(
            placeholder, account, name, (
                MessageFrame(0x102, b''),
                MessageFrame(0xf4, bytes([len(name)]) + name + b'\1'),
                MessageFrame(0x6c, placeholder + account),
                MessageFrame(0x1b7, bytes([len(name)]) + name + b'\7soldier' + placeholder + account),
                MessageFrame(0x12, b'\0'), MessageFrame(0x102, b'')))
        agent = ExperimentalAgentResponse((MessageFrame(0x14d, b'\0'),), (
            MessageFrame(0x100, b'\0'), MessageFrame(0x12, bytes(140)),
            MessageFrame(0x15a, bytes(28)), MessageFrame(0x102, b'')))
        self.assertEqual(ExperimentalAgentResponse.from_bytes(agent.to_bytes()), agent)
        self.server.agent_response = agent
        character = self.server.instances[self.joined.instance_name].character
        request = MessageFrame(0x000c, character.identifier + bytes(131))
        self.admit()
        self.assertEqual(self.admit(request).stage, 'instance-agent-before-world-handoff-rejected')
        self.assertEqual(self.admit(MessageFrame(9, character.identifier)).stage,
                         'instance-experimental-first-gate-sent')
        self.assertEqual(self.admit(MessageFrame(0x000c, b'x' * 147)).stage,
                         'instance-agent-character-rejected')
        self.assertEqual(self.admit(MessageFrame(0x000c, character.identifier)).stage,
                         'instance-agent-character-rejected')
        event = self.admit(request)
        self.assertEqual(event.stage, 'instance-experimental-agent-response-sent')
        channel, payload = channel_payload(event.response)
        self.assertEqual(channel, 43)
        frames = InboundFrameStreamDecoder().feed(payload)
        self.assertEqual([f.type_id for f in frames], [0x14d, 0x100, 0x12, 0x15a, 0x102])
        self.assertEqual(self.admit(request).stage, 'instance-agent-duplicate-ignored')
        self.server.close(43)
        self.admit()
        self.admit(MessageFrame(9, character.identifier))
        self.assertEqual(self.admit(request).stage, 'instance-experimental-agent-response-sent')

    def test_agent_submission_finalizes_local_profile_before_reply(self):
        placeholder = b'C' * 16
        account = b'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        name = b'OldAgent1'
        self.server.world_continuation = ExperimentalWorldContinuation(
            placeholder, account, name, (
                MessageFrame(0x102, b''),
                MessageFrame(0xf4, bytes([len(name)]) + name + b'\1'),
                MessageFrame(0x6c, placeholder + account),
                MessageFrame(0x1b7, bytes([len(name)]) + name + b'\7soldier' + placeholder + account),
                MessageFrame(0x12, b'\0'), MessageFrame(0x102, b'')))
        self.server.agent_response = ExperimentalAgentResponse((MessageFrame(0x14d, b'\0'),), (
            MessageFrame(0x100, b'\0'), MessageFrame(0x12, bytes(140)),
            MessageFrame(0x15a, bytes(28)), MessageFrame(0x102, b'')))
        node = CharacterNode((1, 2), b'\1\2', (3, 4), 5, b'\6\7', (), (0, 0))
        self.server.character_template = ExperimentalCharacterTemplate(replace(
            starting_character_record(), nodes=(node,) * 18, float_bits_458=(0,) * 32))
        character = self.server.instances[self.joined.instance_name].character
        slots = tuple(WireFloat32.from_float(float(i)) for i in range(32))
        request = MessageFrame(0x000c, encode_agent_submission(
            AgentSubmission(character.identifier, slots, True)))
        self.admit()
        self.admit(MessageFrame(9, character.identifier))
        invalid = self.admit(MessageFrame(0x000c, character.identifier + bytes(131)))
        self.assertEqual(invalid.stage, 'instance-agent-finalization-rejected')
        self.assertIsNone(invalid.response)
        self.assertFalse(self.fixture.profiles.store.list(character.owner.profile_id)[0].is_customized)
        self.fixture.profiles.requests[99] = {(1, 0): b'old list'}
        event = self.admit(request)
        self.assertEqual(event.stage, 'instance-agent-profile-finalized')
        self.assertNotIn((1, 0), self.fixture.profiles.requests[99])
        stored = self.fixture.profiles.store.list(character.owner.profile_id)[0]
        self.assertTrue(stored.is_customized)
        self.assertEqual(decode_character_record(stored.character_blob).float_bits_458,
                         tuple(value.bits for value in slots))
        self.assertEqual(self.admit(request).stage, 'instance-agent-duplicate-ignored')
        self.server.close(43)
        self.admit()
        self.admit(MessageFrame(9, character.identifier))
        self.assertEqual(self.admit(request).stage, 'instance-agent-profile-already-finalized')
        self.assertEqual(self.fixture.profiles.store.list(character.owner.profile_id)[0], stored)

    def test_private_character_template_has_no_profile_identity_or_progress(self):
        path = ROOT / 'private/tutorial-character.isacchr'
        if not path.exists():
            self.skipTest('private character template unavailable')
        template = read_character_template(path)
        self.assertEqual(len(template.record.nodes), 18)
        self.assertEqual(template.record.words_510_528, (0, 0, 0, 0))
        self.assertEqual(template.record.words_530_538, (0, 1, 1))
        self.assertEqual(ExperimentalCharacterTemplate.from_bytes(template.to_bytes()), template)

    def test_opt_in_first_tutorial_activation_after_local_finalization(self):
        source = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        path = ROOT / 'private/tutorial-start.isactsa'
        if not source.exists() or not path.exists():
            self.skipTest('private tutorial activation unavailable')
        prepared = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-start.py'))['prepare'](source)
        self.assertEqual(path.read_bytes(), prepared)
        activation = read_tutorial_activation(path)
        self.assertEqual(ExperimentalTutorialActivation.from_bytes(prepared), activation)
        self.server.world_template = read_template(ROOT / 'private/tutorial-startup.isacwst')
        self.server.world_continuation = read_continuation(ROOT / 'private/tutorial-first-gate.isacwct')
        self.server.agent_response = read_agent_response(ROOT / 'private/tutorial-agent.isacaut')
        self.server.character_template = read_character_template(ROOT / 'private/tutorial-character.isacchr')
        self.server.tutorial_activation = activation
        character = self.server.instances[self.joined.instance_name].character
        self.admit()
        self.assertEqual(self.admit(MessageFrame(9, character.identifier)).stage,
                         'instance-experimental-first-gate-sent')
        request = MessageFrame(0x000c, encode_agent_submission(AgentSubmission(
            character.identifier, (WireFloat32(0),) * 32, True)))
        event = self.admit(request)
        self.assertEqual(event.stage, 'instance-agent-profile-finalized-tutorial-activated')
        channel, payload = channel_payload(event.response)
        frames = InboundFrameStreamDecoder().feed(payload)
        self.assertEqual(channel, 43)
        self.assertEqual(frames[-3].type_id, 0x0102)
        self.assertEqual(frames[-2], activation.frame)
        self.assertEqual(frames[-1], MessageFrame(0x0102, b''))
        self.assertTrue(self.fixture.profiles.store.list(character.owner.profile_id)[0].is_customized)
        self.assertEqual(self.admit(request).stage, 'instance-agent-duplicate-ignored')

    def test_opt_in_first_objective_is_one_extra_validated_batch(self):
        source = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        if not source.exists():
            self.skipTest('retail tutorial capture unavailable')
        objective = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-first-objective.py'))['prepare'](source)
        self.assertEqual(ExperimentalFirstObjective.from_bytes(objective.to_bytes()), objective)
        for bad in (objective.to_bytes()[:-1], objective.to_bytes() + b'\0'):
            with self.assertRaises(ValueError):
                ExperimentalFirstObjective.from_bytes(bad)
        self.server.world_template = read_template(ROOT / 'private/tutorial-startup.isacwst')
        self.server.world_continuation = read_continuation(ROOT / 'private/tutorial-first-gate.isacwct')
        self.server.agent_response = read_agent_response(ROOT / 'private/tutorial-agent.isacaut')
        self.server.character_template = read_character_template(ROOT / 'private/tutorial-character.isacchr')
        self.server.tutorial_activation = read_tutorial_activation(ROOT / 'private/tutorial-start.isactsa')
        self.server.first_objective = objective
        character = self.server.instances[self.joined.instance_name].character
        self.admit()
        self.admit(MessageFrame(9, character.identifier))
        request = MessageFrame(0x000c, encode_agent_submission(AgentSubmission(
            character.identifier, (WireFloat32(0),) * 32, True)))
        event = self.admit(request)
        self.assertEqual(event.stage, 'instance-agent-profile-finalized-tutorial-activated')
        _, payload = channel_payload(event.response)
        frames = InboundFrameStreamDecoder().feed(payload)
        self.assertEqual([frame.type_id for frame in frames[-5:]],
                         [0x00e6, 0x0102, 0x014d, 0x00e6, 0x0102])
        table = ReferenceTable()
        startup = self.server.world_batches[self.joined.instance_name]
        decode_type014d(startup[0].body, table)
        continuation = self.server.world_continuation.bind(character, startup[0].body)
        for frame in continuation:
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                decode_type00e6(frame.body, table)
        for frame in frames:
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                state = decode_type00e6(frame.body, table)
        self.assertEqual(tuple(row.signed_0_2[2] for row in state.rows_20),
                         (0, 1, 0, 0, 0))
        self.assertEqual(len(state.rows_20[1].subrows), 1)
        self.assertEqual(state.rows_20[1].subrows[0].reference_0.value,
                         objective.objective_reference)
        self.assertEqual(self.admit(request).stage, 'instance-agent-duplicate-ignored')

    def test_cover_completion_requires_matching_event_and_is_one_shot(self):
        retail = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        local = ROOT / 'evidence/20260928-134503-951950-sdk-adapter-linux/transport-private/backend-0001-client-root.bin'
        if not retail.exists() or not local.exists():
            self.skipTest('private cover captures unavailable')
        objective = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-first-objective.py'))['prepare'](retail)
        cover = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-cover-completion.py'))['prepare'](retail)
        self.assertEqual(ExperimentalCoverCompletion.from_bytes(cover.to_bytes()), cover)
        self.server.world_template = read_template(ROOT / 'private/tutorial-startup.isacwst')
        self.server.world_continuation = read_continuation(ROOT / 'private/tutorial-first-gate.isacwct')
        self.server.agent_response = read_agent_response(ROOT / 'private/tutorial-agent.isacaut')
        self.server.character_template = read_character_template(ROOT / 'private/tutorial-character.isacchr')
        self.server.tutorial_activation = read_tutorial_activation(ROOT / 'private/tutorial-start.isactsa')
        self.server.first_objective = objective
        self.server.cover_completion = cover
        character = self.server.instances[self.joined.instance_name].character
        decoder, channels = TransportStreamDecoder(), ChannelSetup()
        local_action = None
        for root in decoder.feed(local.read_bytes()):
            event = channels.handle(root)
            if event.channel == 10:
                for inner in event.inner_frames:
                    if inner.type_id == 0x0014 and cover.matches(inner.body, inner.body[:16]):
                        local_action = decode_type0014(inner.body)
                        break
            if local_action is not None:
                break
        self.assertIsNotNone(local_action)
        matching = replace(local_action, reference_0=character.identifier)
        message = MessageFrame(0x0014, encode_type0014(matching))
        self.assertEqual(self.admit(message).stage, 'instance-cover-before-agent-ignored')
        self.admit()
        self.admit(MessageFrame(9, character.identifier))
        request = MessageFrame(0x000c, encode_agent_submission(AgentSubmission(
            character.identifier, (WireFloat32(0),) * 32, True)))
        self.assertEqual(self.admit(request).stage,
                         'instance-agent-profile-finalized-tutorial-activated')
        for bad in (replace(matching, reference_0=uuid.uuid4().bytes),
                    replace(matching, reference_1=uuid.uuid4().bytes),
                    replace(matching, bytes_0_3=(0, 0, 0, 85))):
            self.assertEqual(self.admit(MessageFrame(0x0014, encode_type0014(bad))).stage,
                             'instance-cover-candidate-ignored')
        event = self.admit(message)
        self.assertEqual(event.stage, 'instance-experimental-cover-completion-sent')
        _, payload = channel_payload(event.response)
        frames = InboundFrameStreamDecoder().feed(payload)
        self.assertEqual([frame.type_id for frame in frames], [0x014d, 0x00e6, 0x0102])
        startup = self.server.world_batches[self.joined.instance_name]
        continuation = self.server.world_continuation.bind(character, startup[0].body)
        agent = self.server.agent_response.bind(startup[0].body, continuation)
        activation = self.server.tutorial_activation.bind(startup[0].body, continuation, agent)
        first = objective.bind(startup[0].body, continuation, agent, activation)
        table = ReferenceTable()
        decode_type014d(startup[0].body, table)
        for frame in (*continuation, *agent, activation, *first, *frames):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x00e6:
                state = decode_type00e6(frame.body, table)
        self.assertEqual(tuple(row.signed_0_2[2] for row in state.rows_20),
                         (0, 4, 1, 0, 0))
        self.assertEqual(state.rows_20[2].subrows[0].reference_0.value,
                         cover.next_reference)
        self.assertEqual(self.admit(message).stage,
                         'instance-cover-completion-duplicate-ignored')

    def test_experimental_shoot_and_switch_transitions_are_gated_and_one_shot(self):
        retail = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        local = ROOT / 'evidence/20260928-152647-068114-sdk-adapter-linux/transport-private/backend-0001-client-root.bin'
        local_switch = ROOT / 'evidence/20260928-161259-736732-sdk-adapter-linux/transport-private/backend-0002-client-root.bin'
        if not retail.exists() or not local.exists() or not local_switch.exists():
            self.skipTest('private tutorial stage captures unavailable')
        objective = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-first-objective.py'))['prepare'](retail)
        cover = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-cover-completion.py'))['prepare'](retail)
        stage = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-stage-progression.py'))['prepare'](retail)
        next_module = runpy.run_path(str(ROOT / 'tools/prepare-tutorial-next-activity.py'))
        next_activity = next_module['prepare'](retail)
        dialogue_015a = next_module['prepare_dialogue_015a'](retail)
        self.assertEqual(len(dialogue_015a), 35)
        self.assertEqual(ExperimentalStageProgression.from_bytes(stage.to_bytes()), stage)
        self.assertEqual(ExperimentalNextActivity.from_bytes(next_activity.to_bytes()), next_activity)
        self.server.world_template = read_template(ROOT / 'private/tutorial-startup.isacwst')
        self.server.world_continuation = read_continuation(ROOT / 'private/tutorial-first-gate.isacwct')
        self.server.agent_response = read_agent_response(ROOT / 'private/tutorial-agent.isacaut')
        self.server.character_template = read_character_template(ROOT / 'private/tutorial-character.isacchr')
        self.server.tutorial_activation = read_tutorial_activation(ROOT / 'private/tutorial-start.isactsa')
        self.server.first_objective = objective
        self.server.cover_completion = cover
        self.server.stage_progression = stage
        self.server.next_activity = next_activity
        self.server.dialogue_015a = dialogue_015a
        character = self.server.instances[self.joined.instance_name].character
        self.assertEqual(self.admit().stage, 'instance-experimental-startup-batch-sent')
        self.server.agent_sent.add(43)
        decoder, channels = TransportStreamDecoder(), ChannelSetup()
        shots = []
        local_cover = None
        for root in decoder.feed(local.read_bytes()):
            event = channels.handle(root)
            if event.channel == 10:
                for inner in event.inner_frames:
                    if (inner.type_id == 0x0014 and local_cover is None
                            and cover.matches(inner.body, inner.body[:16])):
                        local_cover = decode_type0014(inner.body)
                    elif inner.type_id == 0x006a:
                        shots.append(inner.body)
        self.assertIsNotNone(local_cover)
        cover_body = encode_type0014(replace(local_cover, reference_0=character.identifier))
        cover_event = self.admit(MessageFrame(0x0014, cover_body))
        self.assertEqual(cover_event.stage, 'instance-experimental-cover-completion-sent')
        cover_batch = InboundFrameStreamDecoder().feed(channel_payload(cover_event.response)[1])
        self.assertEqual([frame.type_id for frame in cover_batch],
                         [0x014d, 0x0014, 0x0102, 0x014d, 0x00e6, 0x0102])
        shots = [character.identifier + body[16:] for body in shots
                 if stage.shot_header(character.identifier + body[16:], character.identifier)]
        first = next(i for i in range(len(shots) - 2)
                     if [stage.shot_header(body, character.identifier)[1]
                         for body in shots[i:i + 3]] == [31, 30, 29])
        self.assertEqual([len(body) for body in shots[first:first + 3]], [244, 244, 526])
        self.assertEqual(self.admit(MessageFrame(0x0088, b'')).stage,
                         'instance-switch-before-shooting-ignored')
        self.assertEqual(self.admit(MessageFrame(0x006a, shots[first][:-1])).stage,
                         'instance-shot-candidate-ignored')
        shot_replies = []
        for offset, expected in enumerate(('instance-experimental-shot-echo-sent',
                                           'instance-experimental-shot-echo-sent',
                                           'instance-experimental-shooting-stage-sent')):
            event = self.admit(MessageFrame(0x006a, shots[first + offset]))
            self.assertEqual(event.stage, expected)
            shot_replies.extend(InboundFrameStreamDecoder().feed(
                channel_payload(event.response)[1]))
        self.assertEqual([f.type_id for f in shot_replies],
                         [0x006a, 0x0102, 0x006a, 0x0102,
                          0x00e6, 0x006a, 0x0102])
        startup = self.server.world_batches[self.joined.instance_name]
        continuation = self.server.world_continuation.bind(character, startup[0].body)
        agent = self.server.agent_response.bind(startup[0].body, continuation)
        activation = self.server.tutorial_activation.bind(startup[0].body, continuation, agent)
        first_frames = objective.bind(startup[0].body, continuation, agent, activation)
        cover_frames = cover.bind(startup[0].body, continuation, agent, activation,
                                  first_frames, ack_request=cover_body)
        table, _ = stage._table(startup[0].body,
            (*continuation, *agent, activation, *first_frames, *cover_frames))
        for request, reply in zip(shots[first:first + 3],
                                  (f for f in shot_replies if f.type_id == 0x006a)):
            sent = _read_shot_parts(request, None)
            echoed = decode_shot_echo(reply.body, table)
            self.assertEqual(tuple(ref.value for ref in echoed[0]),
                             tuple(ref.value for ref in sent[0]))
            self.assertEqual(echoed[1:3], sent[1:3])
            self.assertEqual(len(echoed[3]), len(sent[3]))
        self.assertEqual([f.type_id for f in InboundFrameStreamDecoder().feed(
            channel_payload(event.response)[1])], [0x00e6, 0x006a, 0x0102])
        shooting_frames = InboundFrameStreamDecoder().feed(channel_payload(event.response)[1])
        self.assertEqual(self.admit(MessageFrame(0x006a, shots[first + 2])).stage,
                         'instance-shooting-stage-duplicate-ignored')
        records = runpy.run_path(str(ROOT / 'tools/inspect-retail-tutorial.py'))['records']
        retail_switch = None
        for _, kind, _, _, payload in records(retail):
            if kind == 2:
                for frame in decode_outbound_envelope(payload).frames:
                    if frame.type_id == 0x0088 and len(frame.body) == 105:
                        candidate = decode_type0088(frame.body, None)
                        if candidate.signed_0 == 1 and candidate.equipped == 0:
                            retail_switch = candidate
        self.assertIsNotNone(retail_switch)
        seed = ReferenceTable()
        decode_type014d(startup[0].body, seed)
        world = decode_world_start(startup[1].body, seed.clone())
        unequip = world.core.items_4d0[stage.unequip_item_index]
        rebound = replace(retail_switch, owner_reference=CompactReference(character.identifier),
            item=replace(retail_switch.item,
                reference_0=CompactReference(unequip.reference_0.value),
                reference_1=CompactReference(unequip.reference_1.value)))
        switch = MessageFrame(0x0088, encode_type0088(rebound, None))
        latest_decoder, latest_channels = TransportStreamDecoder(), ChannelSetup()
        first_switch = final_shot = None
        for root in latest_decoder.feed(local_switch.read_bytes()):
            latest_event = latest_channels.handle(root)
            if latest_event.channel != 10:
                continue
            for inner in latest_event.inner_frames:
                if inner.type_id == 0x0088 and len(inner.body) == 108 and first_switch is None:
                    first_switch = decode_type0088(inner.body, None)
                if (inner.type_id == 0x006a and final_shot is None and len(inner.body) >= 55
                        and inner.body[48] == 28 and inner.body[49] == 72):
                    final_shot = inner.body
        self.assertIsNotNone(first_switch)
        self.assertIsNotNone(final_shot)
        first_rebound = replace(first_switch,
            owner_reference=CompactReference(character.identifier),
            item=replace(first_switch.item,
                reference_0=CompactReference(unequip.reference_0.value),
                reference_1=CompactReference(unequip.reference_1.value)))
        first_switch_body = encode_type0088(first_rebound, None)
        self.assertEqual(len(first_switch_body), 108)
        self.assertTrue(stage.matches_switch(first_switch_body, character.identifier))
        self.assertTrue(stage.matches_switch(switch.body, character.identifier))
        switch_event = self.admit(MessageFrame(0x0088, first_switch_body))
        self.assertEqual(switch_event.stage, 'instance-experimental-switch-stage-sent')
        switch_frames = InboundFrameStreamDecoder().feed(channel_payload(switch_event.response)[1])
        self.assertEqual([frame.type_id for frame in switch_frames],
                         [0x0088, 0x0088, 0x014d, 0x00e6, 0x0102])
        continuation = self.server.world_continuation.bind(character, startup[0].body)
        agent = self.server.agent_response.bind(startup[0].body, continuation)
        activation = self.server.tutorial_activation.bind(startup[0].body, continuation, agent)
        first_frames = objective.bind(startup[0].body, continuation, agent, activation)
        cover_frames = cover.bind(startup[0].body, continuation, agent, activation,
                                  first_frames, ack_request=cover_body)
        table = ReferenceTable()
        decode_type014d(startup[0].body, table)
        observed = []
        cover_echo = None
        equipment = []
        for frame in (*continuation, *agent, activation, *first_frames, *cover_frames,
                      *shot_replies, *switch_frames):
            if frame.type_id == 0x014d:
                decode_type014d(frame.body, table)
            elif frame.type_id == 0x006a:
                decode_shot_echo(frame.body, table)
            elif frame.type_id == 0x0014:
                cover_echo = decode_type0014_compact(frame.body, table)
            elif frame.type_id == 0x0088:
                equipment.append(decode_type0088(frame.body, table.clone()))
            elif frame.type_id == 0x00e6:
                observed.append(tuple(row.signed_0_2[2] for row in
                                      decode_type00e6(frame.body, table).rows_20))
        self.assertEqual(cover_echo, decode_type0014(cover_body))
        self.assertEqual([item.equipped for item in equipment], [1, 0])
        self.assertTrue(all(item.owner_reference.value == character.identifier
                            for item in equipment))
        self.assertEqual(equipment[1].item.reference_0.value, unequip.reference_0.value)
        self.assertEqual(observed[-2:], [(0, 4, 4, 1, 0), (0, 4, 4, 4, 1)])
        self.assertEqual(self.admit(switch).stage, 'instance-switch-stage-duplicate-ignored')
        secondary_shot = (character.identifier + unequip.reference_0.value
                          + unequip.reference_1.value + final_shot[48:])
        self.assertEqual(stage.final_shot_header(secondary_shot, character.identifier,
                         unequip.reference_0.value, unequip.reference_1.value), 3)
        now = [100.0]
        self.server.clock = lambda: now[0]
        final_event = self.admit(MessageFrame(0x006a, secondary_shot))
        self.assertEqual(final_event.stage, 'instance-experimental-final-shot-stage-sent')
        final_frames = InboundFrameStreamDecoder().feed(channel_payload(final_event.response)[1])
        self.assertEqual([frame.type_id for frame in final_frames], [0x006a, 0x00e6, 0x0102])
        decode_shot_echo(final_frames[0].body, table)
        final_state = decode_type00e6(final_frames[1].body, table)
        self.assertEqual(tuple(row.signed_0_2[2] for row in final_state.rows_20),
                         (0, 4, 4, 4, 4))
        self.assertEqual(self.server.poll_due(), ())
        now[0] += 0.96
        closes = self.server.poll_due()
        self.assertEqual(len(closes), 1)
        self.assertEqual(closes[0].stage, 'instance-experimental-activity-close-sent')
        close_frames = InboundFrameStreamDecoder().feed(channel_payload(closes[0].response)[1])
        self.assertEqual([frame.type_id for frame in close_frames], [0x00e6, 0x0102])
        self.assertEqual(len(close_frames[0].body), 44)
        closed = decode_type00e6(close_frames[0].body, table)
        self.assertEqual(closed.rows_20, ())
        self.assertEqual((closed.reference_0, closed.reference_1),
                         (final_state.reference_0, final_state.reference_1))
        self.assertEqual((closed.byte_64, closed.float_50.bits,
                          closed.unsigned32_68, closed.unsigned32_80),
                         (19, 1065353216, 1, 1))
        self.assertEqual(self.server.poll_due(), ())
        now[0] += 4.0
        next_events = self.server.poll_due()
        self.assertEqual(len(next_events), 1)
        self.assertEqual(next_events[0].stage, 'instance-experimental-next-activity-sent')
        next_frames = InboundFrameStreamDecoder().feed(channel_payload(next_events[0].response)[1])
        self.assertEqual([frame.type_id for frame in next_frames],
                         [0x014d, 0x00e6, 0x0102])
        decode_type014d(next_frames[0].body, table)
        next_state = decode_type00e6(next_frames[1].body, table)
        self.assertEqual(tuple(row.signed_0_2[2] for row in next_state.rows_20),
                         (1, 0, 0, 0))
        self.assertEqual(self.server.poll_due(), ())
        now[0] += 0.26
        dialogue_events = self.server.poll_due()
        self.assertEqual(len(dialogue_events), 1)
        self.assertEqual(dialogue_events[0].stage, 'instance-experimental-dialogue-015a-sent')
        dialogue_frames = InboundFrameStreamDecoder().feed(channel_payload(dialogue_events[0].response)[1])
        self.assertEqual([frame.type_id for frame in dialogue_frames], [0x015a, 0x0102])
        self.assertEqual(dialogue_frames[0].body, dialogue_015a)
        self.assertEqual(self.server.poll_due(), ())
        self.assertEqual(self.admit(MessageFrame(0x006a, secondary_shot)).stage,
                         'instance-final-stage-duplicate-ignored')

    def test_private_tutorial_agent_artifact_matches_capture_and_dictionary(self):
        import types
        path = ROOT / 'private/tutorial-agent.isacaut'
        source = ROOT / 'evidence/20260927-064853-retail-tutorial-x3s3v01n/tutorial-private/tutorial-1200.bin'
        if not path.exists() or not source.exists():
            self.skipTest('private tutorial agent source unavailable')
        agent = read_agent_response(path)
        prepared = runpy.run_path(str(ROOT / 'tools/prepare-world-agent.py'))['prepare'](source)
        self.assertEqual(prepared, agent.to_bytes())
        original = runpy.run_path(str(ROOT / 'tools/compare-world-start.py'))['load_snapshot'](source)
        for known in (original.created, original.world.core.core_tail.tagged_bytes_500.data,
                      original.world.core.bytes_2b0):
            self.assertNotIn(known, prepared)
        character = types.SimpleNamespace(identifier=uuid.uuid4().bytes,
            owner=types.SimpleNamespace(profile_id=str(uuid.uuid4()), display_name='ProjectISAC'))
        startup = read_template(ROOT / 'private/tutorial-startup.isacwst').startup_frames(character)
        continuation = read_continuation(ROOT / 'private/tutorial-first-gate.isacwct')
        bound = continuation.bind(character, startup[0].body)
        self.assertEqual(len(agent.bind(startup[0].body, bound)), 190)

    def test_no_world_before_auth_or_after_character_removal(self):
        self.assertIsNone(self.admit(MessageFrame(1, b'')).response)
        bad = self.fixture.instance_connect(self.joined, tokens=((b'x', 1), (b'forged', 1), (b'y', 1)))
        self.assertEqual(self.admit(bad).stage, 'instance-token-rejected')
        self.assertEqual(self.server.world_batches, {})
        route = self.server.instances[self.joined.instance_name]
        self.fixture.profiles.store.archive_unfinished(route.character.owner.profile_id, route.character.identifier)
        self.assertEqual(self.admit().stage, 'instance-parent-session-rejected')
        self.assertEqual(self.server.world_batches, {})


if __name__ == '__main__':
    unittest.main()
