"""Opt-in, capture-derived startup experiment; NOT a gameplay simulator.

Templates contain a fully decoded/re-encoded WorldStart, never opaque replay
spans. Unknown fields remain capture-derived. Only the established character
binding and explicitly experimental local identity substitutions are changed.
No file/network access occurs while constructing a per-route startup batch.
"""
from dataclasses import dataclass, field, fields, is_dataclass, replace
import os
import stat
import uuid

from isac_protocol.codec import CompactReference, ReferenceTable, encode_svarint32, encode_uvarint
from isac_protocol.framing import MessageFrame
from isac_protocol.world_messages import Type014D, encode_type014d
from isac_protocol.world_start import WorldStart, decode_world_start, encode_world_start

MAGIC = b'ISACWST1'
MAX_TEMPLATE_BYTES = 262144


def read_template(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_TEMPLATE_BYTES):
            raise ValueError('world template must be a bounded, owner-only regular file')
        return ExperimentalWorldTemplate.from_bytes(stream.read(MAX_TEMPLATE_BYTES + 1))


def walk(value):
    if isinstance(value, CompactReference):
        yield value
    elif is_dataclass(value):
        for member in fields(value):
            yield from walk(getattr(value, member.name))
    elif isinstance(value, tuple):
        for child in value:
            yield from walk(child)


def rebind(value, references):
    """Replace aliases everywhere and discard ALL capture-local tokens."""
    if isinstance(value, CompactReference):
        if value.value is None:
            raise ValueError('world template has an unresolved reference')
        return CompactReference(references.get(value.value, value.value))
    if is_dataclass(value):
        return replace(value, **{member.name: rebind(getattr(value, member.name), references)
            for member in fields(value)})
    if isinstance(value, tuple):
        return tuple(rebind(child, references) for child in value)
    return value


@dataclass(frozen=True)
class ExperimentalWorldTemplate:
    world: WorldStart = field(repr=False)

    def __post_init__(self):
        core, tail = self.world.core, self.world.core.core_tail
        if (core.bytes_3b8 != b'soldier' or tail.tagged_bytes_500.tag != 2
                or len(tail.tagged_bytes_500.data) != 36
                or core.reference_4e0.value != tail.fixed_bytes_4f0
                or not any(tail.fixed_bytes_4f0)):
            raise ValueError('unsupported experimental tutorial identity/archetype shape')
        try:
            uuid.UUID(tail.tagged_bytes_500.data.decode('ascii'))
        except (ValueError, UnicodeError) as error:
            raise ValueError('unsupported experimental tagged identity') from error
        runtime = [core.reference_4e0.value, core.reference_2a0.value,
            *(r.value for r in tail.references_670_680),
            *(item.reference_0.value for item in core.items_4d0)]
        if (any(v is None or not any(v) for v in runtime)
                or runtime[0] in runtime[1:]
                or len({item.reference_0.value for item in core.items_4d0}) != len(core.items_4d0)):
            raise ValueError('ambiguous runtime identity aliases in template')
        assets = {core.reference_20.value, core.reference_4b8.value,
                  *(item.reference_1.value for item in core.items_4d0)}
        if assets.intersection(runtime):
            raise ValueError('runtime identity overlaps an established asset candidate')
        if any(r.value is None for r in walk(self.world)):
            raise ValueError('world template has an unresolved reference')

    @classmethod
    def from_bytes(cls, data):
        if not len(MAGIC) < len(data) <= MAX_TEMPLATE_BYTES or not data.startswith(MAGIC):
            raise ValueError('invalid experimental world template header/size')
        return cls(decode_world_start(data[len(MAGIC):], None))

    def to_bytes(self):
        body = MAGIC + encode_world_start(self.world, None)
        if len(body) > MAX_TEMPLATE_BYTES:
            raise ValueError('experimental world template exceeds bound')
        return body

    def bind(self, character_id, account_id, display_name, new_identifier=lambda: uuid.uuid4().bytes):
        """Local substitutions are test policy, not proof of unknown semantics.

        +500 is provisionally the local account identity; +2a0/+670/+680
        get route-lifetime IDs with aliases preserved. Preserve spawn, asset keys, stats,
        lists and flags. Do not reset unknown state to guessed zero defaults.
        """
        if len(character_id) != 16 or not any(character_id):
            raise ValueError('invalid local world character identifier')
        account = str(uuid.UUID(account_id)).encode('ascii')
        name = display_name.encode('utf-8')
        if not 1 <= len(name) <= 63 or b'\0' in name:
            raise ValueError('invalid local world display name')
        core, tail = self.world.core, self.world.core.core_tail
        replacements = {core.reference_4e0.value: character_id}
        used = {r.value for r in walk(self.world)} | {character_id, bytes(16)}
        if character_id in {r.value for r in walk(self.world)}:
            raise ValueError('local character collides with template identity')
        for old in (core.reference_2a0.value, *(r.value for r in tail.references_670_680),
                    *(item.reference_0.value for item in core.items_4d0)):
            if old in replacements:
                continue
            fresh = new_identifier()
            if not isinstance(fresh, bytes) or len(fresh) != 16 or fresh in used:
                raise ValueError('invalid or colliding local world identifier')
            replacements[old] = fresh
            used.add(fresh)
        result = rebind(self.world, replacements)
        result = replace(result, core=replace(result.core, bytes_2b0=name,
            core_tail=replace(result.core.core_tail, fixed_bytes_4f0=character_id,
                tagged_bytes_500=replace(tail.tagged_bytes_500, data=account))))
        return result

    def startup_frames(self, character):
        value = self.bind(character.identifier, character.owner.profile_id,
                          character.owner.display_name)
        references = tuple(dict.fromkeys(r.value for r in walk(value)))
        table = ReferenceTable()
        seed = encode_type014d(Type014D(tuple(CompactReference(r) for r in references)), table)
        snapshot = encode_world_start(value, table)
        # 00dd immediately follows 0007 in three retail starts. Its reader
        # consumes signed32 then unsigned32; 4634,0 are observed constants,
        # not established semantic defaults. 0102 flushes the decoded batch.
        state = encode_svarint32(4634) + encode_uvarint(0, maximum_bits=32)
        return (MessageFrame(0x014d, seed), MessageFrame(7, snapshot),
                MessageFrame(0x00dd, state), MessageFrame(0x0102, b''))
