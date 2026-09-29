# Finding 027: inbound injection helper ABI is complete

Date: 2026-09-24

## Capture

```text
evidence/20260924-180331-injection-helpers-linux
```

The capture reached a normal menu and completed without probe errors. It
recorded 27 complete transport deliveries, including five multi-chunk chains.
Lengths ranged from 3 to 4,096 bytes. The generic append hook reached its
intentional 128-event cap; this does not truncate the helper code capture.

## Outer lock guard

RVA `0x0000b7e0` has the effective signature:

```text
guard *reader_lock(guard *guard, lock_object *lock)
```

The complete 29-byte function:

1. stores `lock` into the first pointer-sized field of `guard`;
2. calls the acquire primitive at RVA `0x00015670` with `lock`; and
3. returns `guard`.

The wrapper passes its stack local as `guard` and secondary-reader offset
`+0x10` as `lock`. Since the secondary interface begins at primary-reader
offset `+0x08`, this lock object is primary-reader offset `+0x18`. The guard
requires one eight-byte field on this 64-bit build.

## Reader notification

RVA `0x0001e0a0` accepts the address of the reader notification field. It
loads the pointer stored in that field and enters the notification primitive.
The delivery wrapper passes secondary-reader offset `+0x60`, equivalent to
primary-reader offset `+0x68`.

The short helper is a protected runtime thunk, so its internal target is not
useful as a stable ABI. Calling RVA `0x0001e0a0` exactly as the retail wrapper
does preserves that boundary.

## Outer unlock

RVA `0x0000c6c0` has the effective signature:

```text
void reader_unlock(guard *guard)
```

It loads the pointer saved in the guard. A null pointer returns immediately;
otherwise it tail-calls the release primitive at RVA `0x0001f110`. No second
guard field or destructor state is read.

## Injection contract

After retaining the exact primary reader and its source at `reader+0x70`, an
inbound plaintext delivery can use the following sequence:

```text
uint64 guard = 0
reader_lock(&guard, reader + 0x18)
append(reader->source_at_0x70, bytes, length)
reader_notify(reader + 0x68)
reader_unlock(&guard)
```

Here `append` is RVA `0x223d140`. It owns the copy into the game's 1,000-byte
source chunks, so the caller's byte buffer only needs to remain valid for the
duration of the call.

This is an implementation-ready application-plaintext injection boundary.
It does not solve response semantics, source-object lifetime, or suppression
of the retail network path. Those remain explicit bridge responsibilities.
