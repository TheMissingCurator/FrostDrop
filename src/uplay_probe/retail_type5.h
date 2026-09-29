/* Bounded type-5 field observer. All target access is through a read callback.
 * No game functions, constructors, payload buffers or registration writes. */
#ifndef ISAC_RETAIL_TYPE5_H
#define ISAC_RETAIL_TYPE5_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

enum { T5_READ, T5_PARSED, T5_DONE, T5_NAME, T5_COUNT, T5_KEY, T5_PAIR,
       T5_COPY, T5_WRITTEN, T5_GATE, T5_SITE_COUNT };
typedef struct { uint64_t rsp, rbp, rax, rbx, rcx, rdx, rsi, rdi, r13, r14; } T5Regs;
typedef int (*T5Read)(uintptr_t, void *, size_t);
typedef struct { int length; unsigned char bytes[512]; } T5Bytes;
typedef struct { unsigned index; T5Bytes key, value; } T5Pair;
typedef struct {
    int kind, complete, parsed, accepted, declared, wire_count, parsed_count;
    int before, after, written, copy_equal, gate_empty;
    uintptr_t owner; /* Internal only: writer assigns opaque session-local IDs. */
    T5Bytes name, record_name;
    unsigned pairs;
    T5Pair pair[24];
} T5Result;
typedef struct {
    int slot[4], active, incomplete, key_pending, key_length;
    unsigned key_index;
    uintptr_t stack, reader, owner, record, copy_stack;
    int copy_pending;
    T5Result result, gate_scratch; /* Preallocated: never put a 26 KB gate result on a game fiber's stack. */
} T5State;
typedef void (*T5Emit)(const T5Result *);

static uint64_t t5_uint(T5Read read, uintptr_t address, size_t size, int *ok) {
    uint64_t value = 0;
    *ok = address && size <= 8 && read(address, &value, size);
    return value;
}
static uintptr_t t5_ptr(T5Read read, uintptr_t address) {
    int ok;
    uint64_t value = t5_uint(read, address, 8, &ok);
    return ok ? (uintptr_t)value : 0;
}
static int t5_int(T5Read read, uintptr_t address) {
    int ok;
    uint64_t value = t5_uint(read, address, 4, &ok);
    return ok && value <= INT32_MAX ? (int)value : -1;
}
static uintptr_t t5_data(T5Read read, uintptr_t base, uintptr_t object, unsigned getter, unsigned offset) {
    uintptr_t table = t5_ptr(read, object);
    if (!table || t5_ptr(read, table + 0x10) != base + getter) return 0;
    return t5_ptr(read, object + offset);
}
static T5Bytes t5_exact(T5Read read, uintptr_t base, uintptr_t object,
                        unsigned getter, unsigned offset, int length, int bound) {
    T5Bytes result;
    uintptr_t data;
    memset(&result, 0, sizeof(result)); result.length = -1;
    if (length < 0 || length >= bound || bound > 512) return result;
    data = t5_data(read, base, object, getter, offset);
    if (data && (!length || read(data, result.bytes, (size_t)length))) result.length = length;
    return result;
}
static T5Bytes t5_string(T5Read read, uintptr_t base, uintptr_t object, unsigned getter, unsigned offset) {
    T5Bytes result;
    uintptr_t data = t5_data(read, base, object, getter, offset);
    unsigned i;
    memset(&result, 0, sizeof(result)); result.length = -1;
    if (!data) return result;
    for (i = 0; i < 64; ++i) {
        if (!read(data + i, result.bytes + i, 1)) return result;
        if (!result.bytes[i]) { result.length = (int)i; return result; }
    }
    return result;
}
static int t5_count(T5Read read, uintptr_t base, uintptr_t collection) {
    uintptr_t table = t5_ptr(read, collection);
    return table && t5_ptr(read, table + 0x70) == base + 0x5b9d0 ? t5_int(read, collection + 8) : -1;
}
static void t5_reset(T5State *s) {
    memset(s, 0, sizeof(*s));
    s->slot[0] = T5_READ; s->slot[1] = T5_NAME;
    s->slot[2] = T5_COPY; s->slot[3] = T5_GATE;
}
static int t5_frame(T5State *s, const T5Regs *r, intptr_t delta) {
    return s->active && r->rsp == s->stack + delta;
}
static int t5_attr(T5State *s, const T5Regs *r) {
    return t5_frame(s, r, -0x100) && r->rbp == s->stack - 0x97 &&
           r->rsi == s->reader && r->r14 == s->stack + 0x78;
}
static void t5_handle(T5State *s, int kind, const T5Regs *r, uintptr_t base, T5Read read, T5Emit emit) {
    T5Result *out = &s->result;
    int ok, count;
    if (kind == T5_GATE) {
        /* Gate observation is independent of parser success/coverage. Do not
         * infer selected-record identity from this final value alone. */
        T5Result *gate = &s->gate_scratch;
        memset(gate, 0, sizeof(*gate)); gate->kind = 1;
        gate->owner = r->r13; gate->gate_empty = !!(r->rax & 255);
        gate->name = t5_string(read, base, r->rsp + 0x50, 0x12920, 0x48);
        gate->before = t5_count(read, base, r->r13 + 0xb8);
        emit(gate); return;
    }
    if (kind == T5_READ) {
        if (r->rcx != r->rsp + 0x20 || r->rbp != r->rsp + 0x100 ||
            t5_uint(read, r->rdx + 0x10, 2, &ok) != 5 || !ok) return;
        memset(out, 0, sizeof(*out));
        out->declared = out->wire_count = out->parsed_count = -1;
        out->name.length = out->record_name.length = -1;
        out->copy_equal = -1;
        s->stack = r->rsp; s->reader = r->rdx; s->owner = out->owner = r->r14;
        out->before = t5_count(read, base, s->owner + 0xb8);
        s->active = 1; s->incomplete = s->key_pending = s->copy_pending = 0;
        s->slot[0] = T5_PARSED; s->slot[1] = T5_NAME; s->slot[2] = T5_COPY;
        return;
    }
    if (!s->active) return;
    switch (kind) {
    case T5_NAME:
        if (!t5_frame(s, r, -0x60) || r->rdi != s->reader ||
            r->rsi != s->stack + 0x20 || (uint32_t)r->rbx != 64) return;
        out->declared = t5_int(read, r->rsp + 0x48);
        s->slot[1] = T5_COUNT; break;
    case T5_COUNT:
        if (!t5_attr(s, r)) return;
        out->wire_count = t5_int(read, r->rbp + 0x77);
        if (out->wire_count < 0 || out->wire_count > 24) s->incomplete = 1;
        s->slot[1] = T5_KEY; break;
    case T5_KEY:
        if (!t5_attr(s, r)) return;
        count = t5_int(read, r->rbp + 0x77);
        if (count < 0 || count > 24 || (uint32_t)r->rdi >= (unsigned)count) { s->incomplete = 1; break; }
        if ((out->wire_count != -1 && out->wire_count != count) || (uint32_t)r->rdi != out->pairs)
            s->incomplete = 1;
        out->wire_count = count; s->key_index = (uint32_t)r->rdi;
        s->key_length = t5_int(read, r->rbp + 0x67); s->key_pending = 1;
        s->slot[1] = T5_PAIR; break;
    case T5_PAIR:
        if (!t5_attr(s, r) || !s->key_pending || (uint32_t)r->rdi != s->key_index) return;
        if (out->pairs < 24) {
            T5Pair *pair = &out->pair[out->pairs++];
            pair->index = s->key_index;
            pair->key = t5_exact(read, base, r->rbp - 0x49, 0x12860, 0x18, s->key_length, 64);
            pair->value = t5_exact(read, base, r->rbp - 0x21, 0x69160, 0x30,
                                   t5_int(read, r->rbp + 0x67), 512);
            if (pair->key.length < 0 || pair->value.length < 0) s->incomplete = 1;
        } else s->incomplete = 1;
        s->key_pending = 0; s->slot[1] = T5_KEY; break;
    case T5_PARSED:
        if (!t5_frame(s, r, 0) || r->r14 != s->owner) return;
        out->parsed = !!(r->rax & 255);
        if (out->parsed) {
            out->name = t5_exact(read, base, s->stack + 0x20, 0x12920, 0x48, out->declared, 64);
            out->parsed_count = t5_count(read, base, s->stack + 0x78);
        }
        s->slot[0] = T5_DONE; s->slot[1] = T5_NAME; break;
    case T5_COPY:
        if (!t5_frame(s, r, 0) || r->r14 != s->owner || r->rbp != s->stack + 0x100 || r->rcx < 0x358) return;
        s->record = r->rcx - 0x358;
        if (!s->record || t5_ptr(read, r->rbp + 0x300) != s->record ||
            r->rdx != t5_data(read, base, s->stack + 0x20, 0x12920, 0x48)) return;
        s->copy_stack = r->rsp; s->copy_pending = 1; s->slot[2] = T5_WRITTEN; break;
    case T5_WRITTEN:
        if (!s->copy_pending || r->rsp != s->copy_stack || r->r14 != s->owner ||
            r->rbp != s->stack + 0x100 || t5_ptr(read, r->rbp + 0x300) != s->record) return;
        out->record_name = t5_string(read, base, s->record + 0x358, 0x69160, 0x30);
        out->written = 1; s->copy_pending = 0; s->slot[2] = T5_COPY; break;
    case T5_DONE:
        if (!t5_frame(s, r, 0) || r->r14 != s->owner) return;
        out->accepted = !!(r->rbx & 255);
        out->after = t5_count(read, base, s->owner + 0xb8);
        out->complete = out->parsed && out->name.length >= 0 && !s->incomplete && !s->key_pending &&
                        out->wire_count >= 0 && (unsigned)out->wire_count == out->pairs;
        if (out->name.length >= 0 && out->record_name.length >= 0) {
            int length = 0;
            while (length < out->name.length && out->name.bytes[length]) ++length;
            out->copy_equal = length == out->record_name.length &&
                !memcmp(out->name.bytes, out->record_name.bytes, (size_t)length);
        }
        emit(out); t5_reset(s); break;
    default: break;
    }
}
#endif
