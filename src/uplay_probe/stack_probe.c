#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stack_probe.h"
#include "sdk_local_route.h"
#include "sdk_api_bindings.h"
#include "sdk_api_code.h"
#include "sdk_protect_path.h"
#include "sdk_native_context.h"

#define ISAC_HOOK_SIZE 12u
#define ISAC_TRAMPOLINE_JUMP_SIZE 13u
#define ISAC_MAX_HOOK_SIZE 16u
#define ISAC_MAX_FRAMES 16u
#define ISAC_CAPTURE_FRAMES 32u
#define ISAC_MAX_STACKS 256u
#define ISAC_MAX_DISPATCH_TARGETS 256u
#define ISAC_MAX_DISPATCH_CALLERS 256u
#define ISAC_MAX_INBOUND_BATCH_CALLERS 64u
#define ISAC_MAX_QUEUE_WRITE_SIGNATURES 128u
#define ISAC_MAX_QUEUE_CODE_ANCHORS 128u
#define ISAC_MAX_QUEUE_STACK_CANDIDATES 16u
#define ISAC_MAX_QUEUE_PRODUCER_EVENTS 16u
#define ISAC_QUEUE_STACK_SCAN_SLOTS 128u
#define ISAC_QUEUE_CODE_BYTES 512u
#define ISAC_QUEUE_CODE_BEFORE 128u
#define ISAC_MAX_QUEUE_PRODUCER_CODE_BYTES 2048u
#define ISAC_MAX_INBOUND_READER_CODE_BYTES 2048u
#define ISAC_INBOUND_READER_FORWARD_BYTES 1024u
#define ISAC_MAX_DISPATCH_THREADS 256u
#define ISAC_MAX_DISPATCH_EVENTS 32768u
#define ISAC_DISPATCH_MESSAGE_CODE_BYTES 32u
#define ISAC_DISPATCH_INBOUND_CODE_BYTES 256u
#define ISAC_DISPATCH_CALLER_CODE_BYTES 768u
#define ISAC_DISPATCH_CALLER_CODE_BEFORE 384u
#define ISAC_MAX_PLAINTEXT_RECORDS 512u
#define ISAC_MAX_PLAINTEXT_BYTES 1000u
#define ISAC_MAX_BOOTSTRAP_RECORDS 2048u
#define ISAC_MAX_CONTINUATION_BOOTSTRAP_RECORDS 32768u
#define ISAC_MAX_BOOTSTRAP_SOCKET_EVENTS 4096u
#define ISAC_MAX_BOOTSTRAP_STREAMS 64u
#define ISAC_MAX_BOOTSTRAP_FRAME_SUMMARY 32u
#define ISAC_MAX_BOOTSTRAP_INSPECT_BYTES 16384u
#define ISAC_MAX_CONTROL_PATH_EVENTS 32u
#define ISAC_MAX_CONTROL_CODE_FUNCTIONS 32u
#define ISAC_MAX_CONTROL_CODE_BYTES 4096u
#define ISAC_MAX_CONTROL_STACK_FRAMES 16u
#define ISAC_MAX_OUTBOUND_CONTROL_PATH_EVENTS 32u
#define ISAC_MAX_OUTBOUND_CONTROL_CODE_FUNCTIONS 32u
#define ISAC_MAX_OUTBOUND_CONTROL_CODE_BYTES 4096u
#define ISAC_MAX_CONTROL_CORRELATION_EVENTS 64u
#define ISAC_MAX_INBOUND_SOURCE_EVENTS 64u
#define ISAC_MAX_INBOUND_VTABLE_SLOTS 16u
#define ISAC_MAX_INBOUND_VTABLE_XREFS 32u
#define ISAC_MAX_INBOUND_VTABLES 8u
#define ISAC_SOURCE_OBJECT_CONSTRUCTOR_RVA 0x2237e90u
#define ISAC_READER_CONSTRUCTOR_A_RVA 0x002f790u
#define ISAC_READER_CONSTRUCTOR_B_RVA 0x002f900u
#define ISAC_READER_SETUP_A_RVA 0x005fb10u
#define ISAC_READER_SETUP_B_RVA 0x005fed0u
#define ISAC_READER_REGISTER_RVA 0x00af360u
#define ISAC_REGISTRATION_CONSTRUCTOR_RVA 0x0034450u
#define ISAC_REGISTRATION_RETURN_RVA 0x00af439u
#define ISAC_REGISTRATION_OBJECT_BYTES 0x98u
#define ISAC_INBOUND_TRANSPORT_DELIVERY_RVA 0x0084bd0u
#define ISAC_INBOUND_TRANSPORT_DELIVERY_RETURN_RVA 0x00982a0u
#define ISAC_INBOUND_SOURCE_APPEND_RVA 0x223d140u
#define ISAC_INBOUND_READER_LOCK_RVA 0x0000b7e0u
#define ISAC_INBOUND_READER_NOTIFY_RVA 0x0001e0a0u
#define ISAC_INBOUND_READER_UNLOCK_RVA 0x0000c6c0u
#define ISAC_MAX_INBOUND_DELIVERY_EVENTS 128u
#define ISAC_MAX_INBOUND_DELIVERY_CHUNKS 32u
#define ISAC_LOCAL_BRIDGE_QUEUE_SLOTS 32u
#define ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES 65536u
#define ISAC_LOCAL_BRIDGE_DEFAULT_PORT 55000u
#define ISAC_LOCAL_BRIDGE_MAX_READERS 128u
#define ISAC_LOCAL_BRIDGE_READER_SCAN_BYTES 0x600u
#define ISAC_LOCAL_BRIDGE_TRANSPORT_SCAN_BYTES 0x400u
#define ISAC_LOCAL_BRIDGE_PREFIX_BYTES 16u
#define ISAC_LOCAL_BRIDGE_MAX_SHARED_FIELDS 8u
#define ISAC_LOCAL_BRIDGE_LOGIN_READER_ID 1l
#define ISAC_LOCAL_BRIDGE_LOGIN_READER_MAX_ID 2l
#define ISAC_LOCAL_BRIDGE_READER_WAIT_MS 5000u
#define ISAC_TYPE3_PROFILE_CAPTURE_MAX_BYTES 4096u
#define ISAC_WORLD_REQUEST_MIN_FRAME_BYTES 512u
#define ISAC_WORLD_REQUEST_MAX_FRAME_BYTES 2048u
#define ISAC_WORLD_STREAM_SYNC_BYTES 4096u
#define ISAC_WORLD_STREAM_MAX_FRAME_BYTES 16777216u
#define ISAC_WORLD_STREAM_MAX_EVENTS 4096l
#define ISAC_WORLD_SNAPSHOT_MAX_BYTES 2097152u
#define ISAC_WORLD_SNAPSHOT_MAX_RECORDS 8192l
#define ISAC_WORLD_CONTINUATION_MAX_BYTES 16777216u
#define ISAC_WORLD_CONTINUATION_MAX_RECORDS 65536l
#define ISAC_WORLD_SNAPSHOT_FLAG_SYNC 0x00000001u
#define ISAC_WORLD_SNAPSHOT_FLAG_DELIVERY_START 0x00000002u
#define ISAC_WORLD_SNAPSHOT_FLAG_DELIVERY_END 0x00000004u
#define ISAC_WORLD_SNAPSHOT_FLAG_GATE_COMPLETE 0x00000008u
#define ISAC_WORLD_REPLAY_HEADER_BYTES 16u
#define ISAC_WORLD_REPLAY_READER_WAIT_MS 5000u
#define ISAC_INBOUND_SOURCE_VTABLE_RVA 0x034863d8u
#define ISAC_TYPE3_REARM_PASSES 12u
#define ISAC_INBOUND_HANDOFF_RVA 0x009a845u
#define ISAC_INBOUND_ADVANCE_RVA 0x009a851u
#define ISAC_VIRTUAL_READ_HELPER_RVA 0x009a7c0u
#define ISAC_CONTROL_TYPE_0003_DISPATCHER_RVA 0x0099490u
#define ISAC_CONTROL_TYPE_0003_DECODER_RVA 0x00b8160u
#define ISAC_CONTROL_TYPE_0003_SCHEMA_RVA 0x22551b0u
#define ISAC_CONTROL_TYPE_0003_COLLECTION_READERS_RVA 0x00215a0u
#define ISAC_CONTROL_TYPE_0002_DECODER_RVA 0x00aeed0u
#define ISAC_CONTROL_TYPE_0002_SCHEMA_RVA 0x2257cc0u
#define ISAC_CONTROL_FIXED_READERS_RVA 0x00216d0u
#define ISAC_CONTROL_TYPE_0002_AUX_LOW_RVA 0x00632f0u
#define ISAC_CONTROL_TYPE_0002_SUBOBJECT_RVA 0x0064760u
#define ISAC_CONTROL_TYPE_0002_AUX_HIGH_RVA 0x0064800u
#define ISAC_CONTROL_TYPE_0002_NESTED_RVA 0x00651d0u
#define ISAC_CONTROL_TYPE_0006_DECODER_RVA 0x009ad00u
#define ISAC_CONTROL_TYPE_0006_SCHEMA_RVA 0x2257c10u
#define ISAC_CONTROL_DIRECT_FORWARD_BYTES 4096u
#define ISAC_MAX_SCHEMA_TARGETS 256u
#define ISAC_MAX_SCHEMA_EVENTS 4096u
#define ISAC_MAX_SCHEMA_CODE_BYTES 4096u
#define ISAC_MAX_SCHEMA_FIELD_THREADS 256u
#define ISAC_MAX_SCHEMA_FIELD_HELPERS 18u
#define ISAC_MAX_SCHEMA_FIELD_RECORDS 32768u
#define ISAC_MAX_SCHEMA_FIELD_SAMPLES_PER_TYPE 128u
#define ISAC_MAX_SCHEMA_FIELD_FILTERED_SAMPLES 2048u
#define ISAC_MAX_SCHEMA_FIELD_MINER_SAMPLES_PER_TYPE 512u
#define ISAC_SCHEMA_FIELD_BYTES 32u
#define ISAC_MAX_SCHEMA_MESSAGE_RECORDS 8192u
#define ISAC_MAX_SCHEMA_MESSAGE_BYTES 2048u
#define ISAC_SCHEMA_BOUNDARY_RVA 0x0f8447eu
#define ISAC_MAX_SCHEMA_HELPER_CODE_BYTES 2048u
#define ISAC_MAX_SCHEMA_NESTED_CODE_BYTES 8192u
#define ISAC_SCHEMA_NESTED_FORWARD_BYTES 2048u
#define ISAC_MAX_SCHEMA_NESTED_CALLEE_BYTES 2048u
#define ISAC_MAX_SCHEMA_NESTED_CALLEES 24u
#define ISAC_MAX_INBOUND_HANDOFF_EVENTS 64u
#define ISAC_INBOUND_OBJECT_BYTES 96u
#define ISAC_MAX_INBOUND_NESTED_OBJECTS 6u
#define ISAC_MAX_INBOUND_CANDIDATES_PER_EVENT 12u
#define ISAC_SERIALIZED_BUFFER_POINTER_OFFSET 0x4090u
#define ISAC_SERIALIZED_BUFFER_LENGTH_OFFSET 0x4098u
#define ISAC_MAX_TARGET_SOCKETS 32u
#define ISAC_MAX_TRANSPORT_STARTUP_EVENTS 256l
#define ISAC_TRANSPORT_STACK_FRAMES 6u
#define ISAC_MAX_TCTD_CERT_READ_EVENTS 64l
#define ISAC_TCTD_CERT_CALLER_FRAMES 8u
#define ISAC_MAX_TCTD_VALIDATION_EVENTS 128l
#define ISAC_TCTD_VALIDATION_CALLER_FRAMES 8u
#define ISAC_TCTD_KEY_READ_RVA 0x000f0f84u
#define ISAC_TCTD_KEY_RETURN_RVA 0x000f1324u
#define ISAC_TCTD_TLS_RETURN_A_RVA 0x000bb537u
#define ISAC_TCTD_TLS_RETURN_B_RVA 0x000bbba7u
#define ISAC_TCTD_VALIDATION_CALLER_RVA 0x013877e0u
#define ISAC_TCTD_VALIDATION_RESULT_RVA 0x004c81fdu
#define ISAC_TCTD_LOCAL_ACCEPT_RVA 0x0206573bu
#define ISAC_TCTD_COMPLETION_DECISION_RVA 0x000bb4cdu
#define ISAC_TCTD_VALIDATOR_SUCCESS_RVA 0x000f12b1u
#define ISAC_TCTD_VALIDATOR_SUCCESS_RESUME_RVA 0x000f12b4u
#define ISAC_TCTD_COMPLETION_ENTRY_RVA 0x000f0e60u
#define ISAC_TCTD_COMPLETION_RETURN_RVA 0x000f1324u
#define ISAC_TCTD_COMPLETION_REGION_END_RVA 0x000f1337u
#define ISAC_MAX_TCTD_COMPLETION_EVENTS 64l
#define ISAC_TCTD_BRANCH_READY_RVA 0x000f11afu
#define ISAC_TCTD_BRANCH_STATUS_READY_RVA 0x000f11d0u
#define ISAC_TCTD_BRANCH_STATUS_RVA 0x000f11d8u
#define ISAC_TCTD_BRANCH_FINAL_RVA 0x000f1251u
#define ISAC_MAX_TCTD_BRANCH_EVENTS 256l
#define ISAC_TCTD_CHAIN_KEY_COPY_RVA 0x021fea19u
#define ISAC_TCTD_CHAIN_RETURN_1_RVA 0x02016925u
#define ISAC_TCTD_CHAIN_RETURN_2_RVA 0x020167dbu
#define ISAC_TCTD_CHAIN_RETURN_3_RVA 0x0223b8d5u
#define ISAC_TCTD_CHAIN_RETURN_4_RVA 0x02248085u
#define ISAC_TCTD_CHAIN_RETURN_5_RVA 0x0224ca7cu
#define ISAC_TCTD_CHAIN_RETURN_6_RVA 0x000f131cu
#define ISAC_MAX_TCTD_CHAIN_EVENTS 32l
#define ISAC_TCTD_PARSER_CALL_RVA 0x020167d8u
#define ISAC_MAX_TCTD_PARSER_WINDOWS 12u
#define ISAC_MAX_TCTD_CERT_FLOW_EVENTS 256l
#define ISAC_MAX_TCTD_CERT_FLOW_CONSUMERS 12l
#define ISAC_MAX_TCTD_VALIDATOR_WINDOWS 8u
#define ISAC_MAX_TCTD_STATE_WRITE_EVENTS 64l
#define ISAC_TCTD_STATE_CALLER_FRAMES 8u
#define ISAC_MAX_TCTD_OWNER_DECISIONS 1024l
#define ISAC_MAX_TCTD_OWNER_WRITES 128l
#define ISAC_TCTD_OWNER_CALLER_FRAMES 8u
#define ISAC_MAX_SUSPENDED_THREADS 512u
#define ISAC_MAX_CODE_WINDOW 512u
#define ISAC_CODE_CAPTURE_MAX_BYTES 6144u
#define ISAC_EXPECTED_GAME_FILE_SIZE 24935424LL
#define ISAC_EXPECTED_GAME_IMAGE_SIZE 0x07311000u
#define ISAC_EXPECTED_GAME_TIMESTAMP 0x693b11ffu
#define ISAC_TCTD_TEXT_RVA 0x00001000u
#define ISAC_TCTD_TEXT_SIZE 0x02900000u

typedef int (WSAAPI *isac_getpeername_fn)(SOCKET, struct sockaddr *, int *);
typedef int (WSAAPI *isac_connect_fn)(
    SOCKET,
    const struct sockaddr *,
    int
);
typedef INT (WSAAPI *isac_getaddrinfo_a_fn)(
    PCSTR,
    PCSTR,
    const ADDRINFOA *,
    PADDRINFOA *
);
typedef INT (WSAAPI *isac_getaddrinfo_w_fn)(
    PCWSTR,
    PCWSTR,
    const ADDRINFOW *,
    PADDRINFOW *
);
typedef int (WINAPI *isac_recv_base_fn)(
    SOCKET,
    LPWSABUF,
    DWORD,
    LPDWORD,
    LPDWORD,
    struct sockaddr *,
    LPINT,
    LPWSAOVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE,
    LPWSABUF
);
typedef int (WINAPI *isac_send_base_fn)(
    SOCKET,
    LPWSABUF,
    DWORD,
    LPDWORD,
    DWORD,
    const struct sockaddr *,
    INT,
    LPWSAOVERLAPPED,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE
);
typedef void *(*isac_reader_lock_fn)(void *, void *);
typedef DWORD (*isac_source_append_fn)(void *, const BYTE *, DWORD);
typedef void (*isac_reader_notify_fn)(void *);
typedef void (*isac_reader_unlock_fn)(void *);
typedef struct isac_inline_hook {
    BYTE *target;
    BYTE *trampoline;
    BYTE original[ISAC_MAX_HOOK_SIZE];
    SIZE_T size;
    BOOL installed;
} isac_inline_hook;

typedef struct isac_patch_diagnostic {
    DWORD original_protection;
    DWORD memory_type;
    DWORD attempted_protection;
    DWORD error;
} isac_patch_diagnostic;

typedef struct isac_stack_signature {
    char direction;
    USHORT depth;
    uintptr_t rvas[ISAC_MAX_FRAMES];
} isac_stack_signature;

typedef struct isac_dispatch_target {
    char kind;
    uintptr_t rva;
} isac_dispatch_target;

typedef struct isac_dispatch_caller {
    USHORT type_id;
    uintptr_t return_rva;
} isac_dispatch_caller;

typedef struct isac_schema_target {
    USHORT type_id;
    uintptr_t deserializer_rva;
} isac_schema_target;

typedef struct isac_bootstrap_stream {
    const void *object;
    char direction;
} isac_bootstrap_stream;

typedef struct isac_local_bridge_record {
    DWORD length;
    BYTE bytes[ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES];
} isac_local_bridge_record;

typedef struct isac_local_bridge_reader {
    const BYTE *reader;
    const BYTE *source;
    LONG id;
    BOOL relationship_logged;
} isac_local_bridge_reader;

typedef struct isac_world_stream_parser {
    uint64_t length_value;
    uint64_t type_value;
    DWORD frame_length;
    DWORD frame_consumed;
    unsigned int length_shift;
    unsigned int length_bytes;
    unsigned int type_shift;
    unsigned int type_bytes;
    BOOL have_length;
    BOOL have_type;
    BOOL started;
} isac_world_stream_parser;

typedef struct isac_schema_field_slot {
    uintptr_t helper_rva;
    uintptr_t return_address;
    const BYTE *destination;
    DWORD absolute_cursor;
    DWORD local_cursor;
    DWORD buffer_length;
    DWORD wire_length;
    DWORD before_length;
    BYTE wire[ISAC_SCHEMA_FIELD_BYTES];
    BYTE before[ISAC_SCHEMA_FIELD_BYTES];
    uint64_t argument_r8;
    uint64_t argument_r9;
    BOOL pending;
} isac_schema_field_slot;

typedef struct isac_schema_field_thread {
    volatile LONG thread_id;
    LONG message_sequence;
    USHORT type_id;
    const BYTE *message;
    const BYTE *decode_context;
    uintptr_t deserializer_rva;
    uintptr_t helpers[3];
    isac_schema_field_slot slots[3];
    uintptr_t message_return_address;
    const BYTE *message_start_buffer;
    DWORD message_start_absolute;
    DWORD message_start_local;
    DWORD message_start_available;
    DWORD message_prefix_length;
    BYTE message_prefix[ISAC_MAX_SCHEMA_MESSAGE_BYTES];
    BOOL message_pending;
} isac_schema_field_thread;

typedef struct isac_queue_write_signature {
    uintptr_t instruction_rva;
    USHORT depth;
    uintptr_t rvas[ISAC_MAX_QUEUE_STACK_CANDIDATES];
} isac_queue_write_signature;

static const BYTE g_internal_signature[ISAC_HOOK_SIZE] = {
    0x55,
    0x41, 0x57,
    0x41, 0x56,
    0x41, 0x55,
    0x41, 0x54,
    0x57,
    0x56,
    0x53
};
static const BYTE g_internal_signature_wine11[ISAC_HOOK_SIZE] = {
    0x41, 0x57,
    0x41, 0x56,
    0x41, 0x55,
    0x41, 0x54,
    0x55,
    0x57,
    0x56,
    0x53
};
static const BYTE g_inbound_queue_producer_signature[16] = {
    0x8b, 0x53, 0x10,
    0x3b, 0x53, 0x08,
    0x75, 0x13,
    0x8d, 0x42, 0x01,
    0x48, 0x8b, 0xcb,
    0x89, 0x43
};
static const BYTE g_world_dispatch_signature[14] = {
    0x48, 0x85, 0xd2,
    0x0f, 0x84, 0xc2, 0x00, 0x00, 0x00,
    0x48, 0x89, 0x5c, 0x24, 0x08,
};
static const BYTE g_inbound_batch_signature[16] = {
    0x48, 0x8b, 0xc4,
    0x53,
    0x48, 0x83, 0xec, 0x60,
    0x48, 0x83, 0x79, 0x18, 0x00,
    0x48, 0x8b, 0xd9
};
static const BYTE g_outbound_plaintext_signature[17] = {
    0xff, 0x50, 0x08,
    0x48, 0x8d, 0x4c, 0x24, 0x20,
    0xe8, 0x04, 0x15, 0x16, 0x02,
    0x48, 0x8d, 0x8c, 0x24
};
static const BYTE g_inbound_plaintext_signature[16] = {
    0x44, 0x8b, 0x46, 0x10,
    0x48, 0x8b, 0x56, 0x08,
    0x45, 0x33, 0xc9,
    0x48, 0x8b, 0xc8,
    0xe8, 0xb3
};
static const BYTE g_inbound_virtual_reader_signature[16] = {
    0x48, 0x8b, 0x4b, 0x48,
    0x48, 0x8b, 0x01,
    0xff, 0x50, 0x18,
    0x84, 0xc0,
    0x0f, 0x84, 0x3a, 0x02
};
static const BYTE g_inbound_handoff_signature[16] = {
    0x48, 0x8b, 0xce,
    0xe8, 0x83, 0x13, 0x1a, 0x02,
    0x84, 0xc0,
    0x75, 0x1d,
    0x48, 0x8b, 0x07,
    0x48
};
static const BYTE g_reader_register_signature[16] = {
    0x4c, 0x89, 0x44, 0x24, 0x18,
    0x55,
    0x57,
    0x41, 0x56,
    0x48, 0x83, 0xec, 0x40,
    0x80, 0xb9, 0x3a
};
static const BYTE g_schema_deserialize_signature[16] = {
    0x48, 0x8b, 0x07,
    0x48, 0x8d, 0x54, 0x24, 0x20,
    0x48, 0x8b, 0xcf,
    0xff, 0x50, 0x38,
    0x84, 0xc0
};
static const BYTE g_reader_setup_a_signature[16] = {
    0x4c, 0x89, 0x4c, 0x24, 0x20,
    0x4c, 0x89, 0x44, 0x24, 0x18,
    0x55,
    0x53,
    0x56,
    0x57,
    0x41, 0x54
};
static const BYTE g_reader_setup_b_signature[16] = {
    0x48, 0x89, 0x5c, 0x24, 0x10,
    0x48, 0x89, 0x6c, 0x24, 0x18,
    0x48, 0x89, 0x74, 0x24, 0x20,
    0x57
};
static const BYTE g_tctd_local_accept_signature[13] = {
    0x44, 0x39, 0xad, 0x40, 0x01, 0x00, 0x00,
    0x74, 0x73,
    0x85, 0xc0,
    0x7f, 0x6f
};
static const BYTE g_wine_connect_signature[14] = {
    0x55,
    0x41, 0x56,
    0x41, 0x55,
    0x41, 0x54,
    0x57,
    0x56,
    0x53,
    0x48, 0x83, 0xec, 0x60
};
static const BYTE g_wine_getaddrinfo_signature[ISAC_HOOK_SIZE] = {
    0x55,
    0x41, 0x57,
    0x41, 0x56,
    0x41, 0x55,
    0x41, 0x54,
    0x57,
    0x56,
    0x53
};
static const BYTE g_wine11_connect_signature[ISAC_HOOK_SIZE] = {
    0x41, 0x55,
    0x41, 0x54,
    0x55,
    0x57,
    0x56,
    0x53,
    0x48, 0x83, 0xec, 0x68
};
static const BYTE g_wine11_getaddrinfo_a_signature[14] = {
    0x41, 0x56,
    0x41, 0x55,
    0x41, 0x54,
    0x55,
    0x57,
    0x56,
    0x53,
    0x48, 0x83, 0xc4, 0x80
};
static const uintptr_t
    g_schema_field_helpers[ISAC_MAX_SCHEMA_FIELD_HELPERS] = {
        0x0f7f5f0u,
        0x0f841e0u,
        0x223d530u,
        0x223d5d0u,
        0x223d5f0u,
        0x223d640u,
        0x223d690u,
        0x223d6a0u,
        0x223d6b0u,
        0x223d6c0u,
        0x223d6d0u,
        0x223d860u,
        0x223da10u,
        0x223dac0u,
        0x223dad0u,
        0x223daf0u,
        0x223dc30u,
        0x223dcc0u
    };

static WCHAR g_stack_log_path[MAX_PATH];
static WCHAR g_code_log_path[MAX_PATH];
static WCHAR g_dispatch_log_path[MAX_PATH];
static WCHAR g_plaintext_log_path[MAX_PATH];
static BYTE *g_game_base;
static SIZE_T g_game_size;
static BOOL g_code_probe_enabled;
static BOOL g_dispatch_probe_enabled;
static BOOL g_dispatch_event_requested;
static BOOL g_dispatch_event_enabled;
static BOOL g_plaintext_probe_requested;
static BOOL g_plaintext_probe_enabled;
static BOOL g_bootstrap_probe_requested;
static BOOL g_bootstrap_probe_enabled;
static BOOL g_bootstrap_redacted_only;
static BOOL g_control_probe_requested;
static BOOL g_control_probe_enabled;
static BOOL g_bootstrap_type3_probe_requested;
static BOOL g_bootstrap_type3_probe_enabled;
static BOOL g_outbound_control_probe_requested;
static BOOL g_outbound_control_probe_enabled;
static BOOL g_inbound_source_probe_requested;
static BOOL g_inbound_source_probe_enabled;
static BOOL g_schema_field_probe_requested;
static BOOL g_schema_field_probe_enabled;
static BOOL g_schema_miner_requested;
static BOOL g_schema_miner_enabled;
static BOOL g_local_bridge_requested;
static BOOL g_local_bridge_enabled;
static BOOL g_local_bridge_injection_requested;
static BOOL g_local_bridge_injection_enabled;
static BOOL g_local_bridge_type3_isolation_requested;
static BOOL g_local_bridge_type3_isolation_enabled;
static BOOL g_type3_profile_capture_requested;
static BOOL g_type3_profile_capture_enabled;
static BOOL g_world_bootstrap_probe_requested;
static BOOL g_world_bootstrap_probe_enabled;
static BOOL g_world_snapshot_capture_requested;
static BOOL g_world_snapshot_capture_enabled;
static BOOL g_world_continuation_capture_requested;
static BOOL g_world_continuation_capture_enabled;
static BOOL g_world_replay_requested;
static BOOL g_world_replay_enabled;
static BOOL g_transport_startup_probe_requested;
static BOOL g_transport_startup_probe_enabled;
static BOOL g_tctd_pc_loopback_requested;
static BOOL g_tctd_echo_requested;
static BOOL g_tctd_echo_enabled;
static BOOL g_startup_leads_requested;
static BOOL g_login_handoff_requested;
static BOOL g_login_handoff_sweep_requested;
static BOOL g_tctd_certificate_probe_requested;
static BOOL g_tctd_certificate_probe_enabled;
static BOOL g_tctd_validation_probe_requested;
static BOOL g_tctd_validation_probe_enabled;
static BOOL g_tctd_validation_remote_requested;
static BOOL g_tctd_local_accept_requested;
static BOOL g_tctd_local_accept_enabled;
static BOOL g_tctd_allocation_requested;
static BOOL g_tctd_allocation_enabled;
static BOOL g_tctd_validator_code_requested;
static BOOL g_tctd_validator_code_enabled;
static BOOL g_tctd_state_watch_requested;
static BOOL g_tctd_state_watch_enabled;
static BOOL g_tctd_owner_watch_requested;
static BOOL g_tctd_owner_watch_enabled;
static BOOL g_tctd_owner_remote_requested;
static BOOL g_tctd_completion_probe_requested;
static BOOL g_tctd_completion_probe_enabled;
static BOOL g_tctd_completion_remote_requested;
static BOOL g_tctd_branch_probe_requested;
static BOOL g_tctd_branch_probe_enabled;
static BOOL g_tctd_branch_remote_requested;
static BOOL g_tctd_chain_probe_requested;
static BOOL g_tctd_chain_probe_enabled;
static BOOL g_tctd_chain_remote_requested;
static BOOL g_tctd_parser_code_requested;
static BOOL g_tctd_parser_code_enabled;
static BOOL g_tctd_cert_flow_requested;
static BOOL g_tctd_cert_flow_enabled;
static BOOL g_tctd_cert_flow_remote_requested;
static BOOL g_tctd_text_dump_requested;
static USHORT g_local_bridge_port = ISAC_LOCAL_BRIDGE_DEFAULT_PORT;
static isac_getpeername_fn g_getpeername;
static isac_recv_base_fn g_original_recv_base;
static isac_send_base_fn g_original_send_base;
static isac_connect_fn g_original_connect;
static isac_getaddrinfo_a_fn g_original_getaddrinfo_a;
static isac_getaddrinfo_w_fn g_original_getaddrinfo_w;
static isac_inline_hook g_recv_hook;
static isac_inline_hook g_send_hook;
static isac_inline_hook g_connect_hook;
static isac_inline_hook g_getaddrinfo_a_hook;
static isac_inline_hook g_getaddrinfo_w_hook;
static isac_stack_signature g_stacks[ISAC_MAX_STACKS];
static volatile LONG g_stack_count;
static volatile LONG g_stack_lock;
static volatile LONG g_limit_logged;
static PVOID volatile g_target_sockets[ISAC_MAX_TARGET_SOCKETS];
static volatile LONG g_core_code_captured;
static volatile LONG g_world_code_captured;
static volatile LONG g_dispatch_install_state;
static volatile LONG g_dispatch_target_lock;
static volatile LONG g_dispatch_target_count;
static volatile LONG g_dispatch_limit_logged;
static volatile LONG g_dispatch_caller_lock;
static volatile LONG g_dispatch_caller_count;
static volatile LONG g_dispatch_caller_limit_logged;
static volatile LONG g_inbound_batch_caller_lock;
static volatile LONG g_inbound_batch_caller_count;
static volatile LONG g_inbound_batch_caller_limit_logged;
static PVOID volatile g_inbound_queue_watch_address;
static volatile LONG g_inbound_queue_watch_error_logged;
static volatile LONG g_queue_write_lock;
static volatile LONG g_queue_write_count;
static volatile LONG g_queue_write_limit_logged;
static volatile LONG g_queue_code_lock;
static volatile LONG g_queue_code_count;
static volatile LONG g_queue_code_limit_logged;
static volatile LONG g_queue_producer_count;
static volatile LONG g_queue_producer_limit_logged;
static volatile LONG g_queue_producer_code_captured;
static volatile LONG g_inbound_reader_code_captured;
static volatile LONG g_inbound_virtual_reader_captured;
static volatile LONG g_inbound_handoff_code_captured;
static volatile LONG g_inbound_handoff_count;
static volatile LONG g_inbound_handoff_limit_logged;
static volatile LONG g_inbound_frame_lock;
static volatile LONG g_inbound_frame_error_logged;
static const BYTE *g_inbound_pending_reader;
static DWORD g_inbound_pending_expected;
static DWORD g_inbound_pending_length;
static BYTE g_inbound_pending[ISAC_MAX_PLAINTEXT_BYTES];
static volatile LONG g_schema_target_lock;
static volatile LONG g_schema_target_count;
static volatile LONG g_schema_target_limit_logged;
static volatile LONG g_schema_event_count;
static volatile LONG g_schema_event_limit_logged;
static volatile LONG g_schema_field_count;
static volatile LONG g_schema_field_limit_logged;
static volatile LONG g_schema_message_count;
static volatile LONG g_schema_message_limit_logged;
static volatile LONG g_schema_helper_code_captured;
static volatile LONG g_schema_nested_code_captured;
static LONG g_schema_field_type_filter = -1;
static volatile LONG g_dispatch_thread_lock;
static volatile LONG g_dispatch_thread_count;
static volatile LONG g_dispatch_arm_error_logged;
static volatile LONG g_dispatch_event_count;
static volatile LONG g_dispatch_event_limit_logged;
static volatile LONG g_dispatch_event_write_error_logged;
static volatile LONG g_plaintext_world_active;
static volatile LONG g_plaintext_count;
static volatile LONG g_plaintext_in_count;
static volatile LONG g_plaintext_limit_logged;
static volatile LONG g_plaintext_in_limit_logged;
static volatile LONG g_plaintext_in_oversize_logged;
static volatile LONG g_plaintext_error_logged;
static volatile LONG g_bootstrap_record_count;
static volatile LONG g_bootstrap_record_limit_logged;
static volatile LONG g_bootstrap_socket_event_count;
static volatile LONG g_bootstrap_socket_limit_logged;
static volatile LONG g_bootstrap_stream_lock;
static volatile LONG g_bootstrap_stream_count;
static volatile LONG g_control_path_count;
static volatile LONG g_control_path_limit_logged;
static volatile LONG g_control_code_lock;
static volatile LONG g_control_code_count;
static volatile LONG g_control_code_limit_logged;
static volatile LONG g_outbound_control_path_count;
static volatile LONG g_outbound_control_path_limit_logged;
static volatile LONG g_outbound_control_code_lock;
static volatile LONG g_outbound_control_code_count;
static volatile LONG g_outbound_control_code_limit_logged;
static volatile LONG g_control_correlation_count;
static volatile LONG g_control_correlation_limit_logged;
static volatile LONG g_inbound_source_vtable_lock;
static volatile LONG g_inbound_source_vtable_count;
static volatile LONG g_inbound_source_vtable_limit_logged;
static volatile LONG g_inbound_source_setup_code_captured;
static volatile LONG g_inbound_registration_object_captured;
static volatile LONG g_inbound_transport_delivery_count;
static volatile LONG g_inbound_transport_delivery_limit_logged;
static volatile LONG g_inbound_source_append_count;
static volatile LONG g_inbound_source_append_limit_logged;
static volatile LONG g_inbound_source_advance_ready_logged;
static volatile LONG g_inbound_source_advance_captured;
static volatile LONG g_inbound_source_watch_ready_logged;
static volatile LONG g_inbound_source_event_count;
static volatile LONG g_inbound_source_event_limit_logged;
static volatile LONG g_local_bridge_queue_lock;
static volatile LONG g_local_bridge_queue_read;
static volatile LONG g_local_bridge_queue_write;
static volatile LONG g_local_bridge_drop_logged;
static volatile LONG g_local_bridge_reader_candidate_count;
static volatile LONG g_local_bridge_reader_lock;
static volatile LONG g_local_bridge_reader_count;
static volatile LONG g_local_bridge_reader_limit_logged;
static volatile LONG g_local_bridge_rx_count;
static volatile LONG g_local_bridge_waiting_logged;
static volatile LONG g_local_bridge_injection_lock;
static volatile LONG g_local_bridge_injection_count;
static volatile LONG g_local_bridge_injection_succeeded;
static volatile LONG g_local_bridge_injection_skip_logged;
static volatile LONG g_local_bridge_injection_wait_logged;
static volatile LONG g_local_bridge_type3_suppression_count;
static volatile LONG g_local_bridge_type3_suppression_error_logged;
static volatile LONG g_type3_profile_capture_count;
static volatile LONG g_world_request_capture_count;
static volatile LONG g_world_request_seen;
static volatile LONG g_world_request_reader_floor;
static volatile LONG g_world_bootstrap_reader_id;
static volatile LONG g_world_stream_lock;
static volatile LONG g_world_stream_event_count;
static volatile LONG g_world_stream_limit_logged;
static volatile LONG g_world_stream_error_logged;
static volatile LONG g_world_stream_gate_complete;
static volatile LONG g_world_snapshot_lock;
static volatile LONG g_world_snapshot_started;
static volatile LONG g_world_snapshot_finished;
static volatile LONG g_world_snapshot_gate_recorded;
static volatile LONG g_world_snapshot_record_count;
static volatile LONG g_world_snapshot_error_logged;
static volatile LONG g_world_snapshot_payload_bytes;
static volatile LONG g_world_replay_reader_lock;
static volatile LONG g_world_replay_armed;
static volatile LONG g_world_replay_started;
static volatile LONG g_world_replay_setup_seen;
static volatile LONG g_world_replay_frame_count;
static volatile LONG g_world_replay_complete;
static volatile LONG g_world_replay_suppression_count;
static volatile LONG g_world_replay_outbound_suppression_count;
static volatile LONG g_world_replay_outbound_suppression_error_logged;
static volatile LONG g_world_replay_wire_send_count;
static volatile LONG g_world_replay_injection_error_logged;
static volatile LONG g_world_replay_suppression_error_logged;
static volatile LONG g_world_replay_before_arm_logged;
static volatile LONG g_transport_startup_event_count;
static volatile LONG g_transport_startup_limit_logged;
static volatile LONG g_transport_connect_count;
static volatile LONG g_transport_resolve_count;
static volatile LONG g_tctd_certificate_watch_armed;
static volatile LONG g_tctd_certificate_read_count;
static volatile LONG g_tctd_certificate_read_limit_logged;
static volatile LONG g_tctd_validation_code_captured;
static volatile LONG g_tctd_validation_event_count;
static volatile LONG g_tctd_validation_event_limit_logged;
static volatile LONG g_tctd_validation_stage;
static volatile LONG g_tctd_local_accept_armed;
static volatile LONG g_tctd_local_accept_applied;
static volatile LONG g_tctd_validator_code_captured;
static volatile LONG g_tctd_state_watch_stage;
static volatile LONG g_tctd_state_write_count;
static volatile LONG g_tctd_state_write_limit_logged;
static PVOID volatile g_tctd_state_watch_address;
static volatile LONG g_tctd_owner_watch_stage;
static volatile LONG g_tctd_owner_decision_count;
static volatile LONG g_tctd_owner_field_write_count;
static volatile LONG g_tctd_owner_state_write_count;
static volatile LONG g_tctd_owner_limit_logged;
static volatile LONG g_tctd_completion_armed;
static volatile LONG g_tctd_completion_event_count;
static volatile LONG g_tctd_completion_setter_count;
static volatile LONG g_tctd_completion_code_captured;
static volatile LONG g_tctd_completion_complete_logged;
static volatile LONG g_tctd_branch_armed;
static volatile LONG g_tctd_branch_event_count;
static volatile LONG g_tctd_branch_complete_logged;
static volatile LONG g_tctd_chain_stage;
static volatile LONG g_tctd_chain_event_count;
static volatile LONG g_tctd_chain_code_captured;
static volatile LONG g_tctd_chain_complete_logged;
static volatile LONG g_tctd_parser_code_armed;
static volatile LONG g_tctd_parser_code_captured;
static volatile LONG g_tctd_cert_flow_event_count;
static volatile LONG g_tctd_cert_flow_limit_logged;
static volatile LONG g_tctd_cert_flow_generation;
static volatile LONG g_tctd_cert_flow_consumer_count;
static volatile LONG g_tctd_cert_flow_consumer_lock;
static volatile LONG g_tctd_cert_flow_decision_code_captured;
static volatile LONG g_tctd_text_dump_started;
static uintptr_t
    g_tctd_cert_flow_consumers[ISAC_MAX_TCTD_CERT_FLOW_CONSUMERS];
static PVOID volatile g_tctd_owner_address;
static PVOID volatile g_tctd_owner_field_address;
static PVOID volatile g_tctd_owner_initial_state_address;
static PVOID volatile g_tctd_owner_state_address;
static ULONGLONG g_world_request_tick;
static volatile LONG g_bootstrap_type3_rearm_passes;
static PVOID volatile g_local_bridge_writer;
static PVOID volatile g_local_bridge_transport;
static PVOID volatile g_local_bridge_reader;
static PVOID volatile g_local_bridge_source;
static PVOID volatile g_local_bridge_injection_reader;
static PVOID volatile g_local_bridge_injection_source;
static PVOID volatile g_world_replay_reader;
static PVOID volatile g_world_replay_source;
static PVOID volatile g_local_bridge_socket;
static isac_world_stream_parser g_world_stream_parser;
static isac_dispatch_target g_dispatch_targets[ISAC_MAX_DISPATCH_TARGETS];
static isac_dispatch_caller g_dispatch_callers[ISAC_MAX_DISPATCH_CALLERS];
static isac_schema_target g_schema_targets[ISAC_MAX_SCHEMA_TARGETS];
static isac_bootstrap_stream
    g_bootstrap_streams[ISAC_MAX_BOOTSTRAP_STREAMS];
static uintptr_t
    g_control_code_functions[ISAC_MAX_CONTROL_CODE_FUNCTIONS];
static uintptr_t g_outbound_control_code_functions[
    ISAC_MAX_OUTBOUND_CONTROL_CODE_FUNCTIONS
];
static isac_schema_field_thread
    g_schema_field_threads[ISAC_MAX_SCHEMA_FIELD_THREADS];
static volatile LONG g_schema_field_rotations[0x10000u];
static volatile LONG g_schema_field_samples[0x10000u];
static uintptr_t g_inbound_batch_callers[ISAC_MAX_INBOUND_BATCH_CALLERS];
static uintptr_t g_inbound_source_vtables[ISAC_MAX_INBOUND_VTABLES];
static isac_queue_write_signature
    g_queue_writes[ISAC_MAX_QUEUE_WRITE_SIGNATURES];
static uintptr_t g_queue_code_anchors[ISAC_MAX_QUEUE_CODE_ANCHORS];
static DWORD g_dispatch_threads[ISAC_MAX_DISPATCH_THREADS];
static PVOID g_dispatch_exception_handler;
static HANDLE g_dispatch_event_file = INVALID_HANDLE_VALUE;
static HANDLE g_world_snapshot_file = INVALID_HANDLE_VALUE;
static HANDLE g_local_bridge_thread;
static volatile DWORD g_local_bridge_worker_thread_id;
static HANDLE g_local_bridge_stop_event;
static HANDLE g_local_bridge_queue_event;
static isac_local_bridge_record
    g_local_bridge_queue[ISAC_LOCAL_BRIDGE_QUEUE_SLOTS];
static isac_local_bridge_reader
    g_local_bridge_readers[ISAC_LOCAL_BRIDGE_MAX_READERS];

static void log_dispatch_status(const char *event, const char *detail);
static void refresh_dispatch_thread_breakpoints(void);
static void refresh_login_handoff_threads(void);
static LONG next_transport_startup_event(void);

static void append_stack_log(const char *line) {
    HANDLE file;
    DWORD written;
    DWORD length;

    if (g_stack_log_path[0] == L'\0') {
        return;
    }
    length = (DWORD)strlen(line);
    file = CreateFileW(
        g_stack_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    WriteFile(file, line, length, &written, NULL);
    CloseHandle(file);
}

static void append_code_log(const char *line) {
    HANDLE file;
    DWORD written;
    DWORD length;

    if (g_code_log_path[0] == L'\0') {
        return;
    }
    length = (DWORD)strlen(line);
    file = CreateFileW(
        g_code_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    WriteFile(file, line, length, &written, NULL);
    CloseHandle(file);
}

static void append_dispatch_log(const char *line) {
    HANDLE file;
    DWORD written;
    DWORD length;

    if (g_dispatch_log_path[0] == L'\0') {
        return;
    }
    length = (DWORD)strlen(line);
    file = CreateFileW(
        g_dispatch_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    WriteFile(file, line, length, &written, NULL);
    CloseHandle(file);
}

static void append_plaintext_log(const char *line) {
    HANDLE file;
    DWORD written;
    DWORD length;

    if (g_plaintext_log_path[0] == L'\0') {
        return;
    }
    length = (DWORD)strlen(line);
    file = CreateFileW(
        g_plaintext_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }
    WriteFile(file, line, length, &written, NULL);
    CloseHandle(file);
}

static void log_status(const char *event, const char *detail) {
    /* Handoff details can occupy 767 bytes, plus the event/timing envelope. */
    char line[1024];
    int length;

    length = snprintf(
        line,
        sizeof(line),
        "%s tick_ms=%llu process=%lu thread=%lu detail=%s\r\n",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        detail
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_stack_log(line);
    } else {
        /* Never silently lose a record or emit a deceptively partial one. */
        append_stack_log("STACK_PROBE_LOG_ERROR detail=status-format-or-size\r\n");
    }
}

static BOOL stack_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_STACK_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL code_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_CODE_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL dispatch_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_DISPATCH_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL dispatch_event_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_DISPATCH_EVENT_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL plaintext_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_PLAINTEXT_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL bootstrap_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_BOOTSTRAP_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL control_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_CONTROL_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL bootstrap_type3_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_BOOTSTRAP_TYPE3_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL outbound_control_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_OUTBOUND_CONTROL_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL inbound_source_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_INBOUND_SOURCE_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL local_bridge_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_LOCAL_BACKEND_BRIDGE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL local_bridge_injection_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_LOCAL_BACKEND_INJECT",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL local_bridge_type3_isolation_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_LOCAL_BACKEND_ISOLATE_TYPE3",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL type3_profile_capture_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_LOCAL_BACKEND_CAPTURE_TYPE3",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL world_bootstrap_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_WORLD_BOOTSTRAP_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL world_snapshot_capture_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_WORLD_BOOTSTRAP_CAPTURE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL world_continuation_capture_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_WORLD_CONTINUATION_CAPTURE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL world_replay_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_WORLD_BOOTSTRAP_REPLAY",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL transport_startup_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TRANSPORT_STARTUP_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_pc_loopback_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_PC_LOOPBACK",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_certificate_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_CERT_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_validation_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_VALIDATION_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_validation_remote_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_VALIDATION_REMOTE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_local_accept_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_LOCAL_ACCEPT",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_validator_code_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_VALIDATOR_CODE_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_state_watch_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_STATE_WATCH",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_owner_watch_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_OWNER_WATCH",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_owner_remote_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_OWNER_WATCH_REMOTE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_completion_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_COMPLETION_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_completion_remote_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_COMPLETION_REMOTE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_branch_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_BRANCH_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_branch_remote_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_BRANCH_REMOTE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_chain_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_CHAIN_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_chain_remote_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_CHAIN_REMOTE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_parser_code_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_PARSER_CODE_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_cert_flow_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_CERT_FLOW_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_cert_flow_remote_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_CERT_FLOW_REMOTE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL tctd_text_dump_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_TCTD_TEXT_DUMP",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static uintptr_t tctd_validation_checkpoint_rva(LONG stage) {
    switch (stage) {
        case 1:
            return ISAC_TCTD_KEY_RETURN_RVA;
        case 2:
            return ISAC_TCTD_TLS_RETURN_A_RVA;
        case 3:
            return ISAC_TCTD_TLS_RETURN_B_RVA;
        case 4:
            return ISAC_TCTD_VALIDATION_CALLER_RVA;
        case 5:
            return ISAC_TCTD_VALIDATION_RESULT_RVA;
        default:
            return 0u;
    }
}

static const char *tctd_validation_checkpoint_name(LONG stage) {
    switch (stage) {
        case 1:
            return "key-read-return";
        case 2:
            return "tls-return-a";
        case 3:
            return "tls-return-b";
        case 4:
            return "validation-caller";
        case 5:
            return "validation-result";
        default:
            return NULL;
    }
}

static uintptr_t tctd_chain_checkpoint_rva(LONG stage) {
    switch (stage) {
        case 1:
            return ISAC_TCTD_CHAIN_RETURN_1_RVA;
        case 2:
            return ISAC_TCTD_CHAIN_RETURN_2_RVA;
        case 3:
            return ISAC_TCTD_CHAIN_RETURN_3_RVA;
        case 4:
            return ISAC_TCTD_CHAIN_RETURN_4_RVA;
        case 5:
            return ISAC_TCTD_CHAIN_RETURN_5_RVA;
        case 6:
            return ISAC_TCTD_CHAIN_RETURN_6_RVA;
        default:
            return 0u;
    }
}

static const char *tctd_chain_checkpoint_name(LONG stage) {
    switch (stage) {
        case 1:
            return "key-parser-return";
        case 2:
            return "certificate-return";
        case 3:
            return "tls-parser-return";
        case 4:
            return "handshake-return";
        case 5:
            return "transport-pump-return";
        case 6:
            return "operation-pump-return";
        default:
            return NULL;
    }
}

static void load_local_bridge_port(void) {
    char value[16];
    char *end = NULL;
    unsigned long parsed;
    DWORD length = GetEnvironmentVariableA(
        "ISAC_LOCAL_BACKEND_PORT",
        value,
        (DWORD)sizeof(value)
    );

    if (length == 0) {
        return;
    }
    if (length >= sizeof(value)) {
        log_dispatch_status(
            "LOCAL_BRIDGE_CONFIG_ERROR",
            "port-environment-value-too-long"
        );
        g_local_bridge_requested = FALSE;
        return;
    }
    parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0' || parsed == 0 || parsed > 0xfffful) {
        log_dispatch_status(
            "LOCAL_BRIDGE_CONFIG_ERROR",
            "port-must-be-in-range-1-through-65535"
        );
        g_local_bridge_requested = FALSE;
        return;
    }
    g_local_bridge_port = (USHORT)parsed;
}

static BOOL schema_field_probe_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_SCHEMA_FIELD_PROBE",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static BOOL schema_miner_requested(void) {
    char value[8];
    DWORD length = GetEnvironmentVariableA(
        "ISAC_SCHEMA_MINER",
        value,
        (DWORD)sizeof(value)
    );
    return length == 1 && value[0] == '1';
}

static void load_schema_field_type_filter(void) {
    char value[32];
    char *end = NULL;
    unsigned long parsed;
    DWORD length = GetEnvironmentVariableA(
        "ISAC_SCHEMA_FIELD_TYPE",
        value,
        (DWORD)sizeof(value)
    );

    if (length == 0) {
        return;
    }
    if (length >= sizeof(value)) {
        log_dispatch_status(
            "SCHEMA_FIELD_FILTER_ERROR",
            "environment-value-too-long"
        );
        return;
    }
    parsed = strtoul(value, &end, 0);
    if (end == value || *end != '\0' || parsed > 0xfffful) {
        log_dispatch_status(
            "SCHEMA_FIELD_FILTER_ERROR",
            "expected-16-bit-message-type"
        );
        return;
    }
    g_schema_field_type_filter = (LONG)parsed;
}

static void log_code_status(const char *event, const char *detail) {
    char line[384];
    int length;

    length = snprintf(
        line,
        sizeof(line),
        "%s tick_ms=%llu process=%lu thread=%lu detail=%s\r\n",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        detail
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_code_log(line);
    }
}

static void log_dispatch_status(const char *event, const char *detail) {
    char line[384];
    int length;

    length = snprintf(
        line,
        sizeof(line),
        "%s tick_ms=%llu process=%lu thread=%lu detail=%s\r\n",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        detail
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
}

static void log_plaintext_status(const char *event, const char *detail) {
    char line[384];
    int length;

    length = snprintf(
        line,
        sizeof(line),
        "%s tick_ms=%llu process=%lu thread=%lu detail=%s\r\n",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        detail
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_plaintext_log(line);
    }
}

static BOOL get_image_range(HMODULE module, BYTE **base, SIZE_T *size) {
    IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)module;
    IMAGE_NT_HEADERS64 *nt_headers;

    if (dos_header == NULL || dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    nt_headers = (IMAGE_NT_HEADERS64 *)(
        (BYTE *)module + (uintptr_t)dos_header->e_lfanew
    );
    if (
        nt_headers->Signature != IMAGE_NT_SIGNATURE ||
        nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC
    ) {
        return FALSE;
    }
    *base = (BYTE *)module;
    *size = nt_headers->OptionalHeader.SizeOfImage;
    return TRUE;
}

static BOOL verified_game_file_diagnostic(ISAC_SDK_DIAGNOSTIC *result) {
    WCHAR path[MAX_PATH];
    const WCHAR *filename;
    DWORD path_length;
    HANDLE file;
    LARGE_INTEGER file_size;
    LARGE_INTEGER nt_offset;
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS64 nt_headers;
    DWORD read_count;
    BOOL verified = FALSE;

    isac_sdk_diagnostic_reset(result);
    result->stage = "file-module-path";
    path_length = GetModuleFileNameW(NULL, path, MAX_PATH);
    if (path_length == 0) {
        result->win32_error = GetLastError();
        return FALSE;
    }
    result->stage = "file-path-truncated";
    if (path_length >= MAX_PATH) return FALSE;
    filename = path + path_length;
    while (filename > path) {
        if (filename[-1] == L'\\' || filename[-1] == L'/') {
            break;
        }
        --filename;
    }
    result->stage = "file-name";
    if (lstrcmpiW(filename, L"thedivision.exe") != 0) {
        return FALSE;
    }

    result->stage = "file-open";
    file = CreateFileW(
        path,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        result->win32_error = GetLastError();
        return FALSE;
    }
    result->stage = "file-size-query";
    if (!GetFileSizeEx(file, &file_size)) goto api_error;
    result->stage = "file-size";
    result->expected = ISAC_EXPECTED_GAME_FILE_SIZE;
    result->observed = (unsigned long long)file_size.QuadPart;
    if (file_size.QuadPart != ISAC_EXPECTED_GAME_FILE_SIZE) goto done;
    result->stage = "file-dos-read";
    if (!ReadFile(file, &dos_header, sizeof(dos_header), &read_count, NULL)) goto api_error;
    result->stage = "file-dos-short-read";
    result->expected = sizeof(dos_header);
    result->observed = read_count;
    if (read_count != sizeof(dos_header)) goto done;
    result->stage = "file-dos-signature";
    result->expected = IMAGE_DOS_SIGNATURE;
    result->observed = dos_header.e_magic;
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) goto done;
    result->stage = "file-nt-offset";
    result->expected = 0;
    result->observed = (unsigned long long)dos_header.e_lfanew;
    if (dos_header.e_lfanew < 0) goto done;
    nt_offset.QuadPart = dos_header.e_lfanew;
    result->stage = "file-nt-seek";
    if (!SetFilePointerEx(file, nt_offset, NULL, FILE_BEGIN)) goto api_error;
    result->stage = "file-nt-read";
    if (!ReadFile(file, &nt_headers, sizeof(nt_headers), &read_count, NULL)) goto api_error;
    result->stage = "file-nt-short-read";
    result->expected = sizeof(nt_headers);
    result->observed = read_count;
    if (read_count != sizeof(nt_headers)) goto done;
    result->stage = "file-nt-signature";
    result->expected = IMAGE_NT_SIGNATURE;
    result->observed = nt_headers.Signature;
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) goto done;
    result->stage = "file-pe-magic";
    result->expected = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    result->observed = nt_headers.OptionalHeader.Magic;
    if (nt_headers.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) goto done;
    result->stage = "file-timestamp";
    result->expected = ISAC_EXPECTED_GAME_TIMESTAMP;
    result->observed = nt_headers.FileHeader.TimeDateStamp;
    if (nt_headers.FileHeader.TimeDateStamp != ISAC_EXPECTED_GAME_TIMESTAMP) goto done;
    result->stage = "file-image-size";
    result->expected = ISAC_EXPECTED_GAME_IMAGE_SIZE;
    result->observed = nt_headers.OptionalHeader.SizeOfImage;
    if (nt_headers.OptionalHeader.SizeOfImage != ISAC_EXPECTED_GAME_IMAGE_SIZE) goto done;
    result->stage = "file-verified";
    verified = TRUE;
    goto done;
api_error:
    result->win32_error = GetLastError();
    result->expected = result->observed = 0;
done:
    CloseHandle(file);
    return verified;
}

static BOOL verified_game_file(void) {
    ISAC_SDK_DIAGNOSTIC result;
    return verified_game_file_diagnostic(&result);
}

static void log_sdk_binding(const char *phase, const char *edge, ISAC_API_BINDING binding,
    uintptr_t expected, uintptr_t entry_slot, unsigned long long unix_ms) {
    MEMORY_BASIC_INFORMATION memory;
    const char *owner = "unknown";
    uintptr_t allocation = 0;
    char detail[512];
    ZeroMemory(&memory, sizeof(memory));
    if (binding.destination && VirtualQuery((void *)binding.destination, &memory, sizeof(memory)) == sizeof(memory)) {
        allocation = (uintptr_t)memory.AllocationBase;
        if (allocation == (uintptr_t)GetModuleHandleW(L"kernel32.dll")) owner = "kernel32";
        else if (allocation == (uintptr_t)GetModuleHandleW(L"kernelbase.dll")) owner = "kernelbase";
        else if (allocation == (uintptr_t)GetModuleHandleW(L"ntdll.dll")) owner = "ntdll";
        else if (allocation == (uintptr_t)GetModuleHandleW(NULL)) owner = "game";
        else if (memory.Type == MEM_IMAGE) owner = "other-image";
        else if (memory.Type == MEM_PRIVATE) owner = "private";
        else owner = "other-mapping";
    }
    snprintf(detail, sizeof(detail),
        "phase=%s,unix_ms=%llu,edge=%s,status=%s,slot=0x%llx,destination=0x%llx,expected=0x%llx,"
        "matches=%d,owner=%s,allocation=0x%llx,rva=0x%llx,protect=0x%lx,memory_type=0x%lx,"
        "entry_slot=0x%llx,entry_slot_matches=%d",
        phase, unix_ms, edge, binding.status,
        (unsigned long long)binding.slot, (unsigned long long)binding.destination,
        (unsigned long long)expected, (int)(expected && binding.destination == expected), owner,
        (unsigned long long)allocation,
        (unsigned long long)(allocation && binding.destination >= allocation ? binding.destination - allocation : 0),
        (unsigned long)memory.Protect, (unsigned long)memory.Type,
        (unsigned long long)entry_slot, (int)(entry_slot && entry_slot == binding.slot));
    log_status("SDK_API_BINDING", detail);
}

static void log_sdk_api_code(const char *phase, const char *api, HMODULE module,
    uintptr_t entry, SIZE_T length, unsigned long long unix_ms) {
    ISAC_API_CODE code = isac_api_code_sample(module, entry, length);
    char hex[ISAC_API_CODE_MAX * 2 + 1], detail[768];
    SIZE_T index;
    static const char digits[] = "0123456789abcdef";
    for (index = 0; index < code.length; ++index) {
        hex[index * 2] = digits[code.bytes[index] >> 4];
        hex[index * 2 + 1] = digits[code.bytes[index] & 15];
    }
    hex[code.length * 2] = 0;
    snprintf(detail, sizeof(detail),
        "phase=%s,unix_ms=%llu,api=%s,status=%s,entry=0x%llx,allocation=0x%llx,rva=0x%llx,"
        "timestamp=0x%lx,image_size=0x%lx,length=%llu,code_hex=%s",
        phase, unix_ms, api, code.status, (unsigned long long)code.entry,
        (unsigned long long)code.allocation, (unsigned long long)code.rva,
        (unsigned long)code.timestamp, (unsigned long)code.image_size,
        (unsigned long long)code.length, hex);
    log_status("SDK_API_CODE", detail);
    if (strcmp(api, "ntdll.NtProtectVirtualMemory") == 0) {
        const char *status = "unrecognized-stub";
        BYTE flag = 0;
        uintptr_t destination = 0, allocation = 0;
        DWORD memory_type = 0;
        MEMORY_BASIC_INFORMATION memory;
        if (isac_api_wine_stub(&code)) {
            status = "dispatch-unreadable";
            if (isac_binding_read(0x7ffe0308u, &flag, sizeof(flag)) &&
                isac_binding_read(0x7ffe1000u, &destination, sizeof(destination))) {
                status = "ok";
                if (destination && VirtualQuery((void *)destination, &memory, sizeof(memory)) == sizeof(memory)) {
                    allocation = (uintptr_t)memory.AllocationBase;
                    memory_type = memory.Type;
                }
            }
        }
        snprintf(detail, sizeof(detail),
            "phase=%s,unix_ms=%llu,status=%s,flag=0x%x,slot=0x7ffe1000,destination=0x%llx,"
            "allocation=0x%llx,memory_type=0x%lx",
            phase, unix_ms, status, (unsigned int)flag,
            (unsigned long long)destination, (unsigned long long)allocation, (unsigned long)memory_type);
        log_status("SDK_WINE_DISPATCH", detail);
    }
}

static void log_sdk_native_context(const char *operation, const char *phase,
    const CONTEXT *context, BOOL ok, DWORD error, BOOL unchanged) {
    char detail[320];
    FILETIME clock;
    unsigned long long unix_ms;
    GetSystemTimeAsFileTime(&clock);
    unix_ms = ((((unsigned long long)clock.dwHighDateTime << 32) | clock.dwLowDateTime)
        - 116444736000000000ULL) / 10000ULL;
    snprintf(detail, sizeof(detail),
        "operation=%s,phase=%s,unix_ms=%llu,context=0x%llx,flags=0x%lx,ok=%d,"
        "win32_error=%lu,unchanged=%d,enabled_slots=0x%llx",
        operation, phase, unix_ms, (unsigned long long)(uintptr_t)context,
        (unsigned long)context->ContextFlags, (int)ok, (unsigned long)error,
        (int)unchanged, (unsigned long long)(context->Dr7 & 0xffu));
    log_status("SDK_NATIVE_CONTEXT", detail);
}

static void log_sdk_native_boundary(const char *phase, const BYTE *target,
    SIZE_T length, DWORD requested, DWORD error) {
    char detail[224];
    snprintf(detail, sizeof(detail),
        "phase=%s,target=0x%llx,length=%llu,requested=0x%lx,win32_error=%lu",
        phase, (unsigned long long)(uintptr_t)target, (unsigned long long)length,
        (unsigned long)requested, (unsigned long)error);
    log_status("SDK_NATIVE_PROTECT_BOUNDARY", detail);
}

static void observe_sdk_protection(const char *phase, BYTE *target,
    SIZE_T length, DWORD requested, DWORD error) {
    MEMORY_BASIC_INFORMATION memory;
    char detail[512];
    HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    BOOL queried;
    FILETIME clock;
    unsigned long long unix_ms;
    if (!strcmp(phase, "write-failed") || !strcmp(phase, "write-succeeded")) {
        if (isac_sdk_path.status && !strcmp(isac_sdk_path.status, "native-only"))
            log_sdk_native_boundary("end", target, length, requested, error);
        isac_sdk_path_finish();
        snprintf(detail, sizeof(detail),
            "phase=%s,status=%s,thread=%lu,entry=0x%llx,jump=0x%llx,returned=0x%llx,"
            "target=0x%llx,length=%llu,requested=0x%lx,entered=%ld,jumped=%ld,completed=%ld,"
            "ntstatus=0x%lx,win32_error=%lu",
            phase, isac_sdk_path.status ? isac_sdk_path.status : "not-started",
            (unsigned long)isac_sdk_path.thread, (unsigned long long)isac_sdk_path.entry,
            (unsigned long long)isac_sdk_path.jump, (unsigned long long)isac_sdk_path.returned,
            (unsigned long long)isac_sdk_path.target, (unsigned long long)isac_sdk_path.length,
            (unsigned long)isac_sdk_path.requested, isac_sdk_path.entered, isac_sdk_path.jumped,
            isac_sdk_path.completed, (unsigned long)isac_sdk_path.ntstatus, (unsigned long)error);
        log_status("SDK_PROTECT_PATH", detail);
        if (isac_sdk_path.active) {
            log_status("SDK_PROTECT_PATH_ERROR", "debug-register-cleanup-failed,terminating=1");
            TerminateProcess(GetCurrentProcess(), 0x4953u);
            return;
        }
    }
    GetSystemTimeAsFileTime(&clock);
    unix_ms = ((((unsigned long long)clock.dwHighDateTime << 32) | clock.dwLowDateTime)
        - 116444736000000000ULL) / 10000ULL;
    ZeroMemory(&memory, sizeof(memory));
    queried = VirtualQuery(target, &memory, sizeof(memory)) == sizeof(memory);
    snprintf(detail, sizeof(detail),
        "phase=%s,unix_ms=%llu,target=0x%llx,length=%llu,requested=0x%lx,win32_error=%lu,"
        "query_ok=%d,region=0x%llx,region_size=0x%llx,allocation=0x%llx,"
        "protect=0x%lx,memory_type=0x%lx,virtual_protect=0x%llx,nt_protect=0x%llx",
        phase, unix_ms, (unsigned long long)(uintptr_t)target, (unsigned long long)length,
        (unsigned long)requested, (unsigned long)error, (int)queried,
        (unsigned long long)(uintptr_t)memory.BaseAddress,
        (unsigned long long)memory.RegionSize,
        (unsigned long long)(uintptr_t)memory.AllocationBase,
        (unsigned long)memory.Protect, (unsigned long)memory.Type,
        (unsigned long long)(uintptr_t)(kernelbase ? GetProcAddress(kernelbase, "VirtualProtect") : NULL),
        (unsigned long long)(uintptr_t)(ntdll ? GetProcAddress(ntdll, "NtProtectVirtualMemory") : NULL));
    log_status("SDK_PROTECT_CALL", detail);
    {
        uintptr_t k32_export = (uintptr_t)(kernel32 ? GetProcAddress(kernel32, "VirtualProtect") : NULL);
        uintptr_t kb_export = (uintptr_t)(kernelbase ? GetProcAddress(kernelbase, "VirtualProtect") : NULL);
        uintptr_t nt_export = (uintptr_t)(ntdll ? GetProcAddress(ntdll, "NtProtectVirtualMemory") : NULL);
        ISAC_API_BINDING forward = isac_binding_forward(k32_export);
        log_sdk_binding(phase, "shim-to-kernel32", isac_binding_slot((uintptr_t)&__imp_VirtualProtect),
            k32_export, 0, unix_ms);
        log_sdk_binding(phase, "kernel32-to-kernelbase", isac_binding_import(kernel32, "kernelbase.dll", "VirtualProtect"),
            kb_export, forward.slot, unix_ms);
        log_sdk_binding(phase, "kernelbase-to-ntdll", isac_binding_import(kernelbase, "ntdll.dll", "NtProtectVirtualMemory"),
            nt_export, 0, unix_ms);
        /* An entry shape may differ even with normal IAT destinations. Report
         * it independently, without classifying it as a hook. */
        log_sdk_binding(phase, "kernel32-entry", forward, kb_export, 0, unix_ms);
        log_sdk_api_code(phase, "kernel32.VirtualProtect", kernel32, k32_export, 24, unix_ms);
        log_sdk_api_code(phase, "kernelbase.VirtualProtect", kernelbase, kb_export, ISAC_API_CODE_MAX, unix_ms);
        log_sdk_api_code(phase, "ntdll.NtProtectVirtualMemory", ntdll, nt_export, 32, unix_ms);
        if (!strcmp(phase, "begin") || !strcmp(phase, "write-failed") || !strcmp(phase, "write-succeeded")) {
            ISAC_API_CODE nt_code = isac_api_code_sample(ntdll, nt_export, 32);
            ISAC_SDK_JUMP jump = isac_sdk_jump_sample(&nt_code);
            char hex[ISAC_SDK_JUMP_BYTES * 2 + 1], jump_detail[640];
            SIZE_T index;
            for (index = 0; index < jump.length; ++index)
                snprintf(hex + index * 2, 3, "%02x", (unsigned int)jump.bytes[index]);
            hex[jump.length * 2] = 0;
            snprintf(jump_detail, sizeof(jump_detail),
                "phase=%s,status=%s,entry=0x%llx,target=0x%llx,allocation=0x%llx,"
                "protect=0x%lx,memory_type=0x%lx,length=%llu,code_hex=%s",
                phase, jump.status, (unsigned long long)jump.entry, (unsigned long long)jump.target,
                (unsigned long long)jump.allocation, (unsigned long)jump.protection,
                (unsigned long)jump.memory_type, (unsigned long long)jump.length, hex);
            log_status("SDK_JUMP_CODE", jump_detail);
            if (!strcmp(phase, "begin")) {
                char native_mode[8];
                BOOL native = GetEnvironmentVariableA("ISAC_SDK_NATIVE_TRACE", native_mode,
                    sizeof(native_mode)) == 1 && native_mode[0] == '1';
                ISAC_API_CODE kb_code = isac_api_code_sample(kernelbase, kb_export, ISAC_API_CODE_MAX);
                uintptr_t returned = isac_sdk_nt_return(&kb_code, nt_export);
                /* Arm last, after all diagnostic reads/logs. Finish at the
                 * immediate post-call observer, before any further API log. */
                if (native) {
                    ZeroMemory(&isac_sdk_path, sizeof(isac_sdk_path));
                    isac_sdk_path.status = "native-only";
                    isac_sdk_path.entry = nt_export; isac_sdk_path.jump = jump.target;
                    isac_sdk_path.returned = returned; isac_sdk_path.target = (uintptr_t)target;
                    isac_sdk_path.length = length; isac_sdk_path.requested = requested;
                    isac_sdk_path.thread = GetCurrentThreadId();
                    log_status("SDK_NATIVE_MODE", "hardware-breakpoints=disabled,context-request=unchanged-state,dispatcher-trace=required");
                    isac_sdk_native_context(log_sdk_native_context);
                    log_sdk_native_boundary("begin", target, length, requested, 0);
                } else {
                    isac_sdk_path_start(nt_export, !strcmp(jump.status, "ok") ? jump.target : 0,
                        returned, (uintptr_t)target, length, requested);
                }
            }
        }
    }
}

static BOOL readable_memory_window(const void *start, SIZE_T length) {
    MEMORY_BASIC_INFORMATION memory;
    uintptr_t region_end;

    if (VirtualQuery(start, &memory, sizeof(memory)) != sizeof(memory)) {
        return FALSE;
    }
    region_end = (uintptr_t)memory.BaseAddress + memory.RegionSize;
    return memory.State == MEM_COMMIT &&
        (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
        (uintptr_t)start + length <= region_end;
}

static BOOL readable_code_window(const BYTE *start, SIZE_T length) {
    MEMORY_BASIC_INFORMATION memory;
    DWORD protection;

    if (
        !readable_memory_window(start, length) ||
        VirtualQuery(start, &memory, sizeof(memory)) != sizeof(memory)
    ) {
        return FALSE;
    }
    protection = memory.Protect;
    return
        (
            (protection & 0xffu) == PAGE_EXECUTE ||
            (protection & 0xffu) == PAGE_EXECUTE_READ ||
            (protection & 0xffu) == PAGE_EXECUTE_READWRITE ||
            (protection & 0xffu) == PAGE_EXECUTE_WRITECOPY
        );
}

static BOOL capture_code_window(
    const char *label,
    uintptr_t target_rva,
    uintptr_t start_rva,
    unsigned int window_length
) {
    BYTE *start;
    char line[1280];
    size_t offset;
    unsigned int index;

    if (
        window_length == 0 ||
        window_length > ISAC_MAX_CODE_WINDOW ||
        start_rva >= g_game_size ||
        window_length > g_game_size - start_rva ||
        target_rva < start_rva ||
        target_rva >= start_rva + window_length
    ) {
        log_code_status("CODE_PROBE_ERROR", "window-outside-game-image");
        return FALSE;
    }
    start = g_game_base + start_rva;
    if (!readable_code_window(start, window_length)) {
        log_code_status("CODE_PROBE_ERROR", "window-memory-unreadable");
        return FALSE;
    }

    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "CODE tick_ms=%llu process=%lu thread=%lu label=%s "
        "target_rva=0x%llx start_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        label,
        (unsigned long long)target_rva,
        (unsigned long long)start_rva,
        window_length
    );
    for (
        index = 0;
        index < window_length && offset + 2 < sizeof(line);
        ++index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return FALSE;
        }
        offset += 2;
    }
    if (offset + 2 < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_code_log(line);
        return TRUE;
    }
    return FALSE;
}

static void capture_tctd_validation_code(void) {
    static const struct {
        const char *label;
        uintptr_t target_rva;
    } targets[] = {
        {"tctd-key-copy", 0x021fea19u},
        {"tctd-key-copy-caller", 0x02016925u},
        {"tctd-key-read", ISAC_TCTD_KEY_READ_RVA},
        {"tctd-key-return", ISAC_TCTD_KEY_RETURN_RVA},
        {"tctd-tls-return-a", ISAC_TCTD_TLS_RETURN_A_RVA},
        {"tctd-tls-return-b", ISAC_TCTD_TLS_RETURN_B_RVA},
        {"tctd-validation-caller", 0x013877e0u},
        {"tctd-validation-result", 0x004c81fdu}
    };
    size_t index;

    if (
        !g_tctd_validation_probe_enabled ||
        !g_code_probe_enabled ||
        InterlockedCompareExchange(
            &g_tctd_validation_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    for (index = 0u; index < sizeof(targets) / sizeof(targets[0]); ++index) {
        uintptr_t start_rva = targets[index].target_rva >= 160u
            ? targets[index].target_rva - 160u
            : 0u;
        capture_code_window(
            targets[index].label,
            targets[index].target_rva,
            start_rva,
            320u
        );
    }
    log_status(
        "TCTD_VALIDATION_CODE_CAPTURED",
        "windows=8,bytes-per-window=320,payloads=disabled"
    );
}

static void capture_tctd_chain_code(void) {
    static const struct {
        const char *label;
        uintptr_t target_rva;
    } targets[] = {
        {"tctd-chain-key-parser", ISAC_TCTD_CHAIN_RETURN_1_RVA},
        {"tctd-chain-certificate", ISAC_TCTD_CHAIN_RETURN_2_RVA},
        {"tctd-chain-tls-parser", ISAC_TCTD_CHAIN_RETURN_3_RVA},
        {"tctd-chain-handshake", ISAC_TCTD_CHAIN_RETURN_4_RVA},
        {"tctd-chain-transport-pump", ISAC_TCTD_CHAIN_RETURN_5_RVA},
        {"tctd-chain-operation-pump", ISAC_TCTD_CHAIN_RETURN_6_RVA}
    };
    size_t index;

    if (
        !g_tctd_chain_probe_enabled ||
        !g_code_probe_enabled ||
        InterlockedCompareExchange(&g_tctd_chain_code_captured, 1, 0) != 0
    ) {
        return;
    }
    for (index = 0u; index < sizeof(targets) / sizeof(targets[0]); ++index) {
        uintptr_t start_rva = targets[index].target_rva >= 160u
            ? targets[index].target_rva - 160u
            : 0u;
        capture_code_window(
            targets[index].label,
            targets[index].target_rva,
            start_rva,
            320u
        );
    }
    log_status(
        "TCTD_CHAIN_CODE_CAPTURED",
        "windows=6,bytes-per-window=320,payloads=disabled"
    );
}

static void capture_tctd_completion_code(void) {
    uintptr_t cursor;
    unsigned int window_count = 0u;
    char label[48];
    char detail[192];

    if (
        !g_tctd_completion_probe_enabled ||
        !g_code_probe_enabled ||
        InterlockedCompareExchange(
            &g_tctd_completion_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    for (
        cursor = ISAC_TCTD_COMPLETION_ENTRY_RVA;
        cursor < ISAC_TCTD_COMPLETION_REGION_END_RVA;
    ) {
        uintptr_t remaining =
            ISAC_TCTD_COMPLETION_REGION_END_RVA - cursor;
        unsigned int length = remaining > ISAC_MAX_CODE_WINDOW
            ? ISAC_MAX_CODE_WINDOW
            : (unsigned int)remaining;

        snprintf(
            label,
            sizeof(label),
            "tctd-completion-region-%02u",
            window_count
        );
        if (!capture_code_window(label, cursor, cursor, length)) {
            log_status(
                "TCTD_COMPLETION_PROBE_ERROR",
                "completion-region-window-capture"
            );
            return;
        }
        cursor += length;
        ++window_count;
    }
    snprintf(
        detail,
        sizeof(detail),
        "begin-rva=0x%llx,end-rva=0x%llx,length=%llu,windows=%u,"
        "entry-rva=0x%llx,setter-rva=0x%llx,return-rva=0x%llx,"
        "payloads=disabled",
        (unsigned long long)ISAC_TCTD_COMPLETION_ENTRY_RVA,
        (unsigned long long)ISAC_TCTD_COMPLETION_REGION_END_RVA,
        (unsigned long long)(
            ISAC_TCTD_COMPLETION_REGION_END_RVA -
            ISAC_TCTD_COMPLETION_ENTRY_RVA
        ),
        window_count,
        (unsigned long long)ISAC_TCTD_COMPLETION_ENTRY_RVA,
        (unsigned long long)ISAC_TCTD_VALIDATOR_SUCCESS_RVA,
        (unsigned long long)ISAC_TCTD_COMPLETION_RETURN_RVA
    );
    log_status("TCTD_COMPLETION_CODE_CAPTURED", detail);
}

static void capture_tctd_validator_body(void) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t begin_rva;
    uintptr_t end_rva;
    uintptr_t cursor;
    uintptr_t function_size;
    unsigned int window_count = 0u;
    char label[48];
    char detail[192];

    if (
        !g_tctd_validator_code_enabled ||
        InterlockedCompareExchange(
            &g_tctd_validator_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_VALIDATOR_SUCCESS_RVA
        ),
        &image_base,
        NULL
    );
    if (
        function_entry == NULL ||
        image_base != (DWORD64)(uintptr_t)g_game_base
    ) {
        log_status(
            "TCTD_VALIDATOR_CODE_ERROR",
            "runtime-function-not-found"
        );
        return;
    }
    begin_rva = (uintptr_t)function_entry->BeginAddress;
    end_rva = (uintptr_t)function_entry->EndAddress;
    function_size = end_rva - begin_rva;
    if (
        begin_rva >= end_rva ||
        end_rva > g_game_size ||
        ISAC_TCTD_VALIDATOR_SUCCESS_RVA < begin_rva ||
        ISAC_TCTD_VALIDATOR_SUCCESS_RVA >= end_rva ||
        function_size >
            ISAC_MAX_TCTD_VALIDATOR_WINDOWS * ISAC_MAX_CODE_WINDOW
    ) {
        log_status(
            "TCTD_VALIDATOR_CODE_ERROR",
            "invalid-or-oversized-runtime-function"
        );
        return;
    }
    for (cursor = begin_rva; cursor < end_rva; ) {
        uintptr_t remaining = end_rva - cursor;
        unsigned int length = remaining > ISAC_MAX_CODE_WINDOW
            ? ISAC_MAX_CODE_WINDOW
            : (unsigned int)remaining;
        snprintf(
            label,
            sizeof(label),
            "tctd-validator-body-%02u",
            window_count
        );
        if (!capture_code_window(label, cursor, cursor, length)) {
            log_status(
                "TCTD_VALIDATOR_CODE_ERROR",
                "runtime-function-window-capture"
            );
            return;
        }
        cursor += length;
        ++window_count;
    }
    snprintf(
        detail,
        sizeof(detail),
        "begin-rva=0x%llx,end-rva=0x%llx,length=%llu,windows=%u,"
        "success-setter-rva=0x%llx,payloads=disabled",
        (unsigned long long)begin_rva,
        (unsigned long long)end_rva,
        (unsigned long long)function_size,
        window_count,
        (unsigned long long)ISAC_TCTD_VALIDATOR_SUCCESS_RVA
    );
    log_status("TCTD_VALIDATOR_CODE_CAPTURED", detail);
}

static BOOL capture_tctd_parser_body(uintptr_t target_rva) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t begin_rva;
    uintptr_t end_rva;
    uintptr_t cursor;
    uintptr_t function_size;
    unsigned int window_count = 0u;
    char label[48];
    char detail[224];

    if (
        !g_tctd_parser_code_enabled ||
        InterlockedCompareExchange(
            &g_tctd_parser_code_captured,
            1,
            0
        ) != 0
    ) {
        return FALSE;
    }
    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + target_rva),
        &image_base,
        NULL
    );
    if (
        function_entry == NULL ||
        image_base != (DWORD64)(uintptr_t)g_game_base
    ) {
        log_status("TCTD_PARSER_CODE_ERROR", "runtime-function-not-found");
        return FALSE;
    }
    begin_rva = (uintptr_t)function_entry->BeginAddress;
    end_rva = (uintptr_t)function_entry->EndAddress;
    function_size = end_rva - begin_rva;
    if (
        begin_rva >= end_rva ||
        end_rva > g_game_size ||
        target_rva < begin_rva ||
        target_rva >= end_rva ||
        function_size >
            ISAC_MAX_TCTD_PARSER_WINDOWS * ISAC_MAX_CODE_WINDOW
    ) {
        log_status(
            "TCTD_PARSER_CODE_ERROR",
            "invalid-or-oversized-runtime-function"
        );
        return FALSE;
    }
    for (cursor = begin_rva; cursor < end_rva; ) {
        uintptr_t remaining = end_rva - cursor;
        unsigned int length = remaining > ISAC_MAX_CODE_WINDOW
            ? ISAC_MAX_CODE_WINDOW
            : (unsigned int)remaining;

        snprintf(
            label,
            sizeof(label),
            "tctd-parser-body-%02u",
            window_count
        );
        if (!capture_code_window(label, cursor, cursor, length)) {
            log_status(
                "TCTD_PARSER_CODE_ERROR",
                "runtime-function-window-capture"
            );
            return FALSE;
        }
        cursor += length;
        ++window_count;
    }
    snprintf(
        detail,
        sizeof(detail),
        "target-rva=0x%llx,begin-rva=0x%llx,end-rva=0x%llx,"
        "length=%llu,windows=%u,mutation=disabled,payloads=disabled",
        (unsigned long long)target_rva,
        (unsigned long long)begin_rva,
        (unsigned long long)end_rva,
        (unsigned long long)function_size,
        window_count
    );
    log_status("TCTD_PARSER_CODE_CAPTURED", detail);
    return TRUE;
}

static void capture_tctd_cert_flow_consumer(
    uintptr_t instruction_rva,
    uintptr_t function_rva,
    uintptr_t function_end_rva
) {
    LONG index;
    LONG consumer_index;
    uintptr_t start_rva;
    uintptr_t available;
    unsigned int length;
    char label[48];

    if (
        !g_tctd_cert_flow_enabled ||
        !g_code_probe_enabled ||
        instruction_rva >= g_game_size
    ) {
        return;
    }
    if (
        function_rva >= g_game_size ||
        function_end_rva <= function_rva ||
        instruction_rva < function_rva ||
        instruction_rva >= function_end_rva
    ) {
        function_rva = instruction_rva;
    }
    while (
        InterlockedCompareExchange(
            &g_tctd_cert_flow_consumer_lock,
            1,
            0
        ) != 0
    ) {
        YieldProcessor();
    }
    consumer_index = g_tctd_cert_flow_consumer_count;
    for (index = 0; index < consumer_index; ++index) {
        if (g_tctd_cert_flow_consumers[index] == function_rva) {
            InterlockedExchange(&g_tctd_cert_flow_consumer_lock, 0);
            return;
        }
    }
    if (consumer_index >= ISAC_MAX_TCTD_CERT_FLOW_CONSUMERS) {
        InterlockedExchange(&g_tctd_cert_flow_consumer_lock, 0);
        return;
    }
    g_tctd_cert_flow_consumers[consumer_index] = function_rva;
    g_tctd_cert_flow_consumer_count = consumer_index + 1;
    InterlockedExchange(&g_tctd_cert_flow_consumer_lock, 0);

    start_rva = function_rva;
    if (
        start_rva >= g_game_size ||
        function_end_rva <= start_rva ||
        function_end_rva > g_game_size ||
        instruction_rva < start_rva ||
        instruction_rva >= function_end_rva ||
        instruction_rva - start_rva >= ISAC_MAX_CODE_WINDOW
    ) {
        start_rva = instruction_rva >= ISAC_MAX_CODE_WINDOW / 2u
            ? instruction_rva - ISAC_MAX_CODE_WINDOW / 2u
            : 0u;
        function_end_rva = g_game_size;
    }
    available = function_end_rva - start_rva;
    length = available > ISAC_MAX_CODE_WINDOW
        ? ISAC_MAX_CODE_WINDOW
        : (unsigned int)available;
    if (length == 0u) {
        return;
    }
    snprintf(
        label,
        sizeof(label),
        "tctd-cert-flow-consumer-%02ld",
        consumer_index
    );
    if (!capture_code_window(label, instruction_rva, start_rva, length)) {
        log_status(
            "TCTD_CERT_FLOW_ERROR",
            "consumer-code-window-capture"
        );
    }
}

static void capture_tctd_cert_flow_decision_code(void) {
    static const struct {
        const char *label;
        uintptr_t target_rva;
    } targets[] = {
        {"tctd-flow-official-consumer", 0x02032828u},
        {"tctd-flow-official-return", 0x02031db5u},
        {"tctd-flow-official-call-a", 0x02092100u},
        {"tctd-flow-official-call-b", 0x0208e81au},
        {"tctd-flow-official-call-c", 0x0205ae61u},
        {"tctd-flow-official-call-d", 0x020628bcu},
        {"tctd-flow-shared-verify", 0x0205291du},
        {"tctd-flow-shared-owner", 0x0205d2d3u},
        {"tctd-flow-shared-tls", 0x02238f65u},
        {"tctd-flow-local-cleanup-a", 0x0205ce7eu},
        {"tctd-flow-local-cleanup-b", 0x02022734u},
        {"tctd-flow-local-cleanup-c", 0x022380a5u},
        {"tctd-flow-local-cleanup-d", 0x02242375u},
        {"tctd-flow-local-cleanup-e", 0x02243014u},
        {"tctd-flow-local-zero-a", 0x02026790u},
        {"tctd-flow-local-zero-b", 0x0201690au}
    };
    size_t index;
    unsigned int captured = 0u;
    char detail[160];

    if (
        !g_tctd_cert_flow_enabled ||
        !g_code_probe_enabled ||
        InterlockedCompareExchange(
            &g_tctd_cert_flow_decision_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    for (index = 0u; index < sizeof(targets) / sizeof(targets[0]); ++index) {
        uintptr_t start_rva = targets[index].target_rva >= 160u
            ? targets[index].target_rva - 160u
            : 0u;
        if (
            capture_code_window(
                targets[index].label,
                targets[index].target_rva,
                start_rva,
                320u
            )
        ) {
            ++captured;
        }
    }
    snprintf(
        detail,
        sizeof(detail),
        "requested-windows=%u,captured-windows=%u,window-bytes=320,"
        "official-and-local-paths=yes,payloads=disabled",
        (unsigned int)(sizeof(targets) / sizeof(targets[0])),
        captured
    );
    log_status("TCTD_CERT_FLOW_CODE_CAPTURED", detail);
}

static void dump_tctd_runtime_text(void) {
    static const WCHAR dump_name[] =
        L"project-isac-tctd-text-private.bin";
    WCHAR dump_path[MAX_PATH];
    DWORD path_length;
    DWORD directory_length;
    HANDLE file;
    SIZE_T offset = 0u;
    const SIZE_T text_size = ISAC_TCTD_TEXT_SIZE;
    BOOL succeeded = TRUE;
    char detail[256];

    if (
        !g_tctd_text_dump_requested ||
        !g_tctd_cert_flow_enabled ||
        g_tctd_cert_flow_remote_requested ||
        InterlockedCompareExchange(&g_tctd_text_dump_started, 1, 0) != 0
    ) {
        return;
    }
    if (
        ISAC_TCTD_TEXT_RVA >= g_game_size ||
        text_size > g_game_size - ISAC_TCTD_TEXT_RVA
    ) {
        log_status("TCTD_TEXT_DUMP_ERROR", "invalid-text-range");
        return;
    }
    path_length = GetModuleFileNameW(NULL, dump_path, MAX_PATH);
    if (path_length == 0u || path_length >= MAX_PATH) {
        log_status("TCTD_TEXT_DUMP_ERROR", "game-module-path-unavailable");
        return;
    }
    directory_length = path_length;
    while (
        directory_length > 0u &&
        dump_path[directory_length - 1u] != L'\\' &&
        dump_path[directory_length - 1u] != L'/'
    ) {
        --directory_length;
    }
    if (
        directory_length == 0u ||
        directory_length +
            (DWORD)(sizeof(dump_name) / sizeof(dump_name[0])) >
            MAX_PATH
    ) {
        log_status("TCTD_TEXT_DUMP_ERROR", "dump-path-too-long");
        return;
    }
    lstrcpyW(dump_path + directory_length, dump_name);
    file = CreateFileW(
        dump_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        log_status("TCTD_TEXT_DUMP_ERROR", "dump-file-create-failed");
        return;
    }
    while (offset < text_size) {
        const BYTE *cursor =
            g_game_base + ISAC_TCTD_TEXT_RVA + offset;
        MEMORY_BASIC_INFORMATION memory;
        uintptr_t region_end;
        SIZE_T remaining;
        SIZE_T chunk_size;
        DWORD written = 0u;

        if (
            VirtualQuery(cursor, &memory, sizeof(memory)) != sizeof(memory) ||
            memory.State != MEM_COMMIT ||
            (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0
        ) {
            succeeded = FALSE;
            break;
        }
        region_end = (uintptr_t)memory.BaseAddress + memory.RegionSize;
        if (region_end <= (uintptr_t)cursor) {
            succeeded = FALSE;
            break;
        }
        remaining = text_size - offset;
        chunk_size = region_end - (uintptr_t)cursor;
        if (chunk_size > remaining) {
            chunk_size = remaining;
        }
        if (
            chunk_size > 0xffffffffu ||
            !WriteFile(file, cursor, (DWORD)chunk_size, &written, NULL) ||
            written != (DWORD)chunk_size
        ) {
            succeeded = FALSE;
            break;
        }
        offset += chunk_size;
    }
    if (succeeded && !FlushFileBuffers(file)) {
        succeeded = FALSE;
    }
    CloseHandle(file);
    if (!succeeded || offset != text_size) {
        DeleteFileW(dump_path);
        snprintf(
            detail,
            sizeof(detail),
            "write-failed-at-offset=0x%llx,partial-file-deleted=yes",
            (unsigned long long)offset
        );
        log_status("TCTD_TEXT_DUMP_ERROR", detail);
        return;
    }
    snprintf(
        detail,
        sizeof(detail),
        "start-rva=0x%llx,length=%llu,file=%ls,scope=loopback-only,"
        "mutation=disabled",
        (unsigned long long)ISAC_TCTD_TEXT_RVA,
        (unsigned long long)text_size,
        dump_name
    );
    log_status("TCTD_TEXT_DUMP_CAPTURED", detail);
}

static BOOL stack_contains_rva(
    const uintptr_t *rvas,
    USHORT depth,
    uintptr_t target
) {
    USHORT frame_index;

    for (frame_index = 0; frame_index < depth; ++frame_index) {
        if (rvas[frame_index] == target) {
            return TRUE;
        }
    }
    return FALSE;
}

static void capture_matching_code_targets(
    const uintptr_t *rvas,
    USHORT depth
) {
    if (!g_code_probe_enabled) {
        return;
    }
    if (InterlockedCompareExchange(&g_core_code_captured, 1, 0) == 0) {
        capture_code_window(
            "inbound-consumer",
            0x2016740u,
            0x2016740u,
            512u
        );
        capture_code_window(
            "outbound-provider",
            0x223aeb0u,
            0x223aeb0u,
            256u
        );
        capture_code_window(
            "outbound-transform",
            0x2023510u,
            0x2023510u,
            512u
        );
    }
    if (
        (
            stack_contains_rva(rvas, depth, 0x0fc3fc0u) ||
            stack_contains_rva(rvas, depth, 0x189fd53u)
        ) &&
        InterlockedCompareExchange(&g_world_code_captured, 1, 0) == 0
    ) {
        capture_code_window(
            "world-dispatcher",
            0x0f8e8d0u,
            0x0f8e8d0u,
            512u
        );
        capture_code_window(
            "write-u16",
            0x223f330u,
            0x223f330u,
            256u
        );
        capture_code_window(
            "write-variable",
            0x223f700u,
            0x223f700u,
            256u
        );
        capture_code_window(
            "write-u32",
            0x223fdc0u,
            0x223fdc0u,
            256u
        );
        capture_code_window(
            "world-send-lower",
            0x22484efu,
            0x22483efu,
            512u
        );
        capture_code_window(
            "world-send-upper",
            0x224ca84u,
            0x224c984u,
            512u
        );
        capture_code_window(
            "world-send-stage-3",
            0x0d6bc2u,
            0x0d6ac2u,
            512u
        );
        capture_code_window(
            "world-send-stage-2",
            0x0d3afau,
            0x0d39fau,
            512u
        );
        capture_code_window(
            "world-send-stage-1",
            0x0d395cu,
            0x0d385cu,
            512u
        );
        capture_code_window(
            "weapon-send-branch-a",
            0x0cf439u,
            0x0cf339u,
            512u
        );
        capture_code_window(
            "weapon-send-branch-b",
            0x0cec89u,
            0x0ceb89u,
            512u
        );
    }
}

static BOOL valid_internal_signature(const BYTE *target) {
    return memcmp(target, g_internal_signature, ISAC_HOOK_SIZE) == 0 ||
        memcmp(
            target,
            g_internal_signature_wine11,
            ISAC_HOOK_SIZE
        ) == 0;
}

static BYTE *find_internal_target(HMODULE ws2_module, const char *wrapper_name) {
    BYTE *wrapper = (BYTE *)GetProcAddress(ws2_module, wrapper_name);
    BYTE *module_base;
    SIZE_T module_size;
    unsigned int offset;

    if (
        wrapper == NULL ||
        !get_image_range(ws2_module, &module_base, &module_size)
    ) {
        return NULL;
    }

    for (offset = 0; offset + 5 <= 128; ++offset) {
        int32_t displacement;
        BYTE *target;

        if (wrapper[offset] != 0xe8) {
            continue;
        }
        CopyMemory(&displacement, wrapper + offset + 1, sizeof(displacement));
        target = wrapper + offset + 5 + displacement;
        if (target < module_base || target + ISAC_HOOK_SIZE > module_base + module_size) {
            continue;
        }
        if (valid_internal_signature(target)) {
            return target;
        }
    }
    return NULL;
}

static void write_absolute_jump(BYTE *destination, const void *target) {
    uintptr_t address = (uintptr_t)target;

    destination[0] = 0x48;
    destination[1] = 0xb8;
    CopyMemory(destination + 2, &address, sizeof(address));
    destination[10] = 0xff;
    destination[11] = 0xe0;
}

static void write_absolute_jump_r11(BYTE *destination, const void *target) {
    uintptr_t address = (uintptr_t)target;

    destination[0] = 0x49;
    destination[1] = 0xbb;
    CopyMemory(destination + 2, &address, sizeof(address));
    destination[10] = 0x41;
    destination[11] = 0xff;
    destination[12] = 0xe3;
}

static BOOL prepare_hook(
    isac_inline_hook *hook,
    BYTE *target,
    SIZE_T hook_size
) {
    BYTE *trampoline;
    DWORD old_protection;

    ZeroMemory(hook, sizeof(*hook));
    if (hook_size < ISAC_HOOK_SIZE || hook_size > ISAC_MAX_HOOK_SIZE) {
        return FALSE;
    }
    trampoline = (BYTE *)VirtualAlloc(
        NULL,
        ISAC_MAX_HOOK_SIZE + ISAC_TRAMPOLINE_JUMP_SIZE,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE
    );
    if (trampoline == NULL) {
        return FALSE;
    }

    hook->target = target;
    hook->trampoline = trampoline;
    hook->size = hook_size;
    CopyMemory(hook->original, target, hook_size);
    CopyMemory(trampoline, target, hook_size);
    write_absolute_jump_r11(trampoline + hook_size, target + hook_size);
    if (!VirtualProtect(
            trampoline,
            ISAC_MAX_HOOK_SIZE + ISAC_TRAMPOLINE_JUMP_SIZE,
            PAGE_EXECUTE_READ,
            &old_protection
        )) {
        VirtualFree(trampoline, 0, MEM_RELEASE);
        ZeroMemory(hook, sizeof(*hook));
        return FALSE;
    }
    FlushInstructionCache(
        GetCurrentProcess(),
        trampoline,
        ISAC_MAX_HOOK_SIZE + ISAC_TRAMPOLINE_JUMP_SIZE
    );
    return TRUE;
}

static BOOL make_hook_target_writable(
    isac_inline_hook *hook,
    DWORD *old_protection,
    isac_patch_diagnostic *diagnostic
) {
    static const DWORD private_candidates[] = {
        PAGE_READWRITE,
        PAGE_EXECUTE_READWRITE
    };
    static const DWORD mapped_candidates[] = {
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_WRITECOPY,
        PAGE_EXECUTE_READWRITE
    };
    MEMORY_BASIC_INFORMATION memory;
    const DWORD *candidates;
    size_t candidate_count;
    size_t index;

    if (diagnostic != NULL) {
        ZeroMemory(diagnostic, sizeof(*diagnostic));
    }
    if (
        VirtualQuery(hook->target, &memory, sizeof(memory)) != sizeof(memory)
    ) {
        if (diagnostic != NULL) {
            diagnostic->error = GetLastError();
        }
        return FALSE;
    }
    if (diagnostic != NULL) {
        diagnostic->original_protection = memory.Protect;
        diagnostic->memory_type = memory.Type;
    }
    if (memory.Type == MEM_IMAGE || memory.Type == MEM_MAPPED) {
        candidates = mapped_candidates;
        candidate_count = sizeof(mapped_candidates) / sizeof(*mapped_candidates);
    } else {
        candidates = private_candidates;
        candidate_count = sizeof(private_candidates) / sizeof(*private_candidates);
    }

    for (index = 0; index < candidate_count; ++index) {
        if (diagnostic != NULL) {
            diagnostic->attempted_protection = candidates[index];
        }
        SetLastError(ERROR_SUCCESS);
        if (VirtualProtect(
                hook->target,
                hook->size,
                candidates[index],
                old_protection
            )) {
            if (diagnostic != NULL) {
                diagnostic->error = ERROR_SUCCESS;
            }
            return TRUE;
        }
        if (diagnostic != NULL) {
            diagnostic->error = GetLastError();
        }
    }
    return FALSE;
}

static BOOL patch_hook(
    isac_inline_hook *hook,
    const void *detour,
    isac_patch_diagnostic *diagnostic
) {
    BYTE patch[ISAC_MAX_HOOK_SIZE];
    DWORD old_protection;
    DWORD ignored;

    FillMemory(patch, sizeof(patch), 0x90);
    write_absolute_jump(patch, detour);
    if (!make_hook_target_writable(hook, &old_protection, diagnostic)) {
        return FALSE;
    }
    CopyMemory(hook->target, patch, hook->size);
    FlushInstructionCache(GetCurrentProcess(), hook->target, hook->size);
    VirtualProtect(hook->target, hook->size, old_protection, &ignored);
    hook->installed = TRUE;
    return TRUE;
}

static BOOL unpatch_hook(isac_inline_hook *hook) {
    DWORD old_protection;
    DWORD ignored;

    if (!hook->installed) {
        return TRUE;
    }
    if (!make_hook_target_writable(hook, &old_protection, NULL)) {
        return FALSE;
    }

    CopyMemory(hook->target, hook->original, hook->size);
    FlushInstructionCache(
        GetCurrentProcess(),
        hook->target,
        hook->size
    );
    VirtualProtect(
        hook->target,
        hook->size,
        old_protection,
        &ignored
    );
    hook->installed = FALSE;
    return TRUE;
}

static size_t suspend_other_threads(
    HANDLE handles[ISAC_MAX_SUSPENDED_THREADS],
    BOOL *complete
) {
    HANDLE snapshot;
    THREADENTRY32 entry;
    DWORD process_id = GetCurrentProcessId();
    DWORD current_thread_id = GetCurrentThreadId();
    size_t count = 0;

    *complete = FALSE;
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    entry.dwSize = sizeof(entry);
    if (!Thread32First(snapshot, &entry)) {
        CloseHandle(snapshot);
        return 0;
    }

    do {
        HANDLE thread;

        if (
            entry.th32OwnerProcessID != process_id ||
            entry.th32ThreadID == current_thread_id
        ) {
            continue;
        }
        if (count == ISAC_MAX_SUSPENDED_THREADS) {
            CloseHandle(snapshot);
            return count;
        }
        thread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
            FALSE,
            entry.th32ThreadID
        );
        if (thread == NULL) {
            continue;
        }
        if (SuspendThread(thread) == (DWORD)-1) {
            CloseHandle(thread);
            continue;
        }
        handles[count++] = thread;
    } while (Thread32Next(snapshot, &entry));

    CloseHandle(snapshot);
    *complete = TRUE;
    return count;
}

static void redirect_suspended_threads(
    HANDLE *handles,
    size_t count,
    const isac_inline_hook *const *hooks,
    size_t hook_count,
    BOOL installing
) {
    size_t index;

    for (index = 0; index < count; ++index) {
        CONTEXT context;
        size_t hook_index;

        ZeroMemory(&context, sizeof(context));
        context.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(handles[index], &context)) {
            continue;
        }
        for (hook_index = 0; hook_index < hook_count; ++hook_index) {
            const BYTE *source = installing
                ? hooks[hook_index]->target
                : hooks[hook_index]->trampoline;
            const BYTE *destination = installing
                ? hooks[hook_index]->trampoline
                : hooks[hook_index]->target;
            uintptr_t instruction = (uintptr_t)context.Rip;
            uintptr_t start = (uintptr_t)source;

            if (
                hooks[hook_index]->target != NULL &&
                hooks[hook_index]->trampoline != NULL &&
                instruction >= start &&
                instruction < start + hooks[hook_index]->size
            ) {
                context.Rip = (DWORD64)(
                    (uintptr_t)destination + (instruction - start)
                );
                SetThreadContext(handles[index], &context);
                break;
            }
        }
    }
}

static void resume_threads(HANDLE *handles, size_t count) {
    size_t index;

    for (index = 0; index < count; ++index) {
        ResumeThread(handles[index]);
        CloseHandle(handles[index]);
    }
}

static BOOL cached_target_socket(SOCKET socket_handle) {
    PVOID value = (PVOID)(uintptr_t)socket_handle;
    unsigned int index;

    for (index = 0; index < ISAC_MAX_TARGET_SOCKETS; ++index) {
        if (g_target_sockets[index] == value) {
            return TRUE;
        }
    }
    return FALSE;
}

static void remember_target_socket(SOCKET socket_handle) {
    PVOID value = (PVOID)(uintptr_t)socket_handle;
    unsigned int index;

    for (index = 0; index < ISAC_MAX_TARGET_SOCKETS; ++index) {
        if (g_target_sockets[index] == value) {
            return;
        }
        if (InterlockedCompareExchangePointer(
                &g_target_sockets[index],
                value,
                NULL
            ) == NULL) {
            return;
        }
    }
}

static LONG target_socket_id(SOCKET socket_handle) {
    PVOID value = (PVOID)(uintptr_t)socket_handle;
    unsigned int index;

    for (index = 0; index < ISAC_MAX_TARGET_SOCKETS; ++index) {
        if (g_target_sockets[index] == value) {
            return (LONG)index + 1;
        }
    }
    return 0;
}

static void record_bootstrap_socket_event(
    char direction,
    SOCKET socket_handle
) {
    LONG sequence;
    char line[384];
    int length;

    if (!g_bootstrap_probe_enabled) {
        return;
    }
    sequence = InterlockedIncrement(&g_bootstrap_socket_event_count);
    if (sequence > (LONG)ISAC_MAX_BOOTSTRAP_SOCKET_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_bootstrap_socket_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "BOOTSTRAP_SOCKET_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    length = snprintf(
        line,
        sizeof(line),
        "BOOTSTRAP_SOCKET sequence=%ld tick_ms=%llu process=%lu thread=%lu "
        "direction=%s socket_id=%ld peer_port=55000\r\n",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        direction == 'S' ? "send" : "recv",
        target_socket_id(socket_handle)
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_plaintext_log(line);
    }
}

static BOOL is_target_socket(SOCKET socket_handle) {
    struct sockaddr_storage address;
    int address_length = (int)sizeof(address);
    const unsigned char *port_bytes;
    unsigned int port;

    if (cached_target_socket(socket_handle)) {
        return TRUE;
    }
    if (
        g_getpeername == NULL ||
        g_getpeername(
            socket_handle,
            (struct sockaddr *)&address,
            &address_length
        ) != 0
    ) {
        return FALSE;
    }
    if (address.ss_family == AF_INET) {
        port_bytes = (const unsigned char *)&(
            (const struct sockaddr_in *)&address
        )->sin_port;
    } else if (address.ss_family == AF_INET6) {
        port_bytes = (const unsigned char *)&(
            (const struct sockaddr_in6 *)&address
        )->sin6_port;
    } else {
        return FALSE;
    }
    port = ((unsigned int)port_bytes[0] << 8) | port_bytes[1];
    if (port != 55000) {
        return FALSE;
    }
    remember_target_socket(socket_handle);
    return TRUE;
}

static BOOL capture_dispatch_code_window(
    char kind,
    BYTE *target,
    uintptr_t target_rva
) {
    unsigned int window_length = kind == 'I'
        ? ISAC_DISPATCH_INBOUND_CODE_BYTES
        : ISAC_DISPATCH_MESSAGE_CODE_BYTES;
    const char *kind_name = kind == 'I'
        ? "inbound-handler"
        : kind == 'O'
            ? "outbound-type-method"
            : "message-type-method";
    char line[896];
    size_t offset;
    unsigned int index;

    if (
        target_rva >= g_game_size ||
        window_length > g_game_size - target_rva ||
        !readable_code_window(target, window_length)
    ) {
        return FALSE;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "DISPATCH_CODE tick_ms=%llu process=%lu thread=%lu kind=%s "
        "target_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        kind_name,
        (unsigned long long)target_rva,
        window_length
    );
    for (
        index = 0;
        index < window_length && offset + 2 < sizeof(line);
        ++index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)target[index]
        );
        if (written != 2) {
            return FALSE;
        }
        offset += 2;
    }
    if (offset + 2 >= sizeof(line)) {
        return FALSE;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    return TRUE;
}

static BOOL capture_dispatch_caller_code_window(
    BYTE *return_address,
    uintptr_t return_rva
) {
    BYTE *start;
    uintptr_t start_rva;
    unsigned int window_length = ISAC_DISPATCH_CALLER_CODE_BYTES;
    char line[1792];
    size_t offset;
    unsigned int index;

    if (return_rva < ISAC_DISPATCH_CALLER_CODE_BEFORE) {
        return FALSE;
    }
    start_rva = return_rva - ISAC_DISPATCH_CALLER_CODE_BEFORE;
    if (
        start_rva >= g_game_size ||
        window_length > g_game_size - start_rva
    ) {
        return FALSE;
    }
    start = return_address - ISAC_DISPATCH_CALLER_CODE_BEFORE;
    if (!readable_code_window(start, window_length)) {
        return FALSE;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "DISPATCH_CALLER_CODE tick_ms=%llu process=%lu thread=%lu "
        "return_rva=0x%llx start_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)return_rva,
        (unsigned long long)start_rva,
        window_length
    );
    for (
        index = 0;
        index < window_length && offset + 2 < sizeof(line);
        ++index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return FALSE;
        }
        offset += 2;
    }
    if (offset + 2 >= sizeof(line)) {
        return FALSE;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    return TRUE;
}

static void capture_queue_code_anchor(
    const char *kind,
    BYTE *anchor,
    uintptr_t anchor_rva
) {
    BYTE *start;
    uintptr_t start_rva;
    LONG count;
    LONG existing_index;
    char line[1280];
    size_t offset;
    unsigned int index;

    if (
        anchor_rva < ISAC_QUEUE_CODE_BEFORE ||
        anchor_rva >= g_game_size
    ) {
        return;
    }
    start_rva = anchor_rva - ISAC_QUEUE_CODE_BEFORE;
    if (ISAC_QUEUE_CODE_BYTES > g_game_size - start_rva) {
        return;
    }
    start = anchor - ISAC_QUEUE_CODE_BEFORE;
    if (!readable_code_window(start, ISAC_QUEUE_CODE_BYTES)) {
        return;
    }
    if (InterlockedCompareExchange(&g_queue_code_lock, 1, 0) != 0) {
        return;
    }
    count = g_queue_code_count;
    for (existing_index = 0; existing_index < count; ++existing_index) {
        if (g_queue_code_anchors[existing_index] == anchor_rva) {
            InterlockedExchange(&g_queue_code_lock, 0);
            return;
        }
    }
    if (count >= (LONG)ISAC_MAX_QUEUE_CODE_ANCHORS) {
        if (
            InterlockedCompareExchange(&g_queue_code_limit_logged, 1, 0) == 0
        ) {
            log_dispatch_status(
                "INBOUND_QUEUE_CODE_LIMIT",
                "unique-anchor-capacity-reached"
            );
        }
        InterlockedExchange(&g_queue_code_lock, 0);
        return;
    }
    g_queue_code_anchors[count] = anchor_rva;
    g_queue_code_count = count + 1;

    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_QUEUE_CODE tick_ms=%llu process=%lu thread=%lu "
        "kind=%s anchor_rva=0x%llx start_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        kind,
        (unsigned long long)anchor_rva,
        (unsigned long long)start_rva,
        ISAC_QUEUE_CODE_BYTES
    );
    for (
        index = 0;
        index < ISAC_QUEUE_CODE_BYTES && offset + 2 < sizeof(line);
        ++index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            InterlockedExchange(&g_queue_code_lock, 0);
            return;
        }
        offset += 2;
    }
    if (offset + 2 < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_dispatch_log(line);
    }
    InterlockedExchange(&g_queue_code_lock, 0);
}

static void capture_queue_producer_function(
    uintptr_t function_rva,
    uintptr_t function_end_rva
) {
    BYTE *start;
    uintptr_t available;
    unsigned int length;
    char line[4352];
    size_t offset;
    unsigned int index;

    if (
        function_rva >= function_end_rva ||
        function_rva >= g_game_size ||
        function_end_rva > g_game_size ||
        InterlockedCompareExchange(
            &g_queue_producer_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    available = function_end_rva - function_rva;
    length = available > ISAC_MAX_QUEUE_PRODUCER_CODE_BYTES
        ? ISAC_MAX_QUEUE_PRODUCER_CODE_BYTES
        : (unsigned int)available;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "INBOUND_QUEUE_PRODUCER_CODE_ERROR",
            "function-window-unreadable"
        );
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_QUEUE_PRODUCER_CODE tick_ms=%llu process=%lu thread=%lu "
        "function_rva=0x%llx function_end_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length
    );
    for (index = 0; index < length && offset + 2 < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void capture_inbound_reader_function(
    const char *kind,
    uintptr_t target_rva
) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t available;
    BYTE *start;
    unsigned int length;
    char line[4352];
    size_t offset;
    unsigned int index;

    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + target_rva),
        &image_base,
        NULL
    );
    if (
        function_entry == NULL ||
        image_base != (DWORD64)(uintptr_t)g_game_base
    ) {
        return;
    }
    function_rva = (uintptr_t)function_entry->BeginAddress;
    function_end_rva = (uintptr_t)function_entry->EndAddress;
    if (
        function_rva >= function_end_rva ||
        function_end_rva > g_game_size
    ) {
        log_dispatch_status(
            "INBOUND_READER_CODE_ERROR",
            "invalid-function-range"
        );
        return;
    }
    available = function_end_rva - function_rva;
    length = available > ISAC_MAX_INBOUND_READER_CODE_BYTES
        ? ISAC_MAX_INBOUND_READER_CODE_BYTES
        : (unsigned int)available;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "INBOUND_READER_CODE_ERROR",
            "function-window-unreadable"
        );
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_READER_CODE tick_ms=%llu process=%lu thread=%lu "
        "kind=%s target_rva=0x%llx function_rva=0x%llx "
        "function_end_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        kind,
        (unsigned long long)target_rva,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length
    );
    for (index = 0; index < length && offset + 2 < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void capture_inbound_reader_forward_window(
    const char *kind,
    uintptr_t target_rva
) {
    BYTE *start;
    unsigned int length = ISAC_INBOUND_READER_FORWARD_BYTES;
    char line[2304];
    size_t offset;
    unsigned int index;

    if (
        target_rva >= g_game_size ||
        length > g_game_size - target_rva
    ) {
        log_dispatch_status(
            "INBOUND_READER_CODE_ERROR",
            "forward-window-outside-image"
        );
        return;
    }
    start = g_game_base + target_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "INBOUND_READER_CODE_ERROR",
            "forward-window-unreadable"
        );
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_READER_FORWARD_CODE tick_ms=%llu process=%lu thread=%lu "
        "kind=%s target_rva=0x%llx start_rva=0x%llx "
        "length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        kind,
        (unsigned long long)target_rva,
        (unsigned long long)target_rva,
        length
    );
    for (index = 0; index < length && offset + 2 < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void capture_inbound_reader_functions(void) {
    if (
        InterlockedCompareExchange(
            &g_inbound_reader_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    capture_inbound_reader_forward_window("read-next", 0x111d640u);
    capture_inbound_reader_forward_window("context-init", 0x22378c0u);
    capture_inbound_reader_function("read-next", 0x111d640u);
    capture_inbound_reader_function("context-init", 0x22378c0u);
}

static USHORT unwind_queue_producer_callers(
    const CONTEXT *context,
    uintptr_t *rvas,
    USHORT capacity,
    uintptr_t *function_rva,
    uintptr_t *function_end_rva
) {
    CONTEXT unwind_context = *context;
    USHORT depth = 0;
    unsigned int iteration;

    *function_rva = 0;
    *function_end_rva = 0;
    for (iteration = 0; iteration < 32u && depth < capacity; ++iteration) {
        DWORD64 image_base = 0;
        DWORD64 previous_rip = unwind_context.Rip;
        DWORD64 previous_rsp = unwind_context.Rsp;
        PRUNTIME_FUNCTION function_entry = RtlLookupFunctionEntry(
            unwind_context.Rip,
            &image_base,
            NULL
        );

        if (iteration == 0 && function_entry != NULL) {
            *function_rva = (uintptr_t)function_entry->BeginAddress;
            *function_end_rva = (uintptr_t)function_entry->EndAddress;
        }
        if (function_entry != NULL) {
            PVOID handler_data = NULL;
            DWORD64 establisher_frame = 0;

            RtlVirtualUnwind(
                UNW_FLAG_NHANDLER,
                image_base,
                unwind_context.Rip,
                function_entry,
                &unwind_context,
                &handler_data,
                &establisher_frame,
                NULL
            );
        } else {
            if (!readable_memory_window(
                    (const void *)(uintptr_t)unwind_context.Rsp,
                    sizeof(DWORD64)
                )) {
                break;
            }
            unwind_context.Rip = *(DWORD64 *)(uintptr_t)unwind_context.Rsp;
            unwind_context.Rsp += sizeof(DWORD64);
        }
        if (
            unwind_context.Rip == 0 ||
            (
                unwind_context.Rip == previous_rip &&
                unwind_context.Rsp == previous_rsp
            )
        ) {
            break;
        }
        if (
            unwind_context.Rip >= (DWORD64)(uintptr_t)g_game_base &&
            unwind_context.Rip <
                (DWORD64)(uintptr_t)(g_game_base + g_game_size)
        ) {
            rvas[depth++] = (uintptr_t)(
                unwind_context.Rip - (DWORD64)(uintptr_t)g_game_base
            );
        }
    }
    return depth;
}

static BOOL socket_peer_is_loopback_port(
    SOCKET socket_handle,
    unsigned int expected
) {
    struct sockaddr_storage address;
    int address_length = (int)sizeof(address);
    const unsigned char *port_bytes;
    const unsigned char *address_bytes;
    unsigned int port;
    BOOL loopback = FALSE;
    unsigned int index;

    if (
        g_getpeername == NULL ||
        g_getpeername(
            socket_handle,
            (struct sockaddr *)&address,
            &address_length
        ) != 0
    ) {
        return FALSE;
    }
    if (address.ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 =
            (const struct sockaddr_in *)&address;
        port_bytes = (const unsigned char *)&ipv4->sin_port;
        address_bytes = (const unsigned char *)&ipv4->sin_addr;
        loopback = address_bytes[0] == 127u;
    } else if (address.ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 =
            (const struct sockaddr_in6 *)&address;
        port_bytes = (const unsigned char *)&ipv6->sin6_port;
        address_bytes = (const unsigned char *)&ipv6->sin6_addr;
        loopback = address_bytes[15] == 1u;
        for (index = 0u; index < 15u && loopback; ++index) {
            if (address_bytes[index] != 0u) {
                loopback = FALSE;
            }
        }
    } else {
        return FALSE;
    }
    port = ((unsigned int)port_bytes[0] << 8) | port_bytes[1];
    return loopback && port == expected;
}

static BOOL socket_peer_is_port(SOCKET socket_handle, unsigned int expected) {
    struct sockaddr_storage address;
    int address_length = (int)sizeof(address);
    const unsigned char *port_bytes;
    unsigned int port;

    if (
        g_getpeername == NULL ||
        g_getpeername(
            socket_handle,
            (struct sockaddr *)&address,
            &address_length
        ) != 0
    ) {
        return FALSE;
    }
    if (address.ss_family == AF_INET) {
        port_bytes = (const unsigned char *)(
            &((const struct sockaddr_in *)&address)->sin_port
        );
    } else if (address.ss_family == AF_INET6) {
        port_bytes = (const unsigned char *)(
            &((const struct sockaddr_in6 *)&address)->sin6_port
        );
    } else {
        return FALSE;
    }
    port = ((unsigned int)port_bytes[0] << 8) | port_bytes[1];
    return port == expected;
}

static BOOL arm_tctd_local_acceptance(
    DWORD received_bytes,
    DWORD buffer_count,
    DWORD buffer_index,
    DWORD marker_offset
) {
    CONTEXT context;
    const BYTE *target = g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA;
    char detail[256];

    if (
        InterlockedCompareExchange(&g_tctd_local_accept_applied, 0, 0) >= 256 ||
        InterlockedCompareExchange(&g_tctd_local_accept_armed, 1, 0) != 0
    ) {
        return FALSE;
    }
    if (
        !readable_code_window(
            target,
            sizeof(g_tctd_local_accept_signature)
        ) ||
        memcmp(
            target,
            g_tctd_local_accept_signature,
            sizeof(g_tctd_local_accept_signature)
        ) != 0
    ) {
        InterlockedExchange(&g_tctd_local_accept_armed, 0);
        log_status(
            "TCTD_LOCAL_ACCEPT_ERROR",
            "verifier-return-signature-mismatch,breakpoint=disabled"
        );
        return FALSE;
    }
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_local_accept_armed, 0);
        log_status("TCTD_LOCAL_ACCEPT_ERROR", "arm-get-thread-context");
        return FALSE;
    }
    context.Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA
    );
    context.Dr6 = 0;
    context.Dr7 =
        (context.Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x1u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_local_accept_armed, 0);
        log_status("TCTD_LOCAL_ACCEPT_ERROR", "arm-set-thread-context");
        return FALSE;
    }
    snprintf(
        detail,
        sizeof(detail),
        "received=%lu,buffer-count=%lu,buffer-index=%lu,"
        "marker-offset=%lu,target-rva=0x%llx,slot=dr0,mode=execute,"
        "scope=loopback-port-27015,payloads=disabled",
        (unsigned long)received_bytes,
        (unsigned long)buffer_count,
        (unsigned long)buffer_index,
        (unsigned long)marker_offset,
        (unsigned long long)ISAC_TCTD_LOCAL_ACCEPT_RVA
    );
    log_status("TCTD_LOCAL_ACCEPT_ARMED", detail);
    return TRUE;
}

static BOOL arm_tctd_state_watch_decision(
    DWORD received_bytes,
    DWORD buffer_count,
    DWORD buffer_index,
    DWORD marker_offset
) {
    CONTEXT context;
    char detail[256];

    if (
        InterlockedCompareExchange(&g_tctd_state_watch_stage, 1, 0) != 0
    ) {
        return FALSE;
    }
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_state_watch_stage, 0);
        log_status("TCTD_STATE_WATCH_ERROR", "arm-get-thread-context");
        return FALSE;
    }
    context.Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_COMPLETION_DECISION_RVA
    );
    context.Dr6 = 0;
    context.Dr7 =
        (context.Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x1u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_state_watch_stage, 0);
        log_status("TCTD_STATE_WATCH_ERROR", "arm-set-thread-context");
        return FALSE;
    }
    snprintf(
        detail,
        sizeof(detail),
        "received=%lu,buffer-count=%lu,buffer-index=%lu,"
        "marker-offset=%lu,target-rva=0x%llx,slot=dr0,mode=execute,"
        "next=one-byte-write-watch,mutation=disabled,payloads=disabled",
        (unsigned long)received_bytes,
        (unsigned long)buffer_count,
        (unsigned long)buffer_index,
        (unsigned long)marker_offset,
        (unsigned long long)ISAC_TCTD_COMPLETION_DECISION_RVA
    );
    log_status("TCTD_STATE_WATCH_ARMED", detail);
    return TRUE;
}

static BOOL arm_tctd_owner_watch_decision(
    DWORD received_bytes,
    DWORD buffer_count,
    DWORD buffer_index,
    DWORD marker_offset
) {
    CONTEXT context;
    char detail[256];

    if (InterlockedCompareExchange(&g_tctd_owner_watch_stage, 0, 0) == 1) {
        return FALSE;
    }
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        log_status("TCTD_OWNER_WATCH_ERROR", "arm-get-thread-context");
        return FALSE;
    }
    context.Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_COMPLETION_DECISION_RVA
    );
    context.Dr6 = 0;
    context.Dr7 = (context.Dr7 & ~(DWORD64)0x000f0003u) | (DWORD64)0x1u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        log_status("TCTD_OWNER_WATCH_ERROR", "arm-set-thread-context");
        return FALSE;
    }
    InterlockedExchange(&g_tctd_owner_watch_stage, 1);
    snprintf(
        detail,
        sizeof(detail),
        "received=%lu,buffer-count=%lu,buffer-index=%lu,"
        "marker-offset=%lu,target-rva=0x%llx,decision-slot=dr0,"
        "owner-field-slot=dr1,state-slot=dr2,mutation=disabled,"
        "payloads=disabled",
        (unsigned long)received_bytes,
        (unsigned long)buffer_count,
        (unsigned long)buffer_index,
        (unsigned long)marker_offset,
        (unsigned long long)ISAC_TCTD_COMPLETION_DECISION_RVA
    );
    log_status("TCTD_OWNER_WATCH_ARMED", detail);
    return TRUE;
}

static BOOL arm_tctd_completion_probe(
    DWORD received_bytes,
    DWORD buffer_count,
    DWORD buffer_index,
    DWORD marker_offset
) {
    CONTEXT context;
    char detail[320];

    if (InterlockedCompareExchange(&g_tctd_completion_armed, 1, 0) != 0) {
        return FALSE;
    }
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_completion_armed, 0);
        log_status(
            "TCTD_COMPLETION_PROBE_ERROR",
            "arm-get-thread-context"
        );
        return FALSE;
    }
    capture_tctd_completion_code();
    context.Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_COMPLETION_ENTRY_RVA
    );
    context.Dr1 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_VALIDATOR_SUCCESS_RESUME_RVA
    );
    context.Dr2 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_COMPLETION_RETURN_RVA
    );
    context.Dr6 = 0;
    context.Dr7 =
        (context.Dr7 & ~(DWORD64)0x0fff003fu) |
        (DWORD64)0x15u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_completion_armed, 0);
        log_status(
            "TCTD_COMPLETION_PROBE_ERROR",
            "arm-set-thread-context"
        );
        return FALSE;
    }
    snprintf(
        detail,
        sizeof(detail),
        "received=%lu,buffer-count=%lu,buffer-index=%lu,"
        "marker-offset=%lu,entry-rva=0x%llx,entry-slot=dr0,"
        "setter-resume-rva=0x%llx,setter-slot=dr1,return-rva=0x%llx,"
        "return-slot=dr2,scope=%s,mutation=disabled,payloads=disabled",
        (unsigned long)received_bytes,
        (unsigned long)buffer_count,
        (unsigned long)buffer_index,
        (unsigned long)marker_offset,
        (unsigned long long)ISAC_TCTD_COMPLETION_ENTRY_RVA,
        (unsigned long long)ISAC_TCTD_VALIDATOR_SUCCESS_RESUME_RVA,
        (unsigned long long)ISAC_TCTD_COMPLETION_RETURN_RVA,
        g_tctd_completion_remote_requested
            ? "remote-port-27015"
            : "loopback-port-27015"
    );
    log_status("TCTD_COMPLETION_PROBE_ARMED", detail);
    return TRUE;
}

static BOOL arm_tctd_branch_probe(
    DWORD received_bytes,
    DWORD buffer_count,
    DWORD buffer_index,
    DWORD marker_offset
) {
    CONTEXT context;
    char detail[384];

    if (InterlockedCompareExchange(&g_tctd_branch_armed, 1, 0) != 0) {
        return FALSE;
    }
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_branch_armed, 0);
        log_status("TCTD_BRANCH_PROBE_ERROR", "arm-get-thread-context");
        return FALSE;
    }
    context.Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_BRANCH_READY_RVA
    );
    context.Dr1 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_BRANCH_STATUS_READY_RVA
    );
    context.Dr2 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_BRANCH_STATUS_RVA
    );
    context.Dr3 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_BRANCH_FINAL_RVA
    );
    context.Dr6 = 0;
    context.Dr7 =
        (context.Dr7 & ~(DWORD64)0xffff00ffu) |
        (DWORD64)0x55u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_branch_armed, 0);
        log_status("TCTD_BRANCH_PROBE_ERROR", "arm-set-thread-context");
        return FALSE;
    }
    snprintf(
        detail,
        sizeof(detail),
        "received=%lu,buffer-count=%lu,buffer-index=%lu,"
        "marker-offset=%lu,ready-rva=0x%llx/"
        "dr0,status-ready-rva=0x%llx/dr1,status-rva=0x%llx/dr2,"
        "final-rva=0x%llx/dr3,scope=%s,max-events=256,"
        "mutation=disabled,payloads=disabled",
        (unsigned long)received_bytes,
        (unsigned long)buffer_count,
        (unsigned long)buffer_index,
        (unsigned long)marker_offset,
        (unsigned long long)ISAC_TCTD_BRANCH_READY_RVA,
        (unsigned long long)ISAC_TCTD_BRANCH_STATUS_READY_RVA,
        (unsigned long long)ISAC_TCTD_BRANCH_STATUS_RVA,
        (unsigned long long)ISAC_TCTD_BRANCH_FINAL_RVA,
        g_tctd_branch_remote_requested
            ? "remote-port-27015"
            : "loopback-port-27015"
    );
    log_status("TCTD_BRANCH_PROBE_ARMED", detail);
    return TRUE;
}

static BOOL arm_tctd_certificate_watch(
    const BYTE *public_key,
    DWORD received_bytes,
    DWORD buffer_count,
    DWORD buffer_index,
    DWORD marker_offset
) {
    CONTEXT context;
    uintptr_t aligned_address;
    char detail[256];

    if (
        InterlockedCompareExchange(
            &g_tctd_certificate_watch_armed,
            1,
            0
        ) != 0
    ) {
        return FALSE;
    }
    aligned_address = (uintptr_t)public_key & ~(uintptr_t)7u;
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_certificate_watch_armed, 0);
        log_status("TCTD_CERT_PROBE_ERROR", "watch-get-thread-context");
        return FALSE;
    }
    capture_tctd_validation_code();
    capture_tctd_chain_code();
    capture_tctd_cert_flow_decision_code();
    dump_tctd_runtime_text();
    context.Dr0 = (DWORD64)aligned_address;
    context.Dr6 = 0;
    context.Dr7 =
        (context.Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x000b0001u;
    if (!SetThreadContext(GetCurrentThread(), &context)) {
        InterlockedExchange(&g_tctd_certificate_watch_armed, 0);
        log_status("TCTD_CERT_PROBE_ERROR", "watch-set-thread-context");
        return FALSE;
    }
    snprintf(
        detail,
        sizeof(detail),
        "received=%lu,buffer-count=%lu,buffer-index=%lu,"
        "marker-offset=%lu,alignment-backoff=%lu,watch-bytes=8,"
        "access=read-write,validation-checkpoints=%s,"
        "chain-checkpoints=%s,payloads=disabled",
        (unsigned long)received_bytes,
        (unsigned long)buffer_count,
        (unsigned long)buffer_index,
        (unsigned long)marker_offset,
        (unsigned long)((uintptr_t)public_key - aligned_address),
        g_tctd_validation_probe_enabled ? "enabled" : "disabled",
        g_tctd_chain_probe_enabled ? "enabled" : "disabled"
    );
    log_status("TCTD_CERT_WATCH_ARMED", detail);
    return TRUE;
}

static void inspect_tctd_certificate_receive(
    SOCKET socket_handle,
    const WSABUF *buffers,
    DWORD buffer_count,
    DWORD received_bytes
) {
    static const BYTE ec_public_key_prefix[] = {
        0x30u, 0x59u, 0x30u, 0x13u, 0x06u, 0x07u, 0x2au,
        0x86u, 0x48u, 0xceu, 0x3du, 0x02u, 0x01u, 0x06u,
        0x08u, 0x2au, 0x86u, 0x48u, 0xceu, 0x3du, 0x03u,
        0x01u, 0x07u, 0x03u, 0x42u, 0x00u, 0x04u
    };
    DWORD remaining = received_bytes;
    DWORD index;

    if (
        (
            !g_tctd_certificate_probe_enabled &&
            !g_tctd_local_accept_enabled &&
            !g_tctd_validator_code_enabled &&
            !g_tctd_state_watch_enabled &&
            !g_tctd_owner_watch_enabled &&
            !g_tctd_completion_probe_enabled &&
            !g_tctd_branch_probe_enabled
        ) ||
        (
            g_tctd_certificate_probe_enabled &&
            InterlockedCompareExchange(
                &g_tctd_certificate_watch_armed,
                0,
                0
            ) != 0
        ) ||
        (
            g_tctd_local_accept_enabled &&
            (
                InterlockedCompareExchange(
                    &g_tctd_local_accept_armed,
                    0,
                    0
                ) != 0 ||
                InterlockedCompareExchange(
                    &g_tctd_local_accept_applied,
                    0,
                    0
                ) >= 256
            )
        ) ||
        (
            g_tctd_validator_code_enabled &&
            InterlockedCompareExchange(
                &g_tctd_validator_code_captured,
                0,
                0
            ) != 0
        ) ||
        (
            g_tctd_state_watch_enabled &&
            InterlockedCompareExchange(
                &g_tctd_state_watch_stage,
                0,
                0
            ) != 0
        ) ||
        (
            g_tctd_completion_probe_enabled &&
            InterlockedCompareExchange(
                &g_tctd_completion_armed,
                0,
                0
            ) != 0
        ) ||
        (
            g_tctd_branch_probe_enabled &&
            InterlockedCompareExchange(&g_tctd_branch_armed, 0, 0) != 0
        ) ||
        buffers == NULL ||
        buffer_count == 0u ||
        buffer_count > 64u ||
        received_bytes == 0u ||
        !(
            (
                (
                    g_tctd_owner_watch_enabled &&
                    g_tctd_owner_remote_requested
                ) ||
                g_tctd_validation_remote_requested ||
                g_tctd_completion_remote_requested ||
                g_tctd_branch_remote_requested ||
                g_tctd_chain_remote_requested ||
                g_tctd_cert_flow_remote_requested
            )
                ? socket_peer_is_port(socket_handle, 27015u)
                : socket_peer_is_loopback_port(socket_handle, 27015u)
        ) ||
        !readable_memory_window(
            buffers,
            (SIZE_T)buffer_count * sizeof(*buffers)
        )
    ) {
        return;
    }
    for (index = 0u; index < buffer_count && remaining != 0u; ++index) {
        const BYTE *data = (const BYTE *)buffers[index].buf;
        DWORD length = buffers[index].len < remaining
            ? buffers[index].len
            : remaining;
        DWORD offset;

        if (
            data != NULL &&
            length >= (DWORD)sizeof(ec_public_key_prefix) &&
            readable_memory_window(data, length)
        ) {
            for (
                offset = 0u;
                offset + sizeof(ec_public_key_prefix) <= length;
                ++offset
            ) {
                if (
                    memcmp(
                        data + offset,
                        ec_public_key_prefix,
                        sizeof(ec_public_key_prefix)
                    ) == 0
                ) {
                    if (g_tctd_local_accept_enabled) {
                        arm_tctd_local_acceptance(
                            received_bytes,
                            buffer_count,
                            index,
                            offset
                        );
                    } else if (g_tctd_validator_code_enabled) {
                        capture_tctd_validator_body();
                    } else if (g_tctd_state_watch_enabled) {
                        arm_tctd_state_watch_decision(
                            received_bytes,
                            buffer_count,
                            index,
                            offset
                        );
                    } else if (g_tctd_owner_watch_enabled) {
                        arm_tctd_owner_watch_decision(
                            received_bytes,
                            buffer_count,
                            index,
                            offset
                        );
                    } else if (g_tctd_completion_probe_enabled) {
                        arm_tctd_completion_probe(
                            received_bytes,
                            buffer_count,
                            index,
                            offset
                        );
                    } else if (g_tctd_branch_probe_enabled) {
                        arm_tctd_branch_probe(
                            received_bytes,
                            buffer_count,
                            index,
                            offset
                        );
                    } else {
                        arm_tctd_certificate_watch(
                            data + offset + sizeof(ec_public_key_prefix) - 1u,
                            received_bytes,
                            buffer_count,
                            index,
                            offset
                        );
                    }
                    return;
                }
            }
        }
        remaining -= length;
    }
}

static void stage_tctd_validation_checkpoint(
    CONTEXT *context,
    LONG stage
) {
    uintptr_t target_rva = tctd_validation_checkpoint_rva(stage);
    const char *checkpoint = tctd_validation_checkpoint_name(stage);
    char detail[160];

    if (target_rva == 0u || checkpoint == NULL) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_validation_stage, 0);
        log_status(
            "TCTD_VALIDATION_COMPLETE",
            "staged-checkpoints=5,payloads=disabled"
        );
        return;
    }
    context->Dr0 = (DWORD64)(uintptr_t)(g_game_base + target_rva);
    context->Dr6 = 0;
    context->Dr7 =
        (context->Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x1u;
    InterlockedExchange(&g_tctd_validation_stage, stage);
    snprintf(
        detail,
        sizeof(detail),
        "stage=%ld,checkpoint=%s,target-rva=0x%llx,slot=dr0,"
        "mode=execute,payloads=disabled",
        stage,
        checkpoint,
        (unsigned long long)target_rva
    );
    log_status("TCTD_VALIDATION_STAGE", detail);
}

static void stage_tctd_chain_checkpoint(CONTEXT *context, LONG stage) {
    uintptr_t target_rva = tctd_chain_checkpoint_rva(stage);
    const char *checkpoint = tctd_chain_checkpoint_name(stage);
    char detail[192];

    if (target_rva == 0u || checkpoint == NULL) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_chain_stage, 0);
        if (
            InterlockedCompareExchange(
                &g_tctd_chain_complete_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_CHAIN_COMPLETE",
                "staged-checkpoints=6,mutation=disabled,payloads=disabled"
            );
        }
        return;
    }
    context->Dr0 = (DWORD64)(uintptr_t)(g_game_base + target_rva);
    context->Dr6 = 0;
    context->Dr7 =
        (context->Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x1u;
    InterlockedExchange(&g_tctd_chain_stage, stage);
    snprintf(
        detail,
        sizeof(detail),
        "stage=%ld,checkpoint=%s,target-rva=0x%llx,slot=dr0,"
        "mode=execute,mutation=disabled,payloads=disabled",
        stage,
        checkpoint,
        (unsigned long long)target_rva
    );
    log_status("TCTD_CHAIN_STAGE", detail);
}

static void arm_tctd_parser_call(CONTEXT *context) {
    char detail[160];

    if (InterlockedCompareExchange(&g_tctd_parser_code_armed, 1, 0) != 0) {
        return;
    }
    context->Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_TCTD_PARSER_CALL_RVA
    );
    context->Dr6 = 0;
    context->Dr7 =
        (context->Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x1u;
    snprintf(
        detail,
        sizeof(detail),
        "call-rva=0x%llx,slot=dr0,mode=execute,"
        "mutation=disabled,payloads=disabled",
        (unsigned long long)ISAC_TCTD_PARSER_CALL_RVA
    );
    log_status("TCTD_PARSER_CODE_STAGE", detail);
}

static void record_tctd_certificate_read(CONTEXT *context) {
    uintptr_t rvas[ISAC_TCTD_CERT_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT index;
    LONG sequence;
    BOOL instruction_in_game;
    char detail[300];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_certificate_read_count);
    if (sequence > ISAC_MAX_TCTD_CERT_READ_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_tctd_certificate_read_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_CERT_READ_LIMIT",
                "event-capacity-reached,max-events=64,watch=disabled"
            );
        }
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_CERT_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    instruction_in_game =
        context->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        context->Rip < (DWORD64)(uintptr_t)(g_game_base + g_game_size);
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,instruction-rva=%s",
        sequence,
        instruction_in_game ? "set" : "outside-game"
    );
    if (instruction_in_game && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",instruction=0x%llx",
            (unsigned long long)(
                context->Rip - (DWORD64)(uintptr_t)g_game_base
            )
        );
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",caller-count=%u,caller-rvas=",
            (unsigned int)depth
        );
    }
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",payloads=disabled"
        );
    }
    log_status("TCTD_CERT_READ", detail);
    if (
        g_tctd_validation_probe_enabled &&
        instruction_in_game &&
        (
            g_tctd_validation_remote_requested ||
            context->Rip - (DWORD64)(uintptr_t)g_game_base ==
                ISAC_TCTD_KEY_READ_RVA
        ) &&
        InterlockedCompareExchange(&g_tctd_validation_stage, 0, 0) == 0
    ) {
        stage_tctd_validation_checkpoint(context, 1);
    }
    if (
        g_tctd_chain_probe_enabled &&
        instruction_in_game &&
        context->Rip - (DWORD64)(uintptr_t)g_game_base ==
            ISAC_TCTD_CHAIN_KEY_COPY_RVA &&
        InterlockedCompareExchange(&g_tctd_chain_stage, 0, 0) == 0
    ) {
        stage_tctd_chain_checkpoint(context, 1);
    }
    if (
        g_tctd_parser_code_enabled &&
        instruction_in_game &&
        context->Rip - (DWORD64)(uintptr_t)g_game_base ==
            ISAC_TCTD_CHAIN_KEY_COPY_RVA &&
        InterlockedCompareExchange(&g_tctd_parser_code_armed, 0, 0) == 0
    ) {
        arm_tctd_parser_call(context);
    }
    if (sequence == ISAC_MAX_TCTD_CERT_READ_EVENTS) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        log_status(
            "TCTD_CERT_READ_LIMIT",
            "event-capacity-reached,max-events=64,watch=disabled"
        );
        InterlockedExchange(&g_tctd_certificate_read_limit_logged, 1);
    }
}

static void record_tctd_certificate_flow(CONTEXT *context) {
    uintptr_t rvas[ISAC_TCTD_CERT_CALLER_FRAMES];
    uintptr_t function_rva = 0u;
    uintptr_t function_end_rva = 0u;
    uintptr_t instruction_rva = 0u;
    uintptr_t watched_address = (uintptr_t)context->Dr0;
    uintptr_t source_address = 0u;
    uintptr_t destination_address = 0u;
    uintptr_t followed_address = 0u;
    uintptr_t relative_offset = 0u;
    DWORD64 copy_length = 0u;
    USHORT depth;
    USHORT index;
    LONG sequence;
    LONG generation;
    BOOL instruction_in_game;
    BOOL followed = FALSE;
    const char *access = "consumer";
    const char *action = "retained";
    char detail[448];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_cert_flow_event_count);
    if (sequence > ISAC_MAX_TCTD_CERT_FLOW_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_tctd_cert_flow_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_CERT_FLOW_LIMIT",
                "event-capacity-reached,max-events=256,watch=disabled"
            );
        }
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        return;
    }
    instruction_in_game =
        context->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        context->Rip < (DWORD64)(uintptr_t)(g_game_base + g_game_size);
    if (instruction_in_game) {
        instruction_rva = (uintptr_t)(
            context->Rip - (DWORD64)(uintptr_t)g_game_base
        );
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_CERT_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    if (
        instruction_in_game &&
        (
            function_rva >= g_game_size ||
            function_end_rva <= function_rva ||
            instruction_rva < function_rva ||
            instruction_rva >= function_end_rva
        )
    ) {
        function_rva = instruction_rva;
        function_end_rva = instruction_rva;
    }

    /*
     * At the game's REP MOVSB, R10/R11/R8 retain the original source,
     * destination, and byte count. Following the corresponding destination
     * keeps the watch on the same eight certificate bytes without recording
     * their contents.
     */
    if (instruction_in_game && instruction_rva == ISAC_TCTD_CHAIN_KEY_COPY_RVA) {
        source_address = (uintptr_t)context->R10;
        destination_address = (uintptr_t)context->R11;
        copy_length = context->R8;
        if (
            copy_length != 0u &&
            copy_length <= (DWORD64)SIZE_MAX &&
            source_address <= UINTPTR_MAX - (uintptr_t)copy_length &&
            watched_address >= source_address &&
            watched_address < source_address + (uintptr_t)copy_length
        ) {
            relative_offset = watched_address - source_address;
            if (destination_address <= UINTPTR_MAX - relative_offset) {
                followed_address = (
                    destination_address + relative_offset
                ) & ~(uintptr_t)7u;
            }
            access = "copy-source";
            if (
                followed_address != 0u &&
                followed_address != watched_address
            ) {
                context->Dr0 = (DWORD64)followed_address;
                generation = InterlockedIncrement(
                    &g_tctd_cert_flow_generation
                );
                followed = TRUE;
                action = "followed";
            }
        } else if (
            copy_length != 0u &&
            copy_length <= (DWORD64)SIZE_MAX &&
            destination_address <= UINTPTR_MAX - (uintptr_t)copy_length &&
            watched_address >= destination_address &&
            watched_address < destination_address + (uintptr_t)copy_length
        ) {
            relative_offset = watched_address - destination_address;
            access = "copy-destination";
        }
    }
    if (!followed) {
        generation = InterlockedCompareExchange(
            &g_tctd_cert_flow_generation,
            0,
            0
        );
    }
    if (instruction_in_game && strcmp(access, "consumer") == 0) {
        capture_tctd_cert_flow_consumer(
            instruction_rva,
            function_rva,
            function_end_rva
        );
    }

    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,generation=%ld,instruction-rva=%s",
        sequence,
        generation,
        instruction_in_game ? "set" : "outside-game"
    );
    if (instruction_in_game && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",instruction=0x%llx",
            (unsigned long long)instruction_rva
        );
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",access=%s,action=%s,copy-relative-offset=",
            access,
            action
        );
    }
    if (offset < sizeof(detail)) {
        if (strcmp(access, "consumer") != 0) {
            offset += (size_t)snprintf(
                detail + offset,
                sizeof(detail) - offset,
                "%llu,copy-length=%llu",
                (unsigned long long)relative_offset,
                (unsigned long long)copy_length
            );
        } else {
            offset += (size_t)snprintf(
                detail + offset,
                sizeof(detail) - offset,
                "none,copy-length=none"
            );
        }
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",consumer-rva="
        );
    }
    if (offset < sizeof(detail)) {
        if (instruction_in_game && strcmp(access, "consumer") == 0) {
            offset += (size_t)snprintf(
                detail + offset,
                sizeof(detail) - offset,
                "0x%llx",
                (unsigned long long)function_rva
            );
        } else {
            offset += (size_t)snprintf(
                detail + offset,
                sizeof(detail) - offset,
                "none"
            );
        }
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",caller-count=%u,caller-rvas=",
            (unsigned int)depth
        );
    }
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",payloads=disabled"
        );
    }
    log_status("TCTD_CERT_FLOW", detail);
    if (sequence == ISAC_MAX_TCTD_CERT_FLOW_EVENTS) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        log_status(
            "TCTD_CERT_FLOW_LIMIT",
            "event-capacity-reached,max-events=256,watch=disabled"
        );
        InterlockedExchange(&g_tctd_cert_flow_limit_logged, 1);
    }
}

static const char *tctd_validation_value_class(DWORD64 value) {
    if (value == 0u) {
        return "zero";
    }
    if (value <= 0xffu) {
        return "u8";
    }
    if (value <= 0xffffu) {
        return "u16";
    }
    if (value <= 0xffffffffu) {
        return "u32";
    }
    return "wide";
}

static void record_tctd_validation_checkpoint(
    const char *checkpoint,
    CONTEXT *context
) {
    uintptr_t rvas[ISAC_TCTD_VALIDATION_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char detail[384];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_validation_event_count);
    if (sequence > ISAC_MAX_TCTD_VALIDATION_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_tctd_validation_event_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_VALIDATION_LIMIT",
                "event-capacity-reached,max-events=128,checkpoints=disabled"
            );
        }
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_validation_stage, 0);
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_VALIDATION_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,checkpoint=%s,rax-class=%s,rax-low32=0x%08lx,"
        "zf=%u,cf=%u,sf=%u,caller-count=%u,caller-rvas=",
        sequence,
        checkpoint,
        tctd_validation_value_class(context->Rax),
        (unsigned long)(context->Rax & 0xffffffffu),
        (unsigned int)((context->EFlags >> 6) & 1u),
        (unsigned int)(context->EFlags & 1u),
        (unsigned int)((context->EFlags >> 7) & 1u),
        (unsigned int)depth
    );
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",payloads=disabled"
        );
    }
    log_status("TCTD_VALIDATION_CHECKPOINT", detail);
    if (sequence == ISAC_MAX_TCTD_VALIDATION_EVENTS) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_validation_stage, 0);
        log_status(
            "TCTD_VALIDATION_LIMIT",
            "event-capacity-reached,max-events=128,checkpoints=disabled"
        );
        InterlockedExchange(&g_tctd_validation_event_limit_logged, 1);
    }
}

static void record_tctd_chain_checkpoint(
    const char *checkpoint,
    CONTEXT *context
) {
    uintptr_t rvas[ISAC_TCTD_VALIDATION_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char detail[448];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_chain_event_count);
    if (sequence > ISAC_MAX_TCTD_CHAIN_EVENTS) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_chain_stage, 0);
        if (
            InterlockedCompareExchange(
                &g_tctd_chain_complete_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_CHAIN_LIMIT",
                "event-capacity-reached,max-events=32,breakpoint=disabled"
            );
        }
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_VALIDATION_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,checkpoint=%s,rax-class=%s,rax-low32=0x%08lx,"
        "zf=%u,cf=%u,sf=%u,caller-count=%u,caller-rvas=",
        sequence,
        checkpoint,
        tctd_validation_value_class(context->Rax),
        (unsigned long)(context->Rax & 0xffffffffu),
        (unsigned int)((context->EFlags >> 6) & 1u),
        (unsigned int)(context->EFlags & 1u),
        (unsigned int)((context->EFlags >> 7) & 1u),
        (unsigned int)depth
    );
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",mutation=disabled,payloads=disabled"
        );
    }
    log_status("TCTD_CHAIN_CHECKPOINT", detail);
}

static void record_tctd_completion_checkpoint(
    const char *checkpoint,
    BYTE *state,
    CONTEXT *context,
    BOOL final_checkpoint
) {
    uintptr_t rvas[ISAC_TCTD_VALIDATION_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT index;
    LONG sequence;
    BOOL state_readable;
    char detail[448];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_completion_event_count);
    if (sequence > ISAC_MAX_TCTD_COMPLETION_EVENTS) {
        context->Dr0 = 0;
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr7 &= ~(DWORD64)0x0fff003fu;
        if (
            InterlockedCompareExchange(
                &g_tctd_completion_complete_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_COMPLETION_LIMIT",
                "event-capacity-reached,max-events=64,"
                "breakpoints=disabled"
            );
        }
        return;
    }
    state_readable = state != NULL && readable_memory_window(state, 1u);
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_VALIDATION_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,checkpoint=%s,state=%s,state-byte=%s,"
        "rax-class=%s,rax-low32=0x%08lx,zf=%u,cf=%u,sf=%u,"
        "caller-count=%u,caller-rvas=",
        sequence,
        checkpoint,
        state == NULL ? "null" : state_readable ? "readable" : "unreadable",
        state_readable ? (*state == 0u ? "zero" : "nonzero") : "unreadable",
        tctd_validation_value_class(context->Rax),
        (unsigned long)(context->Rax & 0xffffffffu),
        (unsigned int)((context->EFlags >> 6) & 1u),
        (unsigned int)(context->EFlags & 1u),
        (unsigned int)((context->EFlags >> 7) & 1u),
        (unsigned int)depth
    );
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",mutation=disabled,payloads=disabled"
        );
    }
    log_status("TCTD_COMPLETION_CHECKPOINT", detail);
    if (final_checkpoint) {
        context->Dr0 = 0;
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr7 &= ~(DWORD64)0x0fff003fu;
        if (
            InterlockedCompareExchange(
                &g_tctd_completion_complete_logged,
                1,
                0
            ) == 0
        ) {
            snprintf(
                detail,
                sizeof(detail),
                "events=%ld,setter-hits=%ld,breakpoints=disabled,"
                "mutation=disabled,payloads=disabled",
                (long)InterlockedCompareExchange(
                    &g_tctd_completion_event_count,
                    0,
                    0
                ),
                (long)InterlockedCompareExchange(
                    &g_tctd_completion_setter_count,
                    0,
                    0
                )
            );
            log_status("TCTD_COMPLETION_COMPLETE", detail);
        }
    }
}

static void record_tctd_branch_checkpoint(
    const char *checkpoint,
    unsigned int value,
    CONTEXT *context,
    BOOL terminal
) {
    uintptr_t rvas[ISAC_TCTD_VALIDATION_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char detail[448];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_branch_event_count);
    if (sequence > ISAC_MAX_TCTD_BRANCH_EVENTS) {
        context->Dr0 = 0;
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr3 = 0;
        context->Dr7 &= ~(DWORD64)0xffff00ffu;
        if (
            InterlockedCompareExchange(
                &g_tctd_branch_complete_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_BRANCH_LIMIT",
                "event-capacity-reached,max-events=256,"
                "breakpoints=disabled"
            );
        }
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_VALIDATION_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,checkpoint=%s,result=%s,value-low16=0x%04x,"
        "caller-count=%u,caller-rvas=",
        sequence,
        checkpoint,
        value == 0u ? "zero" : "nonzero",
        value & 0xffffu,
        (unsigned int)depth
    );
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",mutation=disabled,payloads=disabled"
        );
    }
    log_status("TCTD_BRANCH_CHECKPOINT", detail);
    if (terminal) {
        context->Dr0 = 0;
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr3 = 0;
        context->Dr7 &= ~(DWORD64)0xffff00ffu;
        if (
            InterlockedCompareExchange(
                &g_tctd_branch_complete_logged,
                1,
                0
            ) == 0
        ) {
            snprintf(
                detail,
                sizeof(detail),
                "events=%ld,outcome=%s-%s,value-low16=0x%04x,"
                "breakpoints=disabled,mutation=disabled,payloads=disabled",
                (long)InterlockedCompareExchange(
                    &g_tctd_branch_event_count,
                    0,
                    0
                ),
                checkpoint,
                value == 0u ? "zero" : "nonzero",
                value & 0xffffu
            );
            log_status("TCTD_BRANCH_COMPLETE", detail);
        }
    }
}

static void apply_tctd_local_acceptance(CONTEXT *context) {
    const DWORD *verification_mode = (const DWORD *)(uintptr_t)(
        context->Rbp + 0x140u
    );
    LONG original = (LONG)(DWORD)context->Rax;
    char detail[256];

    context->Dr0 = 0;
    context->Dr6 = 0;
    context->Dr7 &= ~(DWORD64)0x000f0003u;
    InterlockedExchange(&g_tctd_local_accept_armed, 0);
    if (!readable_memory_window(verification_mode, sizeof(*verification_mode))) {
        log_status(
            "TCTD_LOCAL_ACCEPT_ERROR",
            "verification-mode-not-readable,breakpoint=disabled"
        );
        return;
    }
    InterlockedIncrement(&g_tctd_local_accept_applied);
    if (*verification_mode != 0u && original <= 0) {
        context->Rax = 1u;
        snprintf(
            detail,
            sizeof(detail),
            "original=%ld,replacement=1,verification-mode=%lu,"
            "target-rva=0x%llx,scope=loopback-port-27015,"
            "breakpoint=disabled,payloads=disabled",
            (long)original,
            (unsigned long)*verification_mode,
            (unsigned long long)ISAC_TCTD_LOCAL_ACCEPT_RVA
        );
        log_status("TCTD_LOCAL_ACCEPT_APPLIED", detail);
    } else {
        snprintf(
            detail,
            sizeof(detail),
            "original=%ld,verification-mode=%lu,reason=%s,"
            "target-rva=0x%llx,scope=loopback-port-27015,"
            "breakpoint=disabled,payloads=disabled",
            (long)original,
            (unsigned long)*verification_mode,
            *verification_mode == 0u
                ? "verification-disabled"
                : "already-accepted",
            (unsigned long long)ISAC_TCTD_LOCAL_ACCEPT_RVA
        );
        log_status("TCTD_LOCAL_ACCEPT_SKIPPED", detail);
    }
}

static void begin_tctd_state_write_watch(CONTEXT *context) {
    BYTE *state = (BYTE *)(uintptr_t)context->Rcx;
    char detail[192];

    if (!readable_memory_window(state, 1u)) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_state_watch_stage, 0);
        log_status(
            "TCTD_STATE_WATCH_ERROR",
            "decision-state-not-readable,breakpoint=disabled"
        );
        return;
    }
    InterlockedExchangePointer(
        &g_tctd_state_watch_address,
        (PVOID)state
    );
    context->Dr0 = (DWORD64)(uintptr_t)state;
    context->Dr6 = 0;
    context->Dr7 =
        (context->Dr7 & ~(DWORD64)0x000f0003u) |
        (DWORD64)0x00010001u;
    InterlockedExchange(&g_tctd_state_watch_stage, 2);
    snprintf(
        detail,
        sizeof(detail),
        "decision-rva=0x%llx,current=%s,slot=dr0,watch-bytes=1,"
        "access=write,mutation=disabled,payloads=disabled",
        (unsigned long long)ISAC_TCTD_COMPLETION_DECISION_RVA,
        *state == 0u ? "zero" : "nonzero"
    );
    log_status("TCTD_STATE_WATCH_TARGET", detail);
}

static void record_tctd_state_write(CONTEXT *context) {
    BYTE *state = (BYTE *)InterlockedCompareExchangePointer(
        &g_tctd_state_watch_address,
        NULL,
        NULL
    );
    uintptr_t rvas[ISAC_TCTD_STATE_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t resume_rva = 0u;
    USHORT depth;
    USHORT index;
    LONG sequence;
    BOOL resume_in_game;
    char detail[384];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_state_write_count);
    if (
        sequence > ISAC_MAX_TCTD_STATE_WRITE_EVENTS ||
        state == NULL ||
        !readable_memory_window(state, 1u)
    ) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_state_watch_stage, 0);
        if (
            InterlockedCompareExchange(
                &g_tctd_state_write_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_status(
                "TCTD_STATE_WATCH_LIMIT",
                sequence > ISAC_MAX_TCTD_STATE_WRITE_EVENTS
                    ? "event-capacity-reached,max-events=64,watch=disabled"
                    : "watched-state-unreadable,watch=disabled"
            );
        }
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_STATE_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    resume_in_game =
        context->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        context->Rip < (DWORD64)(uintptr_t)(g_game_base + g_game_size);
    if (resume_in_game) {
        resume_rva = (uintptr_t)(
            context->Rip - (DWORD64)(uintptr_t)g_game_base
        );
    }
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,value-after=%s,resume-rva=%s",
        sequence,
        *state == 0u ? "zero" : "nonzero",
        resume_in_game ? "set" : "outside-game"
    );
    if (resume_in_game && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",resume=0x%llx",
            (unsigned long long)resume_rva
        );
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",caller-count=%u,caller-rvas=",
            (unsigned int)depth
        );
    }
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",mutation=disabled,payloads=disabled"
        );
    }
    log_status("TCTD_STATE_WRITE", detail);
    if (g_code_probe_enabled && resume_in_game && sequence <= 16) {
        char label[48];
        uintptr_t start_rva = resume_rva >= 128u
            ? resume_rva - 128u
            : 0u;
        snprintf(
            label,
            sizeof(label),
            "tctd-state-write-%02ld",
            sequence
        );
        capture_code_window(label, resume_rva, start_rva, 256u);
    }
    if (sequence == ISAC_MAX_TCTD_STATE_WRITE_EVENTS) {
        context->Dr0 = 0;
        context->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_state_watch_stage, 0);
        InterlockedExchange(&g_tctd_state_write_limit_logged, 1);
        log_status(
            "TCTD_STATE_WATCH_LIMIT",
            "event-capacity-reached,max-events=64,watch=disabled"
        );
    }
}

static void disable_tctd_owner_watch(CONTEXT *context) {
    context->Dr0 = 0;
    context->Dr1 = 0;
    context->Dr2 = 0;
    context->Dr6 = 0;
    context->Dr7 &= ~(DWORD64)0x0fff003fu;
    InterlockedExchange(&g_tctd_owner_watch_stage, 0);
}

static void begin_or_refresh_tctd_owner_watch(CONTEXT *context) {
    BYTE *owner = (BYTE *)(uintptr_t)context->Rbx;
    PVOID state = (PVOID)(uintptr_t)context->Rcx;
    PVOID *field;
    PVOID field_value;
    PVOID previous_owner;
    PVOID previous_field;
    PVOID initial_state;
    PVOID previous_state;
    const char *owner_class;
    const char *field_class;
    const char *state_class;
    const char *state_value;
    const char *field_match;
    const char *field_watch;
    const char *state_watch;
    LONG sequence;
    char detail[384];

    sequence = InterlockedIncrement(&g_tctd_owner_decision_count);
    if (sequence > ISAC_MAX_TCTD_OWNER_DECISIONS) {
        disable_tctd_owner_watch(context);
        if (
            InterlockedCompareExchange(&g_tctd_owner_limit_logged, 1, 0) == 0
        ) {
            log_status(
                "TCTD_OWNER_WATCH_LIMIT",
                "decision-capacity-reached,max-events=1024,watch=disabled"
            );
        }
        return;
    }
    context->Dr0 = 0;
    context->Dr7 &= ~(DWORD64)0x000f0003u;
    InterlockedExchange(&g_tctd_owner_watch_stage, 2);
    if (owner == NULL) {
        log_status("TCTD_OWNER_WATCH_ERROR", "decision-owner-null");
        return;
    }
    field = (PVOID *)(owner + 0x40u);
    if (
        ((uintptr_t)field & 0x7u) != 0u ||
        !readable_memory_window(field, sizeof(*field))
    ) {
        log_status(
            "TCTD_OWNER_WATCH_ERROR",
            "decision-owner-field-unreadable-or-unaligned"
        );
        return;
    }
    field_value = *field;
    previous_owner = InterlockedCompareExchangePointer(
        &g_tctd_owner_address,
        NULL,
        NULL
    );
    previous_field = InterlockedCompareExchangePointer(
        &g_tctd_owner_field_address,
        NULL,
        NULL
    );
    initial_state = InterlockedCompareExchangePointer(
        &g_tctd_owner_initial_state_address,
        NULL,
        NULL
    );
    previous_state = InterlockedCompareExchangePointer(
        &g_tctd_owner_state_address,
        NULL,
        NULL
    );
    owner_class = previous_owner == NULL
        ? "first"
        : previous_owner == owner ? "same" : "replaced";
    field_class = previous_field == NULL
        ? "first"
        : previous_field == field ? "same" : "replaced";
    state_class = initial_state == NULL
        ? "initial"
        : initial_state == state
            ? "initial"
            : previous_state == state ? "same" : "replaced";
    field_match = field_value == state ? "yes" : "no";
    state_value = state != NULL && readable_memory_window(state, 1u)
        ? (*(const BYTE *)state == 0u ? "zero" : "nonzero")
        : "unreadable";

    if (initial_state == NULL && state != NULL) {
        InterlockedCompareExchangePointer(
            &g_tctd_owner_initial_state_address,
            state,
            NULL
        );
    }
    InterlockedExchangePointer(&g_tctd_owner_address, owner);
    InterlockedExchangePointer(&g_tctd_owner_field_address, field);
    InterlockedExchangePointer(&g_tctd_owner_state_address, state);

    context->Dr1 = (DWORD64)(uintptr_t)field;
    context->Dr7 =
        (context->Dr7 & ~(DWORD64)0x00f0000cu) |
        (DWORD64)0x00900004u;
    field_watch = "armed";
    if (state != NULL && readable_memory_window(state, 1u)) {
        context->Dr2 = (DWORD64)(uintptr_t)state;
        context->Dr7 =
            (context->Dr7 & ~(DWORD64)0x0f000030u) |
            (DWORD64)0x01000010u;
        state_watch = "armed";
    } else {
        context->Dr2 = 0;
        context->Dr7 &= ~(DWORD64)0x0f000030u;
        state_watch = "unavailable";
    }
    InterlockedExchange(&g_tctd_owner_watch_stage, 2);
    snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,owner=%s,field=%s,state=%s,state-byte=%s,"
        "field-match=%s,field-watch=%s,state-watch=%s,"
        "mutation=disabled,payloads=disabled",
        sequence,
        owner_class,
        field_class,
        state_class,
        state_value,
        field_match,
        field_watch,
        state_watch
    );
    log_status("TCTD_OWNER_DECISION", detail);
}

static void record_tctd_owner_field_write(CONTEXT *context) {
    PVOID *field = (PVOID *)InterlockedCompareExchangePointer(
        &g_tctd_owner_field_address,
        NULL,
        NULL
    );
    PVOID initial_state = InterlockedCompareExchangePointer(
        &g_tctd_owner_initial_state_address,
        NULL,
        NULL
    );
    PVOID previous_state = InterlockedCompareExchangePointer(
        &g_tctd_owner_state_address,
        NULL,
        NULL
    );
    PVOID state;
    const char *state_class;
    const char *state_value;
    uintptr_t rvas[ISAC_TCTD_OWNER_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t resume_rva = 0u;
    USHORT depth;
    USHORT index;
    LONG sequence;
    BOOL resume_in_game;
    char detail[448];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_owner_field_write_count);
    if (
        sequence > ISAC_MAX_TCTD_OWNER_WRITES ||
        field == NULL ||
        !readable_memory_window(field, sizeof(*field))
    ) {
        disable_tctd_owner_watch(context);
        log_status(
            "TCTD_OWNER_WATCH_LIMIT",
            sequence > ISAC_MAX_TCTD_OWNER_WRITES
                ? "field-write-capacity-reached,max-events=128,watch=disabled"
                : "owner-field-unreadable,watch=disabled"
        );
        return;
    }
    state = *field;
    state_class = state == NULL
        ? "null"
        : state == initial_state
            ? "initial"
            : state == previous_state ? "same" : "replaced";
    state_value = state != NULL && readable_memory_window(state, 1u)
        ? (*(const BYTE *)state == 0u ? "zero" : "nonzero")
        : "unreadable";
    InterlockedExchangePointer(&g_tctd_owner_state_address, state);
    if (state != NULL && readable_memory_window(state, 1u)) {
        context->Dr2 = (DWORD64)(uintptr_t)state;
        context->Dr7 =
            (context->Dr7 & ~(DWORD64)0x0f000030u) |
            (DWORD64)0x01000010u;
    } else {
        context->Dr2 = 0;
        context->Dr7 &= ~(DWORD64)0x0f000030u;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_OWNER_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    resume_in_game =
        context->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        context->Rip < (DWORD64)(uintptr_t)(g_game_base + g_game_size);
    if (resume_in_game) {
        resume_rva = (uintptr_t)(
            context->Rip - (DWORD64)(uintptr_t)g_game_base
        );
    }
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,state=%s,state-byte=%s,resume-rva=%s",
        sequence,
        state_class,
        state_value,
        resume_in_game ? "set" : "outside-game"
    );
    if (resume_in_game && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",resume=0x%llx",
            (unsigned long long)resume_rva
        );
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",caller-count=%u,caller-rvas=",
            (unsigned int)depth
        );
    }
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",mutation=disabled,payloads=disabled"
        );
    }
    log_status("TCTD_OWNER_FIELD_WRITE", detail);
    if (g_code_probe_enabled && resume_in_game && sequence <= 16) {
        char label[48];
        uintptr_t start_rva = resume_rva >= 128u
            ? resume_rva - 128u
            : 0u;
        snprintf(label, sizeof(label), "tctd-owner-field-%02ld", sequence);
        capture_code_window(label, resume_rva, start_rva, 256u);
    }
}

static void record_tctd_owner_state_write(CONTEXT *context) {
    PVOID state = InterlockedCompareExchangePointer(
        &g_tctd_owner_state_address,
        NULL,
        NULL
    );
    uintptr_t rvas[ISAC_TCTD_OWNER_CALLER_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t resume_rva = 0u;
    USHORT depth;
    USHORT index;
    LONG sequence;
    BOOL resume_in_game;
    char detail[416];
    size_t offset;

    sequence = InterlockedIncrement(&g_tctd_owner_state_write_count);
    if (
        sequence > ISAC_MAX_TCTD_OWNER_WRITES ||
        state == NULL ||
        !readable_memory_window(state, 1u)
    ) {
        context->Dr2 = 0;
        context->Dr7 &= ~(DWORD64)0x0f000030u;
        log_status(
            "TCTD_OWNER_STATE_LIMIT",
            sequence > ISAC_MAX_TCTD_OWNER_WRITES
                ? "state-write-capacity-reached,max-events=128,state-watch=disabled"
                : "state-unreadable,state-watch=disabled"
        );
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_TCTD_OWNER_CALLER_FRAMES,
        &function_rva,
        &function_end_rva
    );
    resume_in_game =
        context->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        context->Rip < (DWORD64)(uintptr_t)(g_game_base + g_game_size);
    if (resume_in_game) {
        resume_rva = (uintptr_t)(
            context->Rip - (DWORD64)(uintptr_t)g_game_base
        );
    }
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,value-after=%s,resume-rva=%s",
        sequence,
        *(const BYTE *)state == 0u ? "zero" : "nonzero",
        resume_in_game ? "set" : "outside-game"
    );
    if (resume_in_game && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",resume=0x%llx",
            (unsigned long long)resume_rva
        );
    }
    if (offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",caller-count=%u,caller-rvas=",
            (unsigned int)depth
        );
    }
    if (depth == 0u && offset < sizeof(detail)) {
        offset += (size_t)snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "none"
        );
    }
    for (index = 0u; index < depth && offset < sizeof(detail); ++index) {
        int written = snprintf(
            detail + offset,
            sizeof(detail) - offset,
            "%s0x%llx",
            index == 0u ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
            break;
        }
        offset += (size_t)written;
    }
    if (offset < sizeof(detail)) {
        snprintf(
            detail + offset,
            sizeof(detail) - offset,
            ",mutation=disabled,payloads=disabled"
        );
    }
    log_status("TCTD_OWNER_STATE_WRITE", detail);
    if (g_code_probe_enabled && resume_in_game && sequence <= 16) {
        char label[48];
        uintptr_t start_rva = resume_rva >= 128u
            ? resume_rva - 128u
            : 0u;
        snprintf(label, sizeof(label), "tctd-owner-state-%02ld", sequence);
        capture_code_window(label, resume_rva, start_rva, 256u);
    }
}

static void record_inbound_queue_producer(CONTEXT *context) {
    uintptr_t rvas[ISAC_MAX_QUEUE_STACK_CANDIDATES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT type_id = (USHORT)context->Rax;
    DWORD queue_count = 0;
    DWORD queue_capacity = 0;
    LONG count;
    USHORT index;
    char line[768];
    size_t offset;
    BYTE *queue = (BYTE *)(uintptr_t)context->Rbx;

    capture_inbound_reader_functions();

    if (readable_memory_window(queue, 0x14u)) {
        queue_capacity = *(DWORD *)(queue + 0x08u);
        queue_count = *(DWORD *)(queue + 0x10u);
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_MAX_QUEUE_STACK_CANDIDATES,
        &function_rva,
        &function_end_rva
    );
    count = InterlockedIncrement(&g_queue_producer_count);
    if (count > (LONG)ISAC_MAX_QUEUE_PRODUCER_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_queue_producer_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_QUEUE_PRODUCER_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_QUEUE_PRODUCER sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu instruction_rva=0xf843b6 type_id=0x%04x "
        "queue_count=%lu queue_capacity=%lu function_rva=0x%llx "
        "function_end_rva=0x%llx frame_count=%u rvas=",
        count,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long)queue_count,
        (unsigned long)queue_capacity,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            offset = sizeof(line);
            break;
        }
        offset += (size_t)written;
    }
    if (offset + 2 < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_dispatch_log(line);
    }
    capture_queue_producer_function(function_rva, function_end_rva);
    for (index = 0; index < depth; ++index) {
        capture_queue_code_anchor(
            "producer-caller",
            g_game_base + rvas[index],
            rvas[index]
        );
    }
}

static void record_inbound_queue_write(CONTEXT *context) {
    DWORD64 stack_values[ISAC_QUEUE_STACK_SCAN_SLOTS];
    uintptr_t rvas[ISAC_MAX_QUEUE_STACK_CANDIDATES];
    BYTE *instruction = (BYTE *)(uintptr_t)context->Rip;
    uintptr_t instruction_rva;
    USHORT depth = 0;
    unsigned int stack_index;
    USHORT rva_index;
    LONG count;
    LONG signature_index;
    char line[768];
    size_t offset;

    if (
        instruction < g_game_base ||
        instruction >= g_game_base + g_game_size
    ) {
        return;
    }
    instruction_rva = (uintptr_t)(instruction - g_game_base);
    if (readable_memory_window(
            (const void *)(uintptr_t)context->Rsp,
            sizeof(stack_values)
        )) {
        CopyMemory(
            stack_values,
            (const void *)(uintptr_t)context->Rsp,
            sizeof(stack_values)
        );
        for (
            stack_index = 0;
            stack_index < ISAC_QUEUE_STACK_SCAN_SLOTS &&
                depth < ISAC_MAX_QUEUE_STACK_CANDIDATES;
            ++stack_index
        ) {
            BYTE *candidate = (BYTE *)(uintptr_t)stack_values[stack_index];
            uintptr_t candidate_rva;
            BOOL duplicate = FALSE;

            if (
                candidate < g_game_base ||
                candidate >= g_game_base + g_game_size ||
                !readable_code_window(candidate, 1u)
            ) {
                continue;
            }
            candidate_rva = (uintptr_t)(candidate - g_game_base);
            for (rva_index = 0; rva_index < depth; ++rva_index) {
                if (rvas[rva_index] == candidate_rva) {
                    duplicate = TRUE;
                    break;
                }
            }
            if (!duplicate) {
                rvas[depth++] = candidate_rva;
            }
        }
    }

    if (InterlockedCompareExchange(&g_queue_write_lock, 1, 0) != 0) {
        return;
    }
    count = g_queue_write_count;
    for (signature_index = 0; signature_index < count; ++signature_index) {
        isac_queue_write_signature *existing =
            &g_queue_writes[signature_index];
        if (
            existing->instruction_rva == instruction_rva &&
            existing->depth == depth &&
            memcmp(existing->rvas, rvas, depth * sizeof(*rvas)) == 0
        ) {
            InterlockedExchange(&g_queue_write_lock, 0);
            return;
        }
    }
    if (count >= (LONG)ISAC_MAX_QUEUE_WRITE_SIGNATURES) {
        if (
            InterlockedCompareExchange(&g_queue_write_limit_logged, 1, 0) == 0
        ) {
            log_dispatch_status(
                "INBOUND_QUEUE_WRITE_LIMIT",
                "unique-signature-capacity-reached"
            );
        }
        InterlockedExchange(&g_queue_write_lock, 0);
        return;
    }
    g_queue_writes[count].instruction_rva = instruction_rva;
    g_queue_writes[count].depth = depth;
    CopyMemory(g_queue_writes[count].rvas, rvas, depth * sizeof(*rvas));
    g_queue_write_count = count + 1;

    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_QUEUE_WRITE sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu instruction_rva=0x%llx frame_count=%u rvas=",
        count + 1,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)instruction_rva,
        (unsigned int)depth
    );
    for (rva_index = 0; rva_index < depth && offset < sizeof(line); ++rva_index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            rva_index == 0 ? "" : ",",
            (unsigned long long)rvas[rva_index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            offset = sizeof(line);
            break;
        }
        offset += (size_t)written;
    }
    if (offset + 2 < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_dispatch_log(line);
    }
    InterlockedExchange(&g_queue_write_lock, 0);

    capture_queue_code_anchor("writer", instruction, instruction_rva);
    for (rva_index = 0; rva_index < depth; ++rva_index) {
        capture_queue_code_anchor(
            "stack-candidate",
            g_game_base + rvas[rva_index],
            rvas[rva_index]
        );
    }
}

static BOOL decode_dispatch_type_id(
    BYTE *target,
    uintptr_t target_rva,
    uintptr_t *source_rva,
    USHORT *type_id
) {
    int32_t displacement;
    int64_t source_offset;

    /* movzx eax, word ptr [rip+disp32]; ret */
    if (
        target_rva >= g_game_size ||
        8u > g_game_size - target_rva ||
        !readable_code_window(target, 8u) ||
        target[0] != 0x0f ||
        target[1] != 0xb7 ||
        target[2] != 0x05 ||
        target[7] != 0xc3
    ) {
        return FALSE;
    }
    CopyMemory(&displacement, target + 3, sizeof(displacement));
    source_offset = (int64_t)target_rva + 7 + (int64_t)displacement;
    if (
        source_offset < 0 ||
        (uint64_t)source_offset >
            (uint64_t)g_game_size - sizeof(*type_id)
    ) {
        return FALSE;
    }
    *source_rva = (uintptr_t)source_offset;
    if (!readable_memory_window(
            g_game_base + *source_rva,
            sizeof(*type_id)
        )) {
        return FALSE;
    }
    CopyMemory(type_id, g_game_base + *source_rva, sizeof(*type_id));
    return TRUE;
}

static void log_dispatch_type_id(
    uintptr_t target_rva,
    uintptr_t source_rva,
    USHORT type_id
) {
    char line[384];
    int length;

    length = snprintf(
        line,
        sizeof(line),
        "DISPATCH_TYPE_ID tick_ms=%llu process=%lu thread=%lu "
        "target_rva=0x%llx source_rva=0x%llx type_id=0x%04x\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)target_rva,
        (unsigned long long)source_rva,
        (unsigned int)type_id
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
}

static void record_dispatch_event(
    char direction,
    uintptr_t target_rva,
    USHORT type_id
) {
    LONG sequence;
    char line[384];
    int length;
    DWORD written;

    if (!g_dispatch_event_enabled) {
        return;
    }
    sequence = InterlockedIncrement(&g_dispatch_event_count);
    if (sequence > (LONG)ISAC_MAX_DISPATCH_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_dispatch_event_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "DISPATCH_EVENT_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    length = snprintf(
        line,
        sizeof(line),
        "DISPATCH_EVENT sequence=%ld tick_ms=%llu process=%lu thread=%lu "
        "direction=%s target_rva=0x%llx type_id=0x%04x\r\n",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        direction == 'O' ? "outbound" : "inbound",
        (unsigned long long)target_rva,
        (unsigned int)type_id
    );
    if (
        length <= 0 ||
        (size_t)length >= sizeof(line) ||
        !WriteFile(
            g_dispatch_event_file,
            line,
            (DWORD)length,
            &written,
            NULL
        ) ||
        written != (DWORD)length
    ) {
        if (
            InterlockedCompareExchange(
                &g_dispatch_event_write_error_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "DISPATCH_EVENT_ERROR",
                "event-write-failed"
            );
        }
    }
}

static LONG bootstrap_stream_id(char direction, const void *object) {
    LONG count;
    LONG index;
    LONG result = 0;

    if (!g_bootstrap_probe_enabled || object == NULL) {
        return 0;
    }
    if (InterlockedCompareExchange(&g_bootstrap_stream_lock, 1, 0) != 0) {
        return 0;
    }
    count = g_bootstrap_stream_count;
    for (index = 0; index < count; ++index) {
        if (
            g_bootstrap_streams[index].object == object &&
            g_bootstrap_streams[index].direction == direction
        ) {
            result = index + 1;
            break;
        }
    }
    if (
        result == 0 &&
        count < (LONG)ISAC_MAX_BOOTSTRAP_STREAMS
    ) {
        g_bootstrap_streams[count].object = object;
        g_bootstrap_streams[count].direction = direction;
        g_bootstrap_stream_count = count + 1;
        result = count + 1;
    }
    InterlockedExchange(&g_bootstrap_stream_lock, 0);
    return result;
}

static BOOL decode_bootstrap_varuint(
    const BYTE *buffer,
    DWORD length,
    DWORD *offset,
    uint64_t *value
) {
    uint64_t decoded = 0;
    unsigned int shift = 0;
    DWORD index = *offset;
    unsigned int count;

    for (count = 0; count < 10u && index < length; ++count, ++index) {
        BYTE current = buffer[index];

        if (shift == 63u && (current & 0x7eu) != 0) {
            return FALSE;
        }
        decoded |= (uint64_t)(current & 0x7fu) << shift;
        if ((current & 0x80u) == 0) {
            *offset = index + 1u;
            *value = decoded;
            return TRUE;
        }
        shift += 7u;
    }
    return FALSE;
}

static BOOL local_bridge_login_envelope(
    const BYTE *buffer,
    DWORD length
) {
    DWORD offset;
    uint64_t body_length;

    if (
        buffer == NULL ||
        length < 3u ||
        length > ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES ||
        !readable_memory_window(buffer, length) ||
        buffer[0] != 0x03u
    ) {
        return FALSE;
    }
    offset = 2u;
    if (
        !decode_bootstrap_varuint(
            buffer,
            length,
            &offset,
            &body_length
        ) ||
        body_length != (uint64_t)(length - offset)
    ) {
        return FALSE;
    }
    while (offset < length) {
        DWORD frame_end;
        uint64_t encoded_length;
        uint64_t type_id;

        if (
            !decode_bootstrap_varuint(
                buffer,
                length,
                &offset,
                &encoded_length
            ) ||
            (encoded_length & 1u) != 0 ||
            (encoded_length >> 1u) > length - offset
        ) {
            return FALSE;
        }
        frame_end = offset + (DWORD)(encoded_length >> 1u);
        if (
            offset == frame_end ||
            !decode_bootstrap_varuint(
                buffer,
                frame_end,
                &offset,
                &type_id
            )
        ) {
            return FALSE;
        }
        if (type_id == 0x0002u) {
            return TRUE;
        }
        offset = frame_end;
    }
    return FALSE;
}

static BOOL local_bridge_valid_envelope(
    const BYTE *buffer,
    DWORD length
) {
    DWORD offset;
    uint64_t body_length;

    if (
        buffer == NULL ||
        length < 3u ||
        length > ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES ||
        !readable_memory_window(buffer, length) ||
        buffer[0] != 0x03u
    ) {
        return FALSE;
    }
    offset = 2u;
    if (
        !decode_bootstrap_varuint(buffer, length, &offset, &body_length) ||
        body_length != (uint64_t)(length - offset)
    ) {
        return FALSE;
    }
    while (offset < length) {
        DWORD frame_end;
        uint64_t encoded_length;
        uint64_t type_id;

        if (
            !decode_bootstrap_varuint(
                buffer,
                length,
                &offset,
                &encoded_length
            ) ||
            (encoded_length & 1u) != 0u ||
            (encoded_length >> 1u) == 0u ||
            (encoded_length >> 1u) > length - offset
        ) {
            return FALSE;
        }
        frame_end = offset + (DWORD)(encoded_length >> 1u);
        if (!decode_bootstrap_varuint(buffer, frame_end, &offset, &type_id)) {
            return FALSE;
        }
        offset = frame_end;
    }
    return offset == length;
}

static BOOL world_bootstrap_request_envelope(
    const BYTE *buffer,
    DWORD length,
    DWORD *frame_length
) {
    DWORD offset;
    DWORD frame_end;
    uint64_t body_length;
    uint64_t encoded_length;
    uint64_t type_id;

    if (
        buffer == NULL ||
        length < 3u ||
        length > ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES ||
        !readable_memory_window(buffer, length) ||
        buffer[0] != 0x03u ||
        buffer[1] != 0x00u
    ) {
        return FALSE;
    }
    offset = 2u;
    if (
        !decode_bootstrap_varuint(buffer, length, &offset, &body_length) ||
        body_length != (uint64_t)(length - offset) ||
        !decode_bootstrap_varuint(
            buffer,
            length,
            &offset,
            &encoded_length
        ) ||
        (encoded_length & 1u) != 0u ||
        (encoded_length >> 1u) < ISAC_WORLD_REQUEST_MIN_FRAME_BYTES ||
        (encoded_length >> 1u) > ISAC_WORLD_REQUEST_MAX_FRAME_BYTES ||
        (encoded_length >> 1u) > length - offset
    ) {
        return FALSE;
    }
    frame_end = offset + (DWORD)(encoded_length >> 1u);
    if (
        frame_end != length ||
        !decode_bootstrap_varuint(buffer, frame_end, &offset, &type_id) ||
        type_id != 0x0000u
    ) {
        return FALSE;
    }
    *frame_length = (DWORD)(encoded_length >> 1u);
    return TRUE;
}

static void capture_private_world_request(
    const BYTE *envelope,
    DWORD length,
    DWORD frame_length
) {
    static const WCHAR capture_name[] =
        L"project-isac-world-request-private.bin";
    WCHAR capture_path[MAX_PATH];
    DWORD path_length;
    DWORD directory_length;
    HANDLE file;
    DWORD written = 0;
    char detail[192];

    if (
        envelope == NULL ||
        length == 0u ||
        InterlockedCompareExchange(
            &g_world_request_capture_count,
            1,
            0
        ) != 0
    ) {
        return;
    }
    path_length = GetModuleFileNameW(NULL, capture_path, MAX_PATH);
    if (path_length == 0u || path_length >= MAX_PATH) {
        log_dispatch_status(
            "WORLD_REQUEST_CAPTURE_ERROR",
            "reason=game-module-path-unavailable"
        );
        return;
    }
    directory_length = path_length;
    while (
        directory_length > 0u &&
        capture_path[directory_length - 1u] != L'\\' &&
        capture_path[directory_length - 1u] != L'/'
    ) {
        --directory_length;
    }
    if (
        directory_length == 0u ||
        directory_length +
            (DWORD)(sizeof(capture_name) / sizeof(capture_name[0])) >
            MAX_PATH
    ) {
        log_dispatch_status(
            "WORLD_REQUEST_CAPTURE_ERROR",
            "reason=private-capture-path-too-long"
        );
        return;
    }
    lstrcpyW(capture_path + directory_length, capture_name);
    file = CreateFileW(
        capture_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        log_dispatch_status(
            "WORLD_REQUEST_CAPTURE_ERROR",
            GetLastError() == ERROR_FILE_EXISTS
                ? "reason=private-capture-file-already-exists"
                : "reason=private-capture-file-create-failed"
        );
        return;
    }
    if (
        !WriteFile(file, envelope, length, &written, NULL) ||
        written != length ||
        !FlushFileBuffers(file)
    ) {
        CloseHandle(file);
        log_dispatch_status(
            "WORLD_REQUEST_CAPTURE_ERROR",
            "reason=private-capture-file-write-failed"
        );
        return;
    }
    CloseHandle(file);
    snprintf(
        detail,
        sizeof(detail),
        "channel=0x00,type=0x0000,envelope_length=%lu,"
        "frame_length=%lu,path=project-isac-world-request-private.bin",
        (unsigned long)length,
        (unsigned long)frame_length
    );
    log_dispatch_status("WORLD_REQUEST_CAPTURED", detail);
}

static BOOL world_bootstrap_observe_outbound(
    const BYTE *buffer,
    DWORD length
) {
    DWORD frame_length;
    char detail[128];

    if (
        !g_world_bootstrap_probe_enabled ||
        InterlockedCompareExchange(
            &g_local_bridge_injection_succeeded,
            0,
            0
        ) != 1 ||
        InterlockedCompareExchange(&g_world_request_seen, 0, 0) != 0 ||
        !world_bootstrap_request_envelope(buffer, length, &frame_length)
    ) {
        return FALSE;
    }
    if (InterlockedCompareExchange(&g_world_request_seen, 1, 0) != 0) {
        return FALSE;
    }
    InterlockedExchange(
        &g_world_request_reader_floor,
        InterlockedCompareExchange(&g_local_bridge_reader_count, 0, 0)
    );
    g_world_request_tick = GetTickCount64();
    snprintf(
        detail,
        sizeof(detail),
        "channel=0x00,type=0x0000,envelope_length=%lu,frame_length=%lu,"
        "selector=first-post-login-large-single-frame",
        (unsigned long)length,
        (unsigned long)frame_length
    );
    log_dispatch_status("WORLD_REQUEST_MATCHED", detail);
    capture_private_world_request(buffer, length, frame_length);
    return TRUE;
}

static SOCKET local_bridge_current_socket(void) {
    return (SOCKET)(uintptr_t)InterlockedCompareExchangePointer(
        &g_local_bridge_socket,
        NULL,
        NULL
    );
}

static BOOL local_bridge_owns_socket(SOCKET socket_handle) {
    return g_local_bridge_enabled &&
        socket_handle != INVALID_SOCKET &&
        socket_handle == local_bridge_current_socket();
}

static void local_bridge_disconnect(SOCKET socket_handle) {
    if (
        socket_handle != INVALID_SOCKET &&
        InterlockedCompareExchangePointer(
            &g_local_bridge_socket,
            NULL,
            (PVOID)(uintptr_t)socket_handle
        ) == (PVOID)(uintptr_t)socket_handle
    ) {
        shutdown(socket_handle, SD_BOTH);
        closesocket(socket_handle);
        log_dispatch_status(
            "LOCAL_BRIDGE_DISCONNECTED",
            "loopback-connection-closed"
        );
    }
}

static BOOL local_bridge_pop(BYTE *bytes, DWORD *length) {
    LONG read_index;
    LONG write_index;
    isac_local_bridge_record *record;

    if (InterlockedCompareExchange(&g_local_bridge_queue_lock, 1, 0) != 0) {
        return FALSE;
    }
    read_index = g_local_bridge_queue_read;
    write_index = g_local_bridge_queue_write;
    if (read_index == write_index) {
        InterlockedExchange(&g_local_bridge_queue_lock, 0);
        return FALSE;
    }
    record = &g_local_bridge_queue[
        (unsigned long)read_index % ISAC_LOCAL_BRIDGE_QUEUE_SLOTS
    ];
    *length = record->length;
    CopyMemory(bytes, record->bytes, *length);
    g_local_bridge_queue_read = read_index + 1;
    InterlockedExchange(&g_local_bridge_queue_lock, 0);
    return TRUE;
}

static BOOL local_bridge_enqueue_writer(
    const BYTE *writer,
    const BYTE *transport,
    const BYTE *buffer,
    DWORD length
) {
    BOOL world_request_matched;
    PVOID selected_writer;
    LONG read_index;
    LONG write_index;
    isac_local_bridge_record *record;

    if (!g_local_bridge_enabled || writer == NULL) {
        return FALSE;
    }
    selected_writer = InterlockedCompareExchangePointer(
        &g_local_bridge_writer,
        NULL,
        NULL
    );
    if (selected_writer == NULL) {
        if (!local_bridge_login_envelope(buffer, length)) {
            return FALSE;
        }
        selected_writer = InterlockedCompareExchangePointer(
            &g_local_bridge_writer,
            (PVOID)writer,
            NULL
        );
        if (selected_writer == NULL) {
            selected_writer = (PVOID)writer;
            InterlockedExchangePointer(
                &g_local_bridge_transport,
                (PVOID)transport
            );
            log_dispatch_status(
                "LOCAL_BRIDGE_STREAM_SELECTED",
                "selector=first-valid-type-0x0002-envelope,"
                "transport-retained=yes,"
                "scope=all-valid-envelopes-after-selection"
            );
            if (
                g_bootstrap_type3_probe_enabled ||
                g_local_bridge_injection_enabled
            ) {
                InterlockedExchange(
                    &g_bootstrap_type3_rearm_passes,
                    (LONG)ISAC_TYPE3_REARM_PASSES
                );
                SetEvent(g_local_bridge_queue_event);
            }
        }
    }
    if (!local_bridge_valid_envelope(buffer, length)) {
        return FALSE;
    }
    world_request_matched = world_bootstrap_observe_outbound(buffer, length);
    if (
        buffer == NULL ||
        length == 0 ||
        length > ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES ||
        !readable_memory_window(buffer, length) ||
        InterlockedCompareExchange(&g_local_bridge_queue_lock, 1, 0) != 0
    ) {
        if (
            InterlockedCompareExchange(&g_local_bridge_drop_logged, 1, 0) == 0
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_DROP",
                "reason=invalid-oversize-or-busy"
            );
        }
        return world_request_matched;
    }
    read_index = g_local_bridge_queue_read;
    write_index = g_local_bridge_queue_write;
    if (write_index - read_index >= (LONG)ISAC_LOCAL_BRIDGE_QUEUE_SLOTS) {
        InterlockedExchange(&g_local_bridge_queue_lock, 0);
        if (
            InterlockedCompareExchange(&g_local_bridge_drop_logged, 1, 0) == 0
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_DROP",
                "reason=queue-full"
            );
        }
        return world_request_matched;
    }
    record = &g_local_bridge_queue[
        (unsigned long)write_index % ISAC_LOCAL_BRIDGE_QUEUE_SLOTS
    ];
    record->length = length;
    CopyMemory(record->bytes, buffer, length);
    g_local_bridge_queue_write = write_index + 1;
    InterlockedExchange(&g_local_bridge_queue_lock, 0);
    SetEvent(g_local_bridge_queue_event);
    return world_request_matched;
}

static LONG local_bridge_reader_id(
    const BYTE *reader,
    const BYTE *source,
    BOOL *is_new
) {
    LONG count;
    LONG index;

    *is_new = FALSE;
    if (InterlockedCompareExchange(&g_local_bridge_reader_lock, 1, 0) != 0) {
        return 0;
    }
    count = g_local_bridge_reader_count;
    for (index = 0; index < count; ++index) {
        if (g_local_bridge_readers[index].reader == reader) {
            g_local_bridge_readers[index].source = source;
            InterlockedExchange(&g_local_bridge_reader_lock, 0);
            return g_local_bridge_readers[index].id;
        }
    }
    if (count >= (LONG)ISAC_LOCAL_BRIDGE_MAX_READERS) {
        InterlockedExchange(&g_local_bridge_reader_lock, 0);
        if (
            InterlockedCompareExchange(
                &g_local_bridge_reader_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_READER_LIMIT",
                "anonymous-reader-capacity-reached"
            );
        }
        return 0;
    }
    g_local_bridge_readers[count].reader = reader;
    g_local_bridge_readers[count].source = source;
    g_local_bridge_readers[count].id = count + 1;
    g_local_bridge_readers[count].relationship_logged = FALSE;
    g_local_bridge_reader_count = count + 1;
    *is_new = TRUE;
    InterlockedExchange(&g_local_bridge_reader_lock, 0);
    return count + 1;
}

static void local_bridge_select_injection_reader(
    LONG reader_id,
    const BYTE *reader,
    const BYTE *source
) {
    const BYTE *vtable;

    if (
        !g_local_bridge_injection_enabled ||
        reader_id != ISAC_LOCAL_BRIDGE_LOGIN_READER_ID ||
        reader == NULL ||
        source == NULL ||
        InterlockedCompareExchangePointer(
            &g_local_bridge_writer,
            NULL,
            NULL
        ) == NULL ||
        !readable_memory_window(source, sizeof(vtable))
    ) {
        return;
    }
    vtable = *(const BYTE *const *)source;
    if (vtable != g_game_base + ISAC_INBOUND_SOURCE_VTABLE_RVA) {
        log_dispatch_status(
            "LOCAL_BRIDGE_INJECTION_READER_REJECTED",
            "reader-id=1,reason=source-vtable-mismatch"
        );
        return;
    }
    if (InterlockedCompareExchange(&g_local_bridge_injection_lock, 1, 0) != 0) {
        return;
    }
    if (g_local_bridge_injection_reader == NULL) {
        g_local_bridge_injection_source = (PVOID)source;
        g_local_bridge_injection_reader = (PVOID)reader;
        InterlockedExchange(&g_local_bridge_injection_lock, 0);
        SetEvent(g_local_bridge_queue_event);
        log_dispatch_status(
            "LOCAL_BRIDGE_INJECTION_READER_READY",
            "reader-id=1,origin=verified-transport-delivery,"
            "source-vtable=verified"
        );
        return;
    }
    InterlockedExchange(&g_local_bridge_injection_lock, 0);
}

static void local_bridge_log_relationships(
    LONG reader_id,
    const BYTE *reader,
    const BYTE *source
) {
    const BYTE *transport = (const BYTE *)InterlockedCompareExchangePointer(
        &g_local_bridge_transport,
        NULL,
        NULL
    );
    const BYTE *reader_values[
        ISAC_LOCAL_BRIDGE_READER_SCAN_BYTES / sizeof(void *)
    ];
    const BYTE *transport_values[
        ISAC_LOCAL_BRIDGE_TRANSPORT_SCAN_BYTES / sizeof(void *)
    ];
    unsigned int reader_fields = 0;
    unsigned int transport_fields = 0;
    unsigned int match_count = 0;
    unsigned int reader_index;
    unsigned int transport_index;
    char detail[768];
    size_t offset;

    if (transport == NULL) {
        return;
    }
    for (
        reader_index = 0;
        reader_index < ISAC_LOCAL_BRIDGE_READER_SCAN_BYTES / sizeof(void *);
        ++reader_index
    ) {
        const BYTE *field = reader + reader_index * sizeof(void *);

        if (readable_memory_window(field, sizeof(void *))) {
            reader_values[reader_index] = *(const BYTE *const *)field;
            reader_fields = reader_index + 1u;
        } else {
            reader_values[reader_index] = NULL;
        }
    }
    for (
        transport_index = 0;
        transport_index <
            ISAC_LOCAL_BRIDGE_TRANSPORT_SCAN_BYTES / sizeof(void *);
        ++transport_index
    ) {
        const BYTE *field = transport + transport_index * sizeof(void *);

        if (readable_memory_window(field, sizeof(void *))) {
            transport_values[transport_index] = *(const BYTE *const *)field;
            transport_fields = transport_index + 1u;
        } else {
            transport_values[transport_index] = NULL;
        }
    }
    offset = (size_t)snprintf(
        detail,
        sizeof(detail),
        "reader_id=%ld,reader_scan_fields=%u,transport_scan_fields=%u,"
        "matches=",
        reader_id,
        reader_fields,
        transport_fields
    );
    for (
        reader_index = 0;
        reader_index < reader_fields &&
            match_count < ISAC_LOCAL_BRIDGE_MAX_SHARED_FIELDS;
        ++reader_index
    ) {
        const BYTE *value = reader_values[reader_index];

        if (
            value == NULL ||
            (uintptr_t)value < 0x10000u ||
            (value >= g_game_base && value < g_game_base + g_game_size) ||
            !readable_memory_window(value, 1u)
        ) {
            continue;
        }
        if (value == transport) {
            int written = snprintf(
                detail + offset,
                sizeof(detail) - offset,
                "%sr+0x%x=transport",
                match_count == 0 ? "" : ",",
                reader_index * (unsigned int)sizeof(void *)
            );
            if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
                break;
            }
            offset += (size_t)written;
            ++match_count;
        }
        for (
            transport_index = 0;
            transport_index < transport_fields &&
                match_count < ISAC_LOCAL_BRIDGE_MAX_SHARED_FIELDS;
            ++transport_index
        ) {
            if (value == transport_values[transport_index]) {
                int written = snprintf(
                    detail + offset,
                    sizeof(detail) - offset,
                    "%sr+0x%x=t+0x%x",
                    match_count == 0 ? "" : ",",
                    reader_index * (unsigned int)sizeof(void *),
                    transport_index * (unsigned int)sizeof(void *)
                );
                if (
                    written <= 0 ||
                    (size_t)written >= sizeof(detail) - offset
                ) {
                    reader_index = reader_fields;
                    break;
                }
                offset += (size_t)written;
                ++match_count;
            }
        }
    }
    for (
        transport_index = 0;
        transport_index < transport_fields &&
            match_count < ISAC_LOCAL_BRIDGE_MAX_SHARED_FIELDS;
        ++transport_index
    ) {
        const BYTE *value = transport_values[transport_index];
        const char *role = NULL;

        if (value == reader) {
            role = "reader";
        } else if (value == reader + 0x08u) {
            role = "secondary";
        } else if (value == source) {
            role = "source";
        }
        if (role != NULL) {
            int written = snprintf(
                detail + offset,
                sizeof(detail) - offset,
                "%st+0x%x=%s",
                match_count == 0 ? "" : ",",
                transport_index * (unsigned int)sizeof(void *),
                role
            );
            if (written <= 0 || (size_t)written >= sizeof(detail) - offset) {
                break;
            }
            offset += (size_t)written;
            ++match_count;
        }
    }
    if (match_count == 0u && offset + 5u < sizeof(detail)) {
        CopyMemory(detail + offset, "none", 5u);
    }
    log_dispatch_status("LOCAL_BRIDGE_RELATION", detail);
}

static LONG local_bridge_record_reader(
    const BYTE *reader,
    const char *origin,
    BOOL exact
) {
    const BYTE *source;
    const BYTE *vtable;
    uintptr_t vtable_rva = 0;
    LONG candidate_count;
    LONG reader_id;
    BOOL is_new;
    char detail[256];

    if (
        !g_local_bridge_enabled ||
        reader == NULL ||
        !readable_memory_window(reader + 0x70u, sizeof(source))
    ) {
        return 0;
    }
    source = *(const BYTE *const *)(reader + 0x70u);
    if (
        source == NULL ||
        !readable_memory_window(source, sizeof(vtable))
    ) {
        return 0;
    }
    vtable = *(const BYTE *const *)source;
    if (vtable >= g_game_base && vtable < g_game_base + g_game_size) {
        vtable_rva = (uintptr_t)(vtable - g_game_base);
    }
    candidate_count = InterlockedIncrement(
        &g_local_bridge_reader_candidate_count
    );
    reader_id = local_bridge_reader_id(reader, source, &is_new);
    if (reader_id == 0) {
        return 0;
    }
    if (exact) {
        InterlockedExchangePointer(
            &g_local_bridge_reader,
            (PVOID)reader
        );
        InterlockedExchangePointer(&g_local_bridge_source, (PVOID)source);
        local_bridge_select_injection_reader(reader_id, reader, source);
        if (
            g_world_bootstrap_probe_enabled &&
            InterlockedCompareExchange(&g_world_request_seen, 0, 0) == 1 &&
            reader_id > InterlockedCompareExchange(
                &g_world_request_reader_floor,
                0,
                0
            ) &&
            InterlockedCompareExchange(
                &g_world_bootstrap_reader_id,
                reader_id,
                0
            ) == 0
        ) {
            if (
                g_world_replay_enabled &&
                InterlockedCompareExchange(
                    &g_world_replay_reader_lock,
                    1,
                    0
                ) == 0
            ) {
                InterlockedExchangePointer(
                    &g_world_replay_reader,
                    (PVOID)reader
                );
                InterlockedExchangePointer(
                    &g_world_replay_source,
                    (PVOID)source
                );
                InterlockedExchange(&g_world_replay_reader_lock, 0);
            }
            snprintf(
                detail,
                sizeof(detail),
                "reader_id=%ld,selector=first-post-request-reader,"
                "request_reader_floor=%ld",
                reader_id,
                InterlockedCompareExchange(
                    &g_world_request_reader_floor,
                    0,
                    0
                )
            );
            log_dispatch_status("WORLD_STREAM_READER_SELECTED", detail);
        }
    } else if (candidate_count > 32) {
        return reader_id;
    }
    if (!is_new && exact) {
        return reader_id;
    }
    snprintf(
        detail,
        sizeof(detail),
        "reader_id=%ld,origin=%s,exact=%s,candidate=%ld,"
        "source-vtable-rva=0x%llx",
        reader_id,
        origin,
        exact ? "yes" : "no",
        candidate_count,
        (unsigned long long)vtable_rva
    );
    log_dispatch_status(
        exact ? "LOCAL_BRIDGE_READER_READY" : "LOCAL_BRIDGE_READER_CANDIDATE",
        detail
    );
    if (exact) {
        local_bridge_log_relationships(reader_id, reader, source);
    }
    return reader_id;
}

static BOOL local_bridge_frame_type(
    const BYTE *buffer,
    DWORD length,
    USHORT *type_id,
    DWORD *frame_length
) {
    DWORD offset = 0;
    uint64_t encoded_length;
    uint64_t decoded_type;

    if (
        buffer == NULL ||
        length == 0 ||
        !decode_bootstrap_varuint(
            buffer,
            length,
            &offset,
            &encoded_length
        ) ||
        (encoded_length & 1u) != 0 ||
        (encoded_length >> 1u) == 0 ||
        (encoded_length >> 1u) > 0xffffffffu ||
        !decode_bootstrap_varuint(
            buffer,
            length,
            &offset,
            &decoded_type
        ) ||
        decoded_type > 0xffffu
    ) {
        return FALSE;
    }
    *type_id = (USHORT)decoded_type;
    *frame_length = (DWORD)(encoded_length >> 1u);
    return TRUE;
}

static BOOL local_bridge_single_type3_frame(
    const BYTE *buffer,
    DWORD length
) {
    DWORD offset = 0;
    DWORD frame_end;
    uint64_t encoded_length;
    uint64_t type_id;

    if (
        buffer == NULL ||
        length == 0u ||
        !decode_bootstrap_varuint(
            buffer,
            length,
            &offset,
            &encoded_length
        ) ||
        (encoded_length & 1u) != 0 ||
        (encoded_length >> 1u) > length - offset
    ) {
        return FALSE;
    }
    frame_end = offset + (DWORD)(encoded_length >> 1u);
    return
        frame_end == length &&
        offset < frame_end &&
        decode_bootstrap_varuint(
            buffer,
            frame_end,
            &offset,
            &type_id
        ) &&
        type_id == 0x0003u;
}

static BOOL local_bridge_complete_single_type3_summary(
    const BYTE *prefix,
    DWORD prefix_length,
    uint64_t total_length
) {
    DWORD offset = 0;
    uint64_t encoded_length;
    uint64_t type_id;

    if (
        prefix == NULL ||
        prefix_length == 0u ||
        !decode_bootstrap_varuint(
            prefix,
            prefix_length,
            &offset,
            &encoded_length
        ) ||
        (encoded_length & 1u) != 0u ||
        (encoded_length >> 1u) == 0u ||
        total_length != (uint64_t)offset + (encoded_length >> 1u) ||
        !decode_bootstrap_varuint(
            prefix,
            prefix_length,
            &offset,
            &type_id
        )
    ) {
        return FALSE;
    }
    return type_id == 0x0003u;
}

static void capture_private_type3_profile(
    const BYTE *frame,
    DWORD length
) {
    static const WCHAR capture_name[] =
        L"project-isac-type0003-private.bin";
    WCHAR capture_path[MAX_PATH];
    DWORD path_length;
    DWORD directory_length;
    HANDLE file;
    DWORD written = 0;
    char detail[160];

    if (
        !g_type3_profile_capture_enabled ||
        frame == NULL ||
        length == 0u ||
        InterlockedCompareExchange(
            &g_type3_profile_capture_count,
            1,
            0
        ) != 0
    ) {
        return;
    }
    path_length = GetModuleFileNameW(NULL, capture_path, MAX_PATH);
    if (path_length == 0u || path_length >= MAX_PATH) {
        log_dispatch_status(
            "TYPE3_PROFILE_CAPTURE_ERROR",
            "reason=game-module-path-unavailable"
        );
        return;
    }
    directory_length = path_length;
    while (
        directory_length > 0u &&
        capture_path[directory_length - 1u] != L'\\' &&
        capture_path[directory_length - 1u] != L'/'
    ) {
        --directory_length;
    }
    if (
        directory_length == 0u ||
        directory_length +
            (DWORD)(sizeof(capture_name) / sizeof(capture_name[0])) >
            MAX_PATH
    ) {
        log_dispatch_status(
            "TYPE3_PROFILE_CAPTURE_ERROR",
            "reason=private-capture-path-too-long"
        );
        return;
    }
    lstrcpyW(capture_path + directory_length, capture_name);
    file = CreateFileW(
        capture_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        log_dispatch_status(
            "TYPE3_PROFILE_CAPTURE_ERROR",
            GetLastError() == ERROR_FILE_EXISTS
                ? "reason=private-capture-file-already-exists"
                : "reason=private-capture-file-create-failed"
        );
        return;
    }
    if (
        !WriteFile(file, frame, length, &written, NULL) ||
        written != length ||
        !FlushFileBuffers(file)
    ) {
        CloseHandle(file);
        log_dispatch_status(
            "TYPE3_PROFILE_CAPTURE_ERROR",
            "reason=private-capture-file-write-failed"
        );
        return;
    }
    CloseHandle(file);
    snprintf(
        detail,
        sizeof(detail),
        "reader_id=1,type=0x0003,format=complete-length-prefixed-frame,"
        "length=%lu,path=project-isac-type0003-private.bin",
        (unsigned long)length
    );
    log_dispatch_status("TYPE3_PROFILE_CAPTURED", detail);
}

static DWORD local_bridge_first_frame_span(
    const BYTE *buffer,
    DWORD length
) {
    DWORD offset = 0;
    uint64_t encoded_length;
    uint64_t frame_length;

    if (
        buffer == NULL ||
        length == 0u ||
        !decode_bootstrap_varuint(
            buffer,
            length,
            &offset,
            &encoded_length
        ) ||
        (encoded_length & 1u) != 0
    ) {
        return 0u;
    }
    frame_length = encoded_length >> 1u;
    if (
        frame_length == 0u ||
        frame_length > ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES - offset ||
        frame_length > length - offset
    ) {
        return 0u;
    }
    return offset + (DWORD)frame_length;
}

static void world_snapshot_store_u32(BYTE *destination, DWORD value) {
    destination[0] = (BYTE)(value & 0xffu);
    destination[1] = (BYTE)((value >> 8u) & 0xffu);
    destination[2] = (BYTE)((value >> 16u) & 0xffu);
    destination[3] = (BYTE)((value >> 24u) & 0xffu);
}

static void world_snapshot_store_u64(BYTE *destination, ULONGLONG value) {
    unsigned int index;

    for (index = 0u; index < 8u; ++index) {
        destination[index] = (BYTE)(value >> (index * 8u));
    }
}

static BOOL world_snapshot_write_all(
    HANDLE file,
    const BYTE *bytes,
    DWORD length
) {
    DWORD written = 0u;

    return WriteFile(file, bytes, length, &written, NULL) && written == length;
}

static void world_snapshot_error(const char *reason) {
    if (
        InterlockedCompareExchange(
            &g_world_snapshot_error_logged,
            1,
            0
        ) == 0
    ) {
        log_dispatch_status("WORLD_SNAPSHOT_CAPTURE_ERROR", reason);
    }
}

static DWORD world_snapshot_max_bytes(void) {
    return g_world_continuation_capture_enabled
        ? ISAC_WORLD_CONTINUATION_MAX_BYTES
        : ISAC_WORLD_SNAPSHOT_MAX_BYTES;
}

static LONG world_snapshot_max_records(void) {
    return g_world_continuation_capture_enabled
        ? ISAC_WORLD_CONTINUATION_MAX_RECORDS
        : ISAC_WORLD_SNAPSHOT_MAX_RECORDS;
}

static BOOL world_snapshot_open_locked(void) {
    static const WCHAR capture_name[] =
        L"project-isac-world-bootstrap-private.bin";
    static const BYTE magic[8] = {
        'I', 'S', 'A', 'C', 'W', 'B', 'S', '1'
    };
    WCHAR capture_path[MAX_PATH];
    BYTE header[32] = {0};
    DWORD path_length;
    DWORD directory_length;
    HANDLE file;

    if (
        !g_world_snapshot_capture_enabled ||
        g_world_snapshot_file != INVALID_HANDLE_VALUE ||
        InterlockedCompareExchange(&g_world_snapshot_started, 0, 0) != 0
    ) {
        return g_world_snapshot_file != INVALID_HANDLE_VALUE;
    }
    path_length = GetModuleFileNameW(NULL, capture_path, MAX_PATH);
    if (path_length == 0u || path_length >= MAX_PATH) {
        world_snapshot_error("reason=game-module-path-unavailable");
        return FALSE;
    }
    directory_length = path_length;
    while (
        directory_length > 0u &&
        capture_path[directory_length - 1u] != L'\\' &&
        capture_path[directory_length - 1u] != L'/'
    ) {
        --directory_length;
    }
    if (
        directory_length == 0u ||
        directory_length +
            (DWORD)(sizeof(capture_name) / sizeof(capture_name[0])) >
            MAX_PATH
    ) {
        world_snapshot_error("reason=private-capture-path-too-long");
        return FALSE;
    }
    lstrcpyW(capture_path + directory_length, capture_name);
    file = CreateFileW(
        capture_path,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        world_snapshot_error(
            GetLastError() == ERROR_FILE_EXISTS
                ? "reason=private-capture-file-already-exists"
                : "reason=private-capture-file-create-failed"
        );
        return FALSE;
    }
    CopyMemory(header, magic, sizeof(magic));
    world_snapshot_store_u32(header + 8u, 1u);
    world_snapshot_store_u32(header + 12u, (DWORD)sizeof(header));
    world_snapshot_store_u64(header + 16u, g_world_request_tick);
    world_snapshot_store_u32(header + 24u, 1u);
    if (!world_snapshot_write_all(file, header, (DWORD)sizeof(header))) {
        CloseHandle(file);
        world_snapshot_error("reason=private-capture-header-write-failed");
        return FALSE;
    }
    g_world_snapshot_file = file;
    InterlockedExchange(&g_world_snapshot_started, 1);
    {
        char detail[256];

        snprintf(
            detail,
            sizeof(detail),
            "format=ISACWBS1,timing=relative-to-world-request,"
            "mode=%s,max-payload-bytes=%lu,max-records=%ld,"
            "path=project-isac-world-bootstrap-private.bin",
            g_world_continuation_capture_enabled
                ? "post-gate-continuation"
                : "first-world-gate",
            (unsigned long)world_snapshot_max_bytes(),
            world_snapshot_max_records()
        );
        log_dispatch_status("WORLD_SNAPSHOT_CAPTURE_STARTED", detail);
    }
    return TRUE;
}

static void world_snapshot_finish_locked(
    BOOL complete,
    const char *reason
) {
    char detail[256];
    ULONGLONG duration = 0u;

    if (g_world_snapshot_file == INVALID_HANDLE_VALUE) {
        return;
    }
    if (g_world_request_tick != 0u) {
        duration = GetTickCount64() - g_world_request_tick;
    }
    FlushFileBuffers(g_world_snapshot_file);
    CloseHandle(g_world_snapshot_file);
    g_world_snapshot_file = INVALID_HANDLE_VALUE;
    InterlockedExchange(&g_world_snapshot_finished, 1);
    snprintf(
        detail,
        sizeof(detail),
        "status=%s,reason=%s,records=%ld,payload_bytes=%ld,"
        "duration_ms=%llu,path=project-isac-world-bootstrap-private.bin",
        complete ? "complete" : "incomplete",
        reason,
        InterlockedCompareExchange(&g_world_snapshot_record_count, 0, 0),
        InterlockedCompareExchange(&g_world_snapshot_payload_bytes, 0, 0),
        (unsigned long long)duration
    );
    log_dispatch_status(
        complete ? "WORLD_SNAPSHOT_CAPTURED" : "WORLD_SNAPSHOT_CAPTURE_STOPPED",
        detail
    );
}

static void world_snapshot_write_span(
    const BYTE *bytes,
    DWORD length,
    DWORD flags
) {
    BYTE record_header[16];
    LONG payload_bytes;
    LONG record_count;
    BOOL first_gate_record = FALSE;
    ULONGLONG delta = 0u;

    if (
        !g_world_snapshot_capture_enabled ||
        bytes == NULL ||
        length == 0u ||
        InterlockedCompareExchange(&g_world_snapshot_finished, 0, 0) != 0
    ) {
        return;
    }
    if (InterlockedCompareExchange(&g_world_snapshot_lock, 1, 0) != 0) {
        world_snapshot_error("reason=capture-writer-busy");
        return;
    }
    if (
        g_world_snapshot_file == INVALID_HANDLE_VALUE &&
        (
            (flags & ISAC_WORLD_SNAPSHOT_FLAG_SYNC) == 0u ||
            !world_snapshot_open_locked()
        )
    ) {
        InterlockedExchange(&g_world_snapshot_lock, 0);
        return;
    }
    payload_bytes = InterlockedCompareExchange(
        &g_world_snapshot_payload_bytes,
        0,
        0
    );
    record_count = InterlockedCompareExchange(
        &g_world_snapshot_record_count,
        0,
        0
    );
    if (
        length > world_snapshot_max_bytes() - (DWORD)payload_bytes ||
        record_count >= world_snapshot_max_records()
    ) {
        world_snapshot_finish_locked(FALSE, "capture-limit-reached");
        InterlockedExchange(&g_world_snapshot_lock, 0);
        return;
    }
    if (g_world_request_tick != 0u) {
        delta = GetTickCount64() - g_world_request_tick;
    }
    if (
        InterlockedCompareExchange(&g_world_stream_gate_complete, 0, 0) == 1 &&
        InterlockedCompareExchange(
            &g_world_snapshot_gate_recorded,
            1,
            0
        ) == 0
    ) {
        flags |= ISAC_WORLD_SNAPSHOT_FLAG_GATE_COMPLETE;
        first_gate_record = TRUE;
    }
    world_snapshot_store_u64(record_header, delta);
    world_snapshot_store_u32(record_header + 8u, length);
    world_snapshot_store_u32(record_header + 12u, flags);
    if (
        !world_snapshot_write_all(
            g_world_snapshot_file,
            record_header,
            (DWORD)sizeof(record_header)
        ) ||
        !world_snapshot_write_all(g_world_snapshot_file, bytes, length)
    ) {
        world_snapshot_error("reason=private-capture-record-write-failed");
        world_snapshot_finish_locked(FALSE, "write-failed");
        InterlockedExchange(&g_world_snapshot_lock, 0);
        return;
    }
    InterlockedIncrement(&g_world_snapshot_record_count);
    InterlockedExchangeAdd(
        &g_world_snapshot_payload_bytes,
        (LONG)length
    );
    if (first_gate_record && !g_world_continuation_capture_enabled) {
        world_snapshot_finish_locked(TRUE, "first-complete-type-0x0012");
    }
    InterlockedExchange(&g_world_snapshot_lock, 0);
}

static void world_snapshot_shutdown(void) {
    BOOL gate_recorded;

    if (InterlockedCompareExchange(&g_world_snapshot_lock, 1, 0) != 0) {
        return;
    }
    gate_recorded = InterlockedCompareExchange(
        &g_world_snapshot_gate_recorded,
        0,
        0
    ) == 1;
    world_snapshot_finish_locked(
        gate_recorded,
        gate_recorded
            ? "probe-shutdown-after-world-gate"
            : "probe-shutdown-before-world-gate"
    );
    InterlockedExchange(&g_world_snapshot_lock, 0);
}

static void world_stream_reset_frame(void) {
    g_world_stream_parser.length_value = 0u;
    g_world_stream_parser.type_value = 0u;
    g_world_stream_parser.frame_length = 0u;
    g_world_stream_parser.frame_consumed = 0u;
    g_world_stream_parser.length_shift = 0u;
    g_world_stream_parser.length_bytes = 0u;
    g_world_stream_parser.type_shift = 0u;
    g_world_stream_parser.type_bytes = 0u;
    g_world_stream_parser.have_length = FALSE;
    g_world_stream_parser.have_type = FALSE;
}

static void world_stream_fail(const char *reason) {
    world_stream_reset_frame();
    g_world_stream_parser.started = FALSE;
    if (
        InterlockedCompareExchange(
            &g_world_stream_error_logged,
            1,
            0
        ) == 0
    ) {
        log_dispatch_status("WORLD_STREAM_PARSE_ERROR", reason);
    }
}

static void world_stream_feed_locked(
    LONG reader_id,
    const BYTE *bytes,
    DWORD length
) {
    DWORD index;

    for (index = 0u; index < length; ++index) {
        BYTE current = bytes[index];

        if (!g_world_stream_parser.have_length) {
            if (
                g_world_stream_parser.length_bytes >= 5u ||
                g_world_stream_parser.length_shift >= 35u
            ) {
                world_stream_fail("reason=invalid-frame-length-varuint");
                return;
            }
            g_world_stream_parser.length_value |=
                (uint64_t)(current & 0x7fu) <<
                g_world_stream_parser.length_shift;
            g_world_stream_parser.length_shift += 7u;
            ++g_world_stream_parser.length_bytes;
            if ((current & 0x80u) == 0u) {
                uint64_t encoded_length =
                    g_world_stream_parser.length_value;
                uint64_t decoded_length = encoded_length >> 1u;

                if (
                    (encoded_length & 1u) != 0u ||
                    decoded_length == 0u ||
                    decoded_length > ISAC_WORLD_STREAM_MAX_FRAME_BYTES
                ) {
                    world_stream_fail("reason=invalid-declared-frame-length");
                    return;
                }
                g_world_stream_parser.frame_length =
                    (DWORD)decoded_length;
                g_world_stream_parser.have_length = TRUE;
            }
            continue;
        }

        ++g_world_stream_parser.frame_consumed;
        if (!g_world_stream_parser.have_type) {
            if (
                g_world_stream_parser.type_bytes >= 3u ||
                g_world_stream_parser.type_shift >= 21u
            ) {
                world_stream_fail("reason=invalid-type-varuint");
                return;
            }
            g_world_stream_parser.type_value |=
                (uint64_t)(current & 0x7fu) <<
                g_world_stream_parser.type_shift;
            g_world_stream_parser.type_shift += 7u;
            ++g_world_stream_parser.type_bytes;
            if ((current & 0x80u) == 0u) {
                LONG sequence;
                char detail[192];

                if (
                    g_world_stream_parser.type_value > 0xffffu ||
                    g_world_stream_parser.frame_consumed >
                        g_world_stream_parser.frame_length
                ) {
                    world_stream_fail("reason=invalid-frame-type");
                    return;
                }
                g_world_stream_parser.have_type = TRUE;
                sequence = InterlockedIncrement(
                    &g_world_stream_event_count
                );
                if (sequence <= ISAC_WORLD_STREAM_MAX_EVENTS) {
                    snprintf(
                        detail,
                        sizeof(detail),
                        "reader_id=%ld,sequence=%ld,type_id=0x%04llx,"
                        "frame_length=%lu,type_bytes=%u,body_length=%lu",
                        reader_id,
                        sequence,
                        (unsigned long long)g_world_stream_parser.type_value,
                        (unsigned long)g_world_stream_parser.frame_length,
                        g_world_stream_parser.type_bytes,
                        (unsigned long)(
                            g_world_stream_parser.frame_length -
                            g_world_stream_parser.type_bytes
                        )
                    );
                    log_dispatch_status("WORLD_STREAM_FRAME", detail);
                } else if (
                    InterlockedCompareExchange(
                        &g_world_stream_limit_logged,
                        1,
                        0
                    ) == 0
                ) {
                    log_dispatch_status(
                        "WORLD_STREAM_FRAME_LIMIT",
                        "max-events=4096,parser-continues=enabled"
                    );
                }
            }
        }
        if (
            g_world_stream_parser.frame_consumed ==
            g_world_stream_parser.frame_length
        ) {
            BOOL completed_world_gate =
                g_world_stream_parser.have_type &&
                g_world_stream_parser.type_value == 0x0012u;

            world_stream_reset_frame();
            if (completed_world_gate) {
                InterlockedExchange(&g_world_stream_gate_complete, 1);
            }
        } else if (
            g_world_stream_parser.frame_consumed >
            g_world_stream_parser.frame_length
        ) {
            world_stream_fail("reason=frame-overrun");
            return;
        }
    }
}

static void world_stream_feed(
    LONG reader_id,
    const BYTE *bytes,
    DWORD length,
    BOOL permit_sync
) {
    USHORT type_id = 0;
    DWORD frame_length = 0;
    char detail[128];

    if (
        !g_world_bootstrap_probe_enabled ||
        reader_id == 0 ||
        reader_id != InterlockedCompareExchange(
            &g_world_bootstrap_reader_id,
            0,
            0
        ) ||
        bytes == NULL ||
        length == 0u ||
        InterlockedCompareExchange(&g_world_stream_lock, 1, 0) != 0
    ) {
        return;
    }
    if (!g_world_stream_parser.started) {
        if (
            !permit_sync ||
            !local_bridge_frame_type(
                bytes,
                length,
                &type_id,
                &frame_length
            ) ||
            type_id != 0x0002u ||
            local_bridge_first_frame_span(bytes, length) != length
        ) {
            InterlockedExchange(&g_world_stream_lock, 0);
            return;
        }
        world_stream_reset_frame();
        g_world_stream_parser.started = TRUE;
        snprintf(
            detail,
            sizeof(detail),
            "reader_id=%ld,sync_type=0x0002,sync_frame_length=%lu,"
            "delivery_length=%lu",
            reader_id,
            (unsigned long)frame_length,
            (unsigned long)length
        );
        log_dispatch_status("WORLD_STREAM_SYNCED", detail);
    }
    world_stream_feed_locked(reader_id, bytes, length);
    InterlockedExchange(&g_world_stream_lock, 0);
}

static BOOL local_bridge_injection_reader_snapshot(
    const BYTE **reader,
    const BYTE **source
) {
    const BYTE *selected_reader;
    const BYTE *selected_source;
    const BYTE *current_source;
    DWORD state;

    if (InterlockedCompareExchange(&g_local_bridge_injection_lock, 1, 0) != 0) {
        return FALSE;
    }
    selected_reader = (const BYTE *)g_local_bridge_injection_reader;
    selected_source = (const BYTE *)g_local_bridge_injection_source;
    InterlockedExchange(&g_local_bridge_injection_lock, 0);
    if (
        selected_reader == NULL ||
        selected_source == NULL ||
        !readable_memory_window(
            selected_reader + 0x70u,
            sizeof(current_source)
        ) ||
        !readable_memory_window(selected_reader + 0x90u, sizeof(state))
    ) {
        return FALSE;
    }
    current_source = *(const BYTE *const *)(selected_reader + 0x70u);
    state = *(const DWORD *)(selected_reader + 0x90u);
    if (current_source != selected_source || state == 2u) {
        return FALSE;
    }
    *reader = selected_reader;
    *source = selected_source;
    return TRUE;
}

static BOOL local_bridge_wait_for_injection_reader(
    const BYTE **reader,
    const BYTE **source
) {
    ULONGLONG deadline = GetTickCount64() +
        ISAC_LOCAL_BRIDGE_READER_WAIT_MS;

    while (GetTickCount64() < deadline) {
        if (local_bridge_injection_reader_snapshot(reader, source)) {
            return TRUE;
        }
        if (
            InterlockedCompareExchange(
                &g_local_bridge_injection_wait_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_INJECTION_WAITING",
                "target=reader-id-1,timeout-ms=5000"
            );
        }
        if (
            WaitForSingleObject(g_local_bridge_stop_event, 10u) ==
            WAIT_OBJECT_0
        ) {
            return FALSE;
        }
    }
    return FALSE;
}

static BOOL local_bridge_inject_type3(
    const BYTE *bytes,
    DWORD length
) {
    const BYTE *reader;
    const BYTE *source;
    void *guard = NULL;
    DWORD appended;
    isac_reader_lock_fn reader_lock;
    isac_source_append_fn source_append;
    isac_reader_notify_fn reader_notify;
    isac_reader_unlock_fn reader_unlock;
    char detail[160];

    if (!g_local_bridge_injection_enabled) {
        return FALSE;
    }
    if (!local_bridge_single_type3_frame(bytes, length)) {
        if (
            InterlockedCompareExchange(
                &g_local_bridge_injection_skip_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_INJECTION_SKIPPED",
                "reason=not-one-complete-type-0x0003-frame"
            );
        }
        return FALSE;
    }
    if (!local_bridge_wait_for_injection_reader(&reader, &source)) {
        log_dispatch_status(
            "LOCAL_BRIDGE_INJECTION_ERROR",
            "reason=verified-login-reader-unavailable"
        );
        return FALSE;
    }
    if (
        InterlockedCompareExchange(
            &g_local_bridge_injection_count,
            1,
            0
        ) != 0
    ) {
        log_dispatch_status(
            "LOCAL_BRIDGE_INJECTION_SKIPPED",
            "reason=single-login-injection-already-consumed"
        );
        return FALSE;
    }
    if (
        !readable_code_window(
            g_game_base + ISAC_INBOUND_READER_LOCK_RVA,
            1u
        ) ||
        !readable_code_window(
            g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA,
            1u
        ) ||
        !readable_code_window(
            g_game_base + ISAC_INBOUND_READER_NOTIFY_RVA,
            1u
        ) ||
        !readable_code_window(
            g_game_base + ISAC_INBOUND_READER_UNLOCK_RVA,
            1u
        )
    ) {
        log_dispatch_status(
            "LOCAL_BRIDGE_INJECTION_ERROR",
            "reason=helper-code-unreadable"
        );
        return FALSE;
    }
    reader_lock = (isac_reader_lock_fn)(
        g_game_base + ISAC_INBOUND_READER_LOCK_RVA
    );
    source_append = (isac_source_append_fn)(
        g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA
    );
    reader_notify = (isac_reader_notify_fn)(
        g_game_base + ISAC_INBOUND_READER_NOTIFY_RVA
    );
    reader_unlock = (isac_reader_unlock_fn)(
        g_game_base + ISAC_INBOUND_READER_UNLOCK_RVA
    );

    reader_lock(&guard, (void *)(reader + 0x18u));
    appended = source_append((void *)source, bytes, length);
    if (appended == length) {
        reader_notify((void *)(reader + 0x68u));
    }
    reader_unlock(&guard);
    if (appended == length) {
        InterlockedExchange(&g_local_bridge_injection_succeeded, 1);
    }
    snprintf(
        detail,
        sizeof(detail),
        "reader-id=1,type=0x0003,length=%lu,appended=%lu,status=%s",
        (unsigned long)length,
        (unsigned long)appended,
        appended == length ? "notified" : "append-short"
    );
    log_dispatch_status(
        appended == length
            ? "LOCAL_BRIDGE_INJECTED"
            : "LOCAL_BRIDGE_INJECTION_ERROR",
        detail
    );
    return appended == length;
}

static BOOL local_bridge_replay_header(
    const BYTE *bytes,
    DWORD length
) {
    static const BYTE expected[ISAC_WORLD_REPLAY_HEADER_BYTES] = {
        'I', 'S', 'A', 'C', 'R', 'P', 'L', '1',
        1u, 0u, 0u, 0u, 0u, 0u, 0u, 0u
    };

    return bytes != NULL &&
        length >= ISAC_WORLD_REPLAY_HEADER_BYTES &&
        memcmp(bytes, expected, sizeof(expected)) == 0;
}

static BOOL world_replay_reader_snapshot(
    const BYTE **reader,
    const BYTE **source,
    LONG *reader_id
) {
    const BYTE *selected_reader;
    const BYTE *selected_source;
    const BYTE *current_source;
    DWORD state;

    if (InterlockedCompareExchange(&g_world_replay_reader_lock, 1, 0) != 0) {
        return FALSE;
    }
    selected_reader = (const BYTE *)g_world_replay_reader;
    selected_source = (const BYTE *)g_world_replay_source;
    *reader_id = InterlockedCompareExchange(
        &g_world_bootstrap_reader_id,
        0,
        0
    );
    InterlockedExchange(&g_world_replay_reader_lock, 0);
    if (
        selected_reader == NULL ||
        selected_source == NULL ||
        *reader_id == 0 ||
        !readable_memory_window(
            selected_reader + 0x70u,
            sizeof(current_source)
        ) ||
        !readable_memory_window(selected_reader + 0x90u, sizeof(state))
    ) {
        return FALSE;
    }
    current_source = *(const BYTE *const *)(selected_reader + 0x70u);
    state = *(const DWORD *)(selected_reader + 0x90u);
    if (current_source != selected_source || state == 2u) {
        return FALSE;
    }
    *reader = selected_reader;
    *source = selected_source;
    return TRUE;
}

static BOOL world_replay_wait_for_reader(
    const BYTE **reader,
    const BYTE **source,
    LONG *reader_id
) {
    ULONGLONG deadline = GetTickCount64() +
        ISAC_WORLD_REPLAY_READER_WAIT_MS;

    while (GetTickCount64() < deadline) {
        if (world_replay_reader_snapshot(reader, source, reader_id)) {
            return TRUE;
        }
        if (
            g_local_bridge_stop_event != NULL &&
            WaitForSingleObject(g_local_bridge_stop_event, 5u) ==
                WAIT_OBJECT_0
        ) {
            return FALSE;
        }
    }
    return FALSE;
}

static BOOL local_bridge_inject_world_frame(
    const BYTE *bytes,
    DWORD length
) {
    const BYTE *reader;
    const BYTE *source;
    void *guard = NULL;
    DWORD appended;
    DWORD frame_length = 0u;
    DWORD frame_span;
    USHORT type_id = 0u;
    LONG reader_id = 0;
    LONG sequence;
    isac_reader_lock_fn reader_lock;
    isac_source_append_fn source_append;
    isac_reader_notify_fn reader_notify;
    isac_reader_unlock_fn reader_unlock;
    char detail[224];

    frame_span = local_bridge_first_frame_span(bytes, length);
    if (
        !g_world_replay_enabled ||
        InterlockedCompareExchange(&g_world_replay_armed, 0, 0) != 1 ||
        frame_span != length ||
        !local_bridge_frame_type(
            bytes,
            length,
            &type_id,
            &frame_length
        )
    ) {
        return FALSE;
    }
    if (!world_replay_wait_for_reader(&reader, &source, &reader_id)) {
        if (
            InterlockedCompareExchange(
                &g_world_replay_injection_error_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "WORLD_REPLAY_INJECTION_ERROR",
                "reason=selected-world-reader-unavailable"
            );
        }
        return FALSE;
    }
    if (
        !readable_code_window(
            g_game_base + ISAC_INBOUND_READER_LOCK_RVA,
            1u
        ) ||
        !readable_code_window(
            g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA,
            1u
        ) ||
        !readable_code_window(
            g_game_base + ISAC_INBOUND_READER_NOTIFY_RVA,
            1u
        ) ||
        !readable_code_window(
            g_game_base + ISAC_INBOUND_READER_UNLOCK_RVA,
            1u
        )
    ) {
        if (
            InterlockedCompareExchange(
                &g_world_replay_injection_error_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "WORLD_REPLAY_INJECTION_ERROR",
                "reason=helper-code-unreadable"
            );
        }
        return FALSE;
    }
    reader_lock = (isac_reader_lock_fn)(
        g_game_base + ISAC_INBOUND_READER_LOCK_RVA
    );
    source_append = (isac_source_append_fn)(
        g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA
    );
    reader_notify = (isac_reader_notify_fn)(
        g_game_base + ISAC_INBOUND_READER_NOTIFY_RVA
    );
    reader_unlock = (isac_reader_unlock_fn)(
        g_game_base + ISAC_INBOUND_READER_UNLOCK_RVA
    );

    reader_lock(&guard, (void *)(reader + 0x18u));
    appended = source_append((void *)source, bytes, length);
    if (appended == length) {
        reader_notify((void *)(reader + 0x68u));
    }
    reader_unlock(&guard);
    if (appended != length) {
        if (
            InterlockedCompareExchange(
                &g_world_replay_injection_error_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "WORLD_REPLAY_INJECTION_ERROR",
                "reason=world-frame-append-short"
            );
        }
        return FALSE;
    }
    sequence = InterlockedIncrement(&g_world_replay_frame_count);
    InterlockedExchange(&g_world_replay_started, 1);
    world_stream_feed(
        reader_id,
        bytes,
        length,
        sequence == 1
    );
    snprintf(
        detail,
        sizeof(detail),
        "reader_id=%ld,sequence=%ld,type_id=0x%04x,"
        "frame_length=%lu,wire_length=%lu,status=notified",
        reader_id,
        sequence,
        (unsigned int)type_id,
        (unsigned long)frame_length,
        (unsigned long)length
    );
    log_dispatch_status("WORLD_REPLAY_INJECTED", detail);
    if (
        type_id == 0x0012u &&
        InterlockedCompareExchange(&g_world_replay_complete, 1, 0) == 0
    ) {
        snprintf(
            detail,
            sizeof(detail),
            "reader_id=%ld,sequence=%ld,type_id=0x0012,"
            "frame_length=%lu",
            reader_id,
            sequence,
            (unsigned long)frame_length
        );
        log_dispatch_status("WORLD_REPLAY_GATE_INJECTED", detail);
    }
    return TRUE;
}

static void local_bridge_record_delivery(CONTEXT *context) {
    const BYTE *secondary;
    const BYTE *chain_reference;
    const BYTE *chunk = NULL;
    BYTE prefix[ISAC_LOCAL_BRIDGE_PREFIX_BYTES] = {0};
    BYTE profile_capture[ISAC_TYPE3_PROFILE_CAPTURE_MAX_BYTES] = {0};
    BYTE world_sync[ISAC_WORLD_STREAM_SYNC_BYTES] = {0};
    DWORD prefix_length = 0;
    DWORD profile_capture_length = 0;
    DWORD world_sync_length = 0;
    uint64_t total_length = 0;
    unsigned int chunk_count = 0;
    BOOL profile_capture_complete = TRUE;
    BOOL world_sync_complete = TRUE;
    BOOL world_target = FALSE;
    BOOL world_started = FALSE;
    USHORT type_id = 0;
    DWORD frame_length = 0;
    BOOL has_type;
    LONG reader_id;
    char detail[320];

    if (context == NULL) {
        return;
    }
    secondary = (const BYTE *)(uintptr_t)context->Rcx;
    chain_reference = (const BYTE *)(uintptr_t)context->Rdx;
    if (secondary == NULL) {
        return;
    }
    if (readable_memory_window(chain_reference, sizeof(chunk))) {
        chunk = *(const BYTE *const *)chain_reference;
    }
    reader_id = local_bridge_record_reader(
        secondary - 0x08u,
        "transport-delivery",
        TRUE
    );
    world_target =
        g_world_bootstrap_probe_enabled &&
        reader_id != 0 &&
        reader_id == InterlockedCompareExchange(
            &g_world_bootstrap_reader_id,
            0,
            0
        );
    world_started = world_target && g_world_stream_parser.started;
    while (
        chunk != NULL &&
        chunk_count < ISAC_MAX_INBOUND_DELIVERY_CHUNKS &&
        readable_memory_window(chunk + 0x0cu, sizeof(DWORD)) &&
        readable_memory_window(chunk + 0x3f8u, sizeof(chunk))
    ) {
        DWORD chunk_length = *(const DWORD *)(chunk + 0x0cu);
        DWORD copy_length = 0;
        DWORD snapshot_flags = 0u;
        const BYTE *next_chunk;

        if (
            chunk_length > 0x100000u ||
            !readable_memory_window(chunk + 0x10u, chunk_length)
        ) {
            break;
        }
        next_chunk = *(const BYTE *const *)(chunk + 0x3f8u);
        if (prefix_length < sizeof(prefix)) {
            copy_length = chunk_length;
            if (copy_length > sizeof(prefix) - prefix_length) {
                copy_length = (DWORD)sizeof(prefix) - prefix_length;
            }
            CopyMemory(prefix + prefix_length, chunk + 0x10u, copy_length);
            prefix_length += copy_length;
        }
        if (g_type3_profile_capture_enabled) {
            if (
                chunk_length >
                sizeof(profile_capture) - profile_capture_length
            ) {
                profile_capture_complete = FALSE;
            } else if (profile_capture_complete) {
                CopyMemory(
                    profile_capture + profile_capture_length,
                    chunk + 0x10u,
                    chunk_length
                );
                profile_capture_length += chunk_length;
            }
        }
        if (world_target && !g_world_replay_enabled) {
            if (world_started) {
                world_stream_feed(
                    reader_id,
                    chunk + 0x10u,
                    chunk_length,
                    FALSE
                );
                if (chunk_count == 0u) {
                    snapshot_flags |=
                        ISAC_WORLD_SNAPSHOT_FLAG_DELIVERY_START;
                }
                if (next_chunk == NULL) {
                    snapshot_flags |=
                        ISAC_WORLD_SNAPSHOT_FLAG_DELIVERY_END;
                }
                world_snapshot_write_span(
                    chunk + 0x10u,
                    chunk_length,
                    snapshot_flags
                );
            } else if (
                chunk_length > sizeof(world_sync) - world_sync_length
            ) {
                world_sync_complete = FALSE;
            } else if (world_sync_complete) {
                CopyMemory(
                    world_sync + world_sync_length,
                    chunk + 0x10u,
                    chunk_length
                );
                world_sync_length += chunk_length;
            }
        }
        total_length += chunk_length;
        chunk = next_chunk;
        ++chunk_count;
    }
    has_type = local_bridge_frame_type(
        prefix,
        prefix_length,
        &type_id,
        &frame_length
    );
    snprintf(
        detail,
        sizeof(detail),
        "reader_id=%ld,total_length=%llu,chunk_count=%u,"
        "first_type=%s0x%04x,declared_frame_length=%lu",
        reader_id,
        (unsigned long long)total_length,
        chunk_count,
        has_type ? "" : "unknown-",
        has_type ? (unsigned int)type_id : 0u,
        (unsigned long)(has_type ? frame_length : 0u)
    );
    log_dispatch_status("LOCAL_BRIDGE_DELIVERY", detail);
    if (g_world_replay_enabled && world_target) {
        if (
            total_length <= 8u &&
            InterlockedCompareExchange(
                &g_world_replay_setup_seen,
                1,
                0
            ) == 0
        ) {
            snprintf(
                detail,
                sizeof(detail),
                "reader_id=%ld,total_length=%llu,action=retained,"
                "role=reader-setup",
                reader_id,
                (unsigned long long)total_length
            );
            log_dispatch_status("WORLD_REPLAY_SETUP_RETAINED", detail);
        } else if (
            InterlockedCompareExchange(&g_world_replay_armed, 0, 0) == 1
        ) {
            DWORD64 return_address;
            DWORD64 expected_return = (DWORD64)(uintptr_t)(
                g_game_base + ISAC_INBOUND_TRANSPORT_DELIVERY_RETURN_RVA
            );

            if (
                !readable_memory_window(
                    (const void *)(uintptr_t)context->Rsp,
                    sizeof(return_address)
                )
            ) {
                if (
                    InterlockedCompareExchange(
                        &g_world_replay_suppression_error_logged,
                        1,
                        0
                    ) == 0
                ) {
                    log_dispatch_status(
                        "WORLD_REPLAY_ISOLATION_ERROR",
                        "reason=unreadable-return-address"
                    );
                }
                return;
            }
            return_address = *(const DWORD64 *)(uintptr_t)context->Rsp;
            if (return_address != expected_return) {
                if (
                    InterlockedCompareExchange(
                        &g_world_replay_suppression_error_logged,
                        1,
                        0
                    ) == 0
                ) {
                    log_dispatch_status(
                        "WORLD_REPLAY_ISOLATION_ERROR",
                        "reason=unexpected-delivery-return-site"
                    );
                }
                return;
            }
            context->Rip = return_address;
            context->Rsp += sizeof(return_address);
            snprintf(
                detail,
                sizeof(detail),
                "reader_id=%ld,total_length=%llu,suppression=%ld,"
                "local_replay_started=%s",
                reader_id,
                (unsigned long long)total_length,
                InterlockedIncrement(&g_world_replay_suppression_count),
                InterlockedCompareExchange(
                    &g_world_replay_started,
                    0,
                    0
                ) == 1 ? "yes" : "no"
            );
            log_dispatch_status("WORLD_REPLAY_RETAIL_SUPPRESSED", detail);
            return;
        } else if (
            InterlockedCompareExchange(
                &g_world_replay_before_arm_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "WORLD_REPLAY_RETAIL_BEFORE_ARM",
                "action=retained,reason=local-replay-header-not-received"
            );
        }
    }
    if (
        world_target &&
        !world_started &&
        world_sync_complete &&
        (uint64_t)world_sync_length == total_length
    ) {
        world_stream_feed(
            reader_id,
            world_sync,
            world_sync_length,
            TRUE
        );
        if (g_world_stream_parser.started) {
            world_snapshot_write_span(
                world_sync,
                world_sync_length,
                ISAC_WORLD_SNAPSHOT_FLAG_SYNC |
                    ISAC_WORLD_SNAPSHOT_FLAG_DELIVERY_START |
                    ISAC_WORLD_SNAPSHOT_FLAG_DELIVERY_END
            );
        }
    }
    if (
        g_type3_profile_capture_enabled &&
        reader_id == ISAC_LOCAL_BRIDGE_LOGIN_READER_ID &&
        profile_capture_complete &&
        (uint64_t)profile_capture_length == total_length &&
        local_bridge_complete_single_type3_summary(
            prefix,
            prefix_length,
            total_length
        )
    ) {
        capture_private_type3_profile(
            profile_capture,
            profile_capture_length
        );
    }
    if (
        g_local_bridge_type3_isolation_enabled &&
        reader_id >= ISAC_LOCAL_BRIDGE_LOGIN_READER_ID &&
        reader_id <= ISAC_LOCAL_BRIDGE_LOGIN_READER_MAX_ID &&
        InterlockedCompareExchange(
            &g_local_bridge_injection_succeeded,
            0,
            0
        ) == 1 &&
        local_bridge_complete_single_type3_summary(
            prefix,
            prefix_length,
            total_length
        )
    ) {
        DWORD64 return_address;
        DWORD64 expected_return = (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_TRANSPORT_DELIVERY_RETURN_RVA
        );

        if (
            !readable_memory_window(
                (const void *)(uintptr_t)context->Rsp,
                sizeof(return_address)
            )
        ) {
            if (
                InterlockedCompareExchange(
                    &g_local_bridge_type3_suppression_error_logged,
                    1,
                    0
                ) == 0
            ) {
                log_dispatch_status(
                    "LOCAL_BRIDGE_TYPE3_ISOLATION_ERROR",
                    "reason=unreadable-return-address"
                );
            }
            return;
        }
        return_address = *(const DWORD64 *)(uintptr_t)context->Rsp;
        if (return_address != expected_return) {
            if (
                InterlockedCompareExchange(
                    &g_local_bridge_type3_suppression_error_logged,
                    1,
                    0
                ) == 0
            ) {
                log_dispatch_status(
                    "LOCAL_BRIDGE_TYPE3_ISOLATION_ERROR",
                    "reason=unexpected-delivery-return-site"
                );
            }
            return;
        }
        context->Rip = return_address;
        context->Rsp += sizeof(return_address);
        snprintf(
            detail,
            sizeof(detail),
            "reader_id=%ld,type=0x0003,total_length=%llu,"
            "suppression=%ld,scope=login-readers-1-through-2",
            reader_id,
            (unsigned long long)total_length,
            InterlockedIncrement(&g_local_bridge_type3_suppression_count)
        );
        log_dispatch_status("LOCAL_BRIDGE_RETAIL_TYPE3_SUPPRESSED", detail);
    }
}

static BOOL local_bridge_send_record(
    SOCKET socket_handle,
    const BYTE *bytes,
    DWORD length
) {
    DWORD offset = 0;

    while (offset < length) {
        int sent = send(
            socket_handle,
            (const char *)bytes + offset,
            (int)(length - offset),
            0
        );
        if (sent == SOCKET_ERROR || sent == 0) {
            return FALSE;
        }
        offset += (DWORD)sent;
    }
    return TRUE;
}

static SOCKET local_bridge_connect(void) {
    SOCKET socket_handle;
    struct sockaddr_in address;
    char detail[128];

    socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(g_local_bridge_port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (
        connect(
            socket_handle,
            (const struct sockaddr *)&address,
            (int)sizeof(address)
        ) == SOCKET_ERROR
    ) {
        closesocket(socket_handle);
        return INVALID_SOCKET;
    }
    InterlockedExchangePointer(
        &g_local_bridge_socket,
        (PVOID)(uintptr_t)socket_handle
    );
    snprintf(
        detail,
        sizeof(detail),
        "peer=127.0.0.1:%u,injection=%s",
        (unsigned int)g_local_bridge_port,
        g_world_replay_enabled
            ? "type-0x0003-once-and-world-replay"
            : g_local_bridge_injection_enabled
            ? "type-0x0003-once"
            : "disabled"
    );
    log_dispatch_status("LOCAL_BRIDGE_CONNECTED", detail);
    return socket_handle;
}

static DWORD WINAPI local_bridge_worker(LPVOID parameter) {
    WSADATA winsock_data;
    BYTE record[ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES];
    BYTE received[ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES];
    BYTE injection_pending[ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES];
    DWORD injection_pending_length = 0u;
    SOCKET socket_handle = INVALID_SOCKET;
    ULONGLONG next_connect_tick = 0;

    (void)parameter;
    g_local_bridge_worker_thread_id = GetCurrentThreadId();
    if (WSAStartup(MAKEWORD(2, 2), &winsock_data) != 0) {
        log_dispatch_status(
            "LOCAL_BRIDGE_ERROR",
            "winsock-startup-failed"
        );
        g_local_bridge_worker_thread_id = 0u;
        return 1;
    }
    while (WaitForSingleObject(g_local_bridge_stop_event, 0) != WAIT_OBJECT_0) {
        DWORD length;

        refresh_login_handoff_threads();

        if (
            InterlockedCompareExchange(
                &g_bootstrap_type3_rearm_passes,
                0,
                0
            ) > 0
        ) {
            refresh_dispatch_thread_breakpoints();
            InterlockedDecrement(&g_bootstrap_type3_rearm_passes);
        }

        if (
            socket_handle == INVALID_SOCKET &&
            GetTickCount64() >= next_connect_tick
        ) {
            socket_handle = local_bridge_connect();
            if (socket_handle == INVALID_SOCKET) {
                next_connect_tick = GetTickCount64() + 1000u;
                if (
                    InterlockedCompareExchange(
                        &g_local_bridge_waiting_logged,
                        1,
                        0
                    ) == 0
                ) {
                    log_dispatch_status(
                        "LOCAL_BRIDGE_WAITING",
                        "loopback-backend-not-listening"
                    );
                }
            }
        }
        while (
            socket_handle != INVALID_SOCKET &&
            local_bridge_pop(record, &length)
        ) {
            if (!local_bridge_send_record(socket_handle, record, length)) {
                local_bridge_disconnect(socket_handle);
                socket_handle = INVALID_SOCKET;
                next_connect_tick = GetTickCount64() + 1000u;
                break;
            }
        }
        if (socket_handle != INVALID_SOCKET) {
            fd_set read_set;
            struct timeval timeout;
            int selected;

            FD_ZERO(&read_set);
            FD_SET(socket_handle, &read_set);
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
            selected = select(0, &read_set, NULL, NULL, &timeout);
            if (selected > 0 && FD_ISSET(socket_handle, &read_set)) {
                int result = recv(
                    socket_handle,
                    (char *)received,
                    (int)sizeof(received),
                    0
                );
                if (result > 0) {
                    LONG sequence = InterlockedIncrement(
                        &g_local_bridge_rx_count
                    );
                    USHORT type_id = 0;
                    DWORD frame_length = 0;
                    BOOL has_type = local_bridge_frame_type(
                        received,
                        (DWORD)result,
                        &type_id,
                        &frame_length
                    );
                    char detail[224];

                    snprintf(
                        detail,
                        sizeof(detail),
                        "sequence=%ld,length=%d,first_type=%s0x%04x,"
                        "declared_frame_length=%lu,injection=%s",
                        sequence,
                        result,
                        has_type ? "" : "unknown-",
                        has_type ? (unsigned int)type_id : 0u,
                        (unsigned long)(has_type ? frame_length : 0u),
                        g_local_bridge_injection_enabled
                            ? "type-0x0003-once"
                            : "disabled"
                    );
                    log_dispatch_status("LOCAL_BRIDGE_RX", detail);
                    if (g_local_bridge_injection_enabled) {
                        DWORD received_length = (DWORD)result;

                        if (
                            received_length >
                            ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES -
                                injection_pending_length
                        ) {
                            injection_pending_length = 0u;
                            log_dispatch_status(
                                "LOCAL_BRIDGE_INJECTION_ERROR",
                                "reason=response-reassembly-overflow"
                            );
                        } else {
                            DWORD frame_span;

                            CopyMemory(
                                injection_pending + injection_pending_length,
                                received,
                                received_length
                            );
                            injection_pending_length += received_length;
                            for (;;) {
                                if (
                                    g_world_replay_enabled &&
                                    InterlockedCompareExchange(
                                        &g_world_replay_armed,
                                        0,
                                        0
                                    ) == 0 &&
                                    injection_pending_length >= 8u &&
                                    memcmp(
                                        injection_pending,
                                        "ISACRPL1",
                                        8u
                                    ) == 0
                                ) {
                                    if (
                                        injection_pending_length <
                                        ISAC_WORLD_REPLAY_HEADER_BYTES
                                    ) {
                                        break;
                                    }
                                    if (!local_bridge_replay_header(
                                        injection_pending,
                                        injection_pending_length
                                    )) {
                                        injection_pending_length = 0u;
                                        log_dispatch_status(
                                            "WORLD_REPLAY_HEADER_ERROR",
                                            "reason=invalid-loopback-control-header"
                                        );
                                        break;
                                    }
                                    injection_pending_length -=
                                        ISAC_WORLD_REPLAY_HEADER_BYTES;
                                    if (injection_pending_length != 0u) {
                                        MoveMemory(
                                            injection_pending,
                                            injection_pending +
                                                ISAC_WORLD_REPLAY_HEADER_BYTES,
                                            injection_pending_length
                                        );
                                    }
                                    InterlockedExchange(
                                        &g_world_replay_armed,
                                        1
                                    );
                                    log_dispatch_status(
                                        "WORLD_REPLAY_ARMED",
                                        "source=loopback-control-header,"
                                        "retail-world-isolation=bidirectional,"
                                        "initial-world-request=retained"
                                    );
                                    continue;
                                }
                                frame_span = local_bridge_first_frame_span(
                                    injection_pending,
                                    injection_pending_length
                                );
                                if (frame_span == 0u) {
                                    break;
                                }
                                if (
                                    g_world_replay_enabled &&
                                    InterlockedCompareExchange(
                                        &g_world_replay_armed,
                                        0,
                                        0
                                    ) == 1
                                ) {
                                    local_bridge_inject_world_frame(
                                        injection_pending,
                                        frame_span
                                    );
                                } else {
                                    local_bridge_inject_type3(
                                        injection_pending,
                                        frame_span
                                    );
                                }
                                injection_pending_length -= frame_span;
                                if (injection_pending_length != 0u) {
                                    MoveMemory(
                                        injection_pending,
                                        injection_pending + frame_span,
                                        injection_pending_length
                                    );
                                }
                            }
                        }
                    }
                } else {
                    local_bridge_disconnect(socket_handle);
                    socket_handle = INVALID_SOCKET;
                    next_connect_tick = GetTickCount64() + 1000u;
                }
            } else if (selected == SOCKET_ERROR) {
                local_bridge_disconnect(socket_handle);
                socket_handle = INVALID_SOCKET;
                next_connect_tick = GetTickCount64() + 1000u;
            }
        }
        WaitForSingleObject(
            g_local_bridge_queue_event,
            g_world_replay_enabled
                ? 5u
                : g_bootstrap_type3_rearm_passes > 0 ? 25u : 50u
        );
    }
    local_bridge_disconnect(socket_handle);
    WSACleanup();
    g_local_bridge_worker_thread_id = 0u;
    return 0;
}

static void start_local_bridge(void) {
    char detail[192];

    if (!g_local_bridge_enabled || g_local_bridge_thread != NULL) {
        return;
    }
    g_local_bridge_stop_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_local_bridge_queue_event = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (
        g_local_bridge_stop_event == NULL ||
        g_local_bridge_queue_event == NULL
    ) {
        log_dispatch_status("LOCAL_BRIDGE_ERROR", "event-creation-failed");
        return;
    }
    g_local_bridge_thread = CreateThread(
        NULL,
        0,
        local_bridge_worker,
        NULL,
        0,
        NULL
    );
    if (g_local_bridge_thread == NULL) {
        log_dispatch_status("LOCAL_BRIDGE_ERROR", "thread-creation-failed");
        return;
    }
    snprintf(
        detail,
        sizeof(detail),
        "peer=127.0.0.1:%u,mode=receive-observe-only,"
        "writer-selector=type-0x0002,max-record-bytes=%u,queue-slots=%u",
        (unsigned int)g_local_bridge_port,
        ISAC_LOCAL_BRIDGE_MAX_RECORD_BYTES,
        ISAC_LOCAL_BRIDGE_QUEUE_SLOTS
    );
    log_dispatch_status("LOCAL_BRIDGE_READY", detail);
}

static void stop_local_bridge(void) {
    SOCKET socket_handle;

    if (g_local_bridge_stop_event != NULL) {
        SetEvent(g_local_bridge_stop_event);
    }
    if (g_local_bridge_queue_event != NULL) {
        SetEvent(g_local_bridge_queue_event);
    }
    socket_handle = local_bridge_current_socket();
    local_bridge_disconnect(socket_handle);
    if (g_local_bridge_thread != NULL) {
        WaitForSingleObject(g_local_bridge_thread, 2000u);
        CloseHandle(g_local_bridge_thread);
        g_local_bridge_thread = NULL;
    }
    if (g_local_bridge_stop_event != NULL) {
        CloseHandle(g_local_bridge_stop_event);
        g_local_bridge_stop_event = NULL;
    }
    if (g_local_bridge_queue_event != NULL) {
        CloseHandle(g_local_bridge_queue_event);
        g_local_bridge_queue_event = NULL;
    }
}

static BOOL peek_control_frame(
    const BYTE *source,
    USHORT *type_id,
    DWORD *frame_length,
    DWORD *absolute_cursor,
    DWORD *local_cursor
) {
    const BYTE *buffer_object;
    const BYTE *buffer;
    DWORD buffer_length;
    DWORD offset;
    uint64_t encoded_length;
    uint64_t decoded_type;

    if (
        source == NULL ||
        !readable_memory_window(source + 0x40u, 0x14u)
    ) {
        return FALSE;
    }
    *absolute_cursor = *(const DWORD *)(source + 0x40u);
    buffer_object = *(const BYTE *const *)(source + 0x48u);
    *local_cursor = *(const DWORD *)(source + 0x50u);
    if (
        buffer_object == NULL ||
        !readable_memory_window(buffer_object, 0x10u)
    ) {
        return FALSE;
    }
    buffer_length = *(const DWORD *)(buffer_object + 0x0cu);
    buffer = buffer_object + 0x10u;
    if (
        *local_cursor >= buffer_length ||
        buffer_length > 0x10000u ||
        !readable_memory_window(buffer, buffer_length)
    ) {
        return FALSE;
    }
    offset = *local_cursor;
    if (
        !decode_bootstrap_varuint(
            buffer,
            buffer_length,
            &offset,
            &encoded_length
        ) ||
        (encoded_length & 1u) != 0 ||
        (encoded_length >> 1u) > buffer_length - offset
    ) {
        return FALSE;
    }
    *frame_length = (DWORD)(encoded_length >> 1u);
    if (
        *frame_length == 0u ||
        !decode_bootstrap_varuint(
            buffer,
            offset + *frame_length,
            &offset,
            &decoded_type
        ) ||
        decoded_type > 0xffffu
    ) {
        return FALSE;
    }
    *type_id = (USHORT)decoded_type;
    return TRUE;
}

static void capture_control_code(USHORT type_id, uintptr_t caller_rva) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t available;
    unsigned int length;
    BOOL exact_range = FALSE;
    BOOL truncated;
    LONG count;
    LONG index;
    const BYTE *start;
    char line[8704];
    size_t offset;
    unsigned int byte_index;

    if (caller_rva >= g_game_size) {
        return;
    }
    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + caller_rva),
        &image_base,
        NULL
    );
    if (
        function_entry != NULL &&
        image_base == (DWORD64)(uintptr_t)g_game_base
    ) {
        function_rva = (uintptr_t)function_entry->BeginAddress;
        function_end_rva = (uintptr_t)function_entry->EndAddress;
        exact_range = TRUE;
    } else {
        function_rva = caller_rva > 256u ? caller_rva - 256u : 0u;
        function_end_rva = function_rva + 512u;
    }
    if (
        (
            caller_rva == ISAC_CONTROL_TYPE_0002_SCHEMA_RVA ||
            caller_rva == ISAC_CONTROL_FIXED_READERS_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0002_AUX_LOW_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0002_SUBOBJECT_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0002_AUX_HIGH_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0002_NESTED_RVA ||
            function_rva == ISAC_CONTROL_TYPE_0003_DISPATCHER_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0003_DECODER_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0003_SCHEMA_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0003_COLLECTION_READERS_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0006_SCHEMA_RVA ||
            caller_rva == ISAC_CONTROL_TYPE_0006_DECODER_RVA
        ) &&
        caller_rva <= g_game_size - ISAC_CONTROL_DIRECT_FORWARD_BYTES
    ) {
        function_rva = caller_rva;
        function_end_rva = caller_rva + ISAC_CONTROL_DIRECT_FORWARD_BYTES;
        exact_range = FALSE;
    }
    if (
        function_rva >= function_end_rva ||
        function_end_rva > g_game_size
    ) {
        return;
    }
    if (InterlockedCompareExchange(&g_control_code_lock, 1, 0) != 0) {
        return;
    }
    count = g_control_code_count;
    for (index = 0; index < count; ++index) {
        if (g_control_code_functions[index] == function_rva) {
            InterlockedExchange(&g_control_code_lock, 0);
            return;
        }
    }
    if (count >= (LONG)ISAC_MAX_CONTROL_CODE_FUNCTIONS) {
        InterlockedExchange(&g_control_code_lock, 0);
        if (
            InterlockedCompareExchange(
                &g_control_code_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "CONTROL_CODE_LIMIT",
                "unique-function-capacity-reached"
            );
        }
        return;
    }
    g_control_code_functions[count] = function_rva;
    g_control_code_count = count + 1;
    InterlockedExchange(&g_control_code_lock, 0);

    available = function_end_rva - function_rva;
    length = available > ISAC_MAX_CONTROL_CODE_BYTES
        ? ISAC_MAX_CONTROL_CODE_BYTES
        : (unsigned int)available;
    truncated = !exact_range || available > ISAC_MAX_CONTROL_CODE_BYTES;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status("CONTROL_CODE_ERROR", "function-window-unreadable");
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "CONTROL_CODE tick_ms=%llu process=%lu thread=%lu "
        "type_id=0x%04x caller_rva=0x%llx function_rva=0x%llx "
        "function_end_rva=0x%llx length=%u exact_range=%u truncated=%u "
        "bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long long)caller_rva,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length,
        exact_range ? 1u : 0u,
        truncated ? 1u : 0u
    );
    for (
        byte_index = 0;
        byte_index < length && offset + 2u < sizeof(line);
        ++byte_index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[byte_index]
        );
        if (written != 2) {
            return;
        }
        offset += 2u;
    }
    if (byte_index != length || offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void record_control_path(
    const CONTEXT *context,
    const BYTE *reader,
    USHORT type_id,
    DWORD frame_length,
    DWORD absolute_cursor,
    DWORD local_cursor
) {
    uintptr_t rvas[ISAC_MAX_CONTROL_STACK_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t reader_method_rva = 0;
    const BYTE *const *vtable;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char line[1024];
    size_t offset;

    if (
        !g_control_probe_enabled ||
        (
            g_bootstrap_type3_probe_enabled
                ? type_id != 0x0003u
                : (type_id != 0x0002u && type_id != 0x0006u)
        )
    ) {
        return;
    }
    if (
        reader != NULL &&
        readable_memory_window(reader, sizeof(vtable))
    ) {
        vtable = *(const BYTE *const *const *)reader;
        if (
            vtable != NULL &&
            readable_memory_window(vtable, 4u * sizeof(*vtable)) &&
            vtable[3] >= g_game_base &&
            vtable[3] < g_game_base + g_game_size
        ) {
            reader_method_rva = (uintptr_t)(vtable[3] - g_game_base);
        }
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_MAX_CONTROL_STACK_FRAMES,
        &function_rva,
        &function_end_rva
    );
    sequence = InterlockedIncrement(&g_control_path_count);
    if (sequence > (LONG)ISAC_MAX_CONTROL_PATH_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_control_path_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "CONTROL_PATH_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "CONTROL_PATH sequence=%ld tick_ms=%llu process=%lu thread=%lu "
        "type_id=0x%04x frame_length=%lu absolute_cursor=%lu "
        "local_cursor=%lu reader_method_rva=0x%llx frame_count=%u rvas=",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long)frame_length,
        (unsigned long)absolute_cursor,
        (unsigned long)local_cursor,
        (unsigned long long)reader_method_rva,
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            return;
        }
        offset += (size_t)written;
    }
    if (offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    for (index = 0; index < depth; ++index) {
        capture_control_code(type_id, rvas[index]);
    }
}

static void capture_outbound_control_code(
    USHORT type_id,
    uintptr_t caller_rva
) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t available;
    unsigned int length;
    BOOL exact_range = FALSE;
    BOOL truncated;
    LONG count;
    LONG index;
    const BYTE *start;
    char line[8704];
    size_t offset;
    unsigned int byte_index;

    if (caller_rva >= g_game_size) {
        return;
    }
    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + caller_rva),
        &image_base,
        NULL
    );
    if (
        function_entry != NULL &&
        image_base == (DWORD64)(uintptr_t)g_game_base
    ) {
        function_rva = (uintptr_t)function_entry->BeginAddress;
        function_end_rva = (uintptr_t)function_entry->EndAddress;
        exact_range = TRUE;
    } else {
        function_rva = caller_rva > 256u ? caller_rva - 256u : 0u;
        function_end_rva = function_rva + 512u;
    }
    if (
        function_rva >= function_end_rva ||
        function_end_rva > g_game_size
    ) {
        return;
    }
    if (
        InterlockedCompareExchange(
            &g_outbound_control_code_lock,
            1,
            0
        ) != 0
    ) {
        return;
    }
    count = g_outbound_control_code_count;
    for (index = 0; index < count; ++index) {
        if (g_outbound_control_code_functions[index] == function_rva) {
            InterlockedExchange(&g_outbound_control_code_lock, 0);
            return;
        }
    }
    if (count >= (LONG)ISAC_MAX_OUTBOUND_CONTROL_CODE_FUNCTIONS) {
        InterlockedExchange(&g_outbound_control_code_lock, 0);
        if (
            InterlockedCompareExchange(
                &g_outbound_control_code_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "OUTBOUND_CONTROL_CODE_LIMIT",
                "unique-function-capacity-reached"
            );
        }
        return;
    }
    g_outbound_control_code_functions[count] = function_rva;
    g_outbound_control_code_count = count + 1;
    InterlockedExchange(&g_outbound_control_code_lock, 0);

    available = function_end_rva - function_rva;
    length = available > ISAC_MAX_OUTBOUND_CONTROL_CODE_BYTES
        ? ISAC_MAX_OUTBOUND_CONTROL_CODE_BYTES
        : (unsigned int)available;
    truncated = !exact_range ||
        available > ISAC_MAX_OUTBOUND_CONTROL_CODE_BYTES;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "OUTBOUND_CONTROL_CODE_ERROR",
            "function-window-unreadable"
        );
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "OUTBOUND_CONTROL_CODE tick_ms=%llu process=%lu thread=%lu "
        "type_id=0x%04x caller_rva=0x%llx function_rva=0x%llx "
        "function_end_rva=0x%llx length=%u exact_range=%u truncated=%u "
        "bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long long)caller_rva,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length,
        exact_range ? 1u : 0u,
        truncated ? 1u : 0u
    );
    for (
        byte_index = 0;
        byte_index < length && offset + 2u < sizeof(line);
        ++byte_index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[byte_index]
        );
        if (written != 2) {
            return;
        }
        offset += 2u;
    }
    if (byte_index != length || offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void record_outbound_control_path(
    const CONTEXT *context,
    USHORT type_id,
    DWORD envelope_length,
    int marker,
    int channel
) {
    uintptr_t rvas[ISAC_MAX_CONTROL_STACK_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char line[1024];
    size_t offset;

    if (
        !g_outbound_control_probe_enabled ||
        context == NULL ||
        (type_id != 0x0002u && type_id != 0x0005u)
    ) {
        return;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_MAX_CONTROL_STACK_FRAMES,
        &function_rva,
        &function_end_rva
    );
    sequence = InterlockedIncrement(&g_outbound_control_path_count);
    if (sequence > (LONG)ISAC_MAX_OUTBOUND_CONTROL_PATH_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_outbound_control_path_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "OUTBOUND_CONTROL_PATH_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "OUTBOUND_CONTROL_PATH sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu type_id=0x%04x envelope_length=%lu marker=0x%02x "
        "channel=0x%02x boundary_function_rva=0x%llx "
        "boundary_function_end_rva=0x%llx frame_count=%u rvas=",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long)envelope_length,
        (unsigned int)marker,
        (unsigned int)channel,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            return;
        }
        offset += (size_t)written;
    }
    if (offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);

    if (function_rva < g_game_size) {
        capture_outbound_control_code(type_id, function_rva);
    }
    for (index = 0; index < depth; ++index) {
        capture_outbound_control_code(type_id, rvas[index]);
    }
}

static void record_control_correlation(
    char direction,
    LONG stream_id,
    uint64_t type_id,
    DWORD frame_length,
    int marker,
    int channel,
    uint64_t first_value,
    DWORD encoded_bytes
) {
    LONG sequence;
    char line[512];
    int length;

    if (!g_outbound_control_probe_enabled) {
        return;
    }
    if (
        (direction == 'O' && type_id != 0x0002u && type_id != 0x0005u) ||
        (direction == 'I' && type_id != 0x0002u && type_id != 0x0006u)
    ) {
        return;
    }
    sequence = InterlockedIncrement(&g_control_correlation_count);
    if (sequence > (LONG)ISAC_MAX_CONTROL_CORRELATION_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_control_correlation_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "CONTROL_CORRELATION_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    length = snprintf(
        line,
        sizeof(line),
        "CONTROL_CORRELATION sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu direction=%s stream_id=%ld type_id=0x%04llx "
        "frame_length=%lu marker=%s channel=%s first_uvar=%llu "
        "encoded_bytes=%lu\r\n",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        direction == 'O' ? "outbound" : "inbound",
        stream_id,
        (unsigned long long)type_id,
        (unsigned long)frame_length,
        marker < 0 ? "-" : marker == 3 ? "0x03" : "other",
        channel < 0 ? "-" : channel == 0 ? "0x00" :
            channel == 9 ? "0x09" : channel == 10 ? "0x0a" : "other",
        (unsigned long long)first_value,
        (unsigned long)encoded_bytes
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
}

static void capture_bootstrap_record(
    char direction,
    LONG stream_id,
    const BYTE *buffer,
    DWORD length,
    const CONTEXT *context
) {
    uint64_t frame_types[ISAC_MAX_BOOTSTRAP_FRAME_SUMMARY];
    DWORD frame_lengths[ISAC_MAX_BOOTSTRAP_FRAME_SUMMARY];
    DWORD offset = 0;
    DWORD frame_count = 0;
    DWORD listed_frames = 0;
    uint64_t decoded_length;
    uint64_t type_id;
    const char *framing = "unrecognized";
    int marker = -1;
    int channel = -1;
    BOOL valid = FALSE;
    LONG sequence;
    char line[2048];
    char marker_text[8];
    char channel_text[8];
    size_t line_offset;
    DWORD index;

    sequence = InterlockedIncrement(&g_bootstrap_record_count);
    if (
        sequence > (LONG)(
            g_world_continuation_capture_enabled
                ? ISAC_MAX_CONTINUATION_BOOTSTRAP_RECORDS
                : ISAC_MAX_BOOTSTRAP_RECORDS
        )
    ) {
        if (
            InterlockedCompareExchange(
                &g_bootstrap_record_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "BOOTSTRAP_PROBE_LIMIT",
                "record-capacity-reached"
            );
        }
        return;
    }
    if (
        buffer != NULL &&
        length != 0 &&
        length <= ISAC_MAX_BOOTSTRAP_INSPECT_BYTES &&
        readable_memory_window(buffer, length)
    ) {
        if (direction == 'O' && length >= 3u) {
            uint64_t body_length;

            marker = buffer[0];
            channel = buffer[1];
            offset = 2u;
            if (
                decode_bootstrap_varuint(
                    buffer,
                    length,
                    &offset,
                    &body_length
                ) &&
                body_length == (uint64_t)(length - offset)
            ) {
                valid = TRUE;
                while (offset < length) {
                    DWORD frame_start;
                    DWORD frame_end;
                    DWORD field_start;
                    DWORD field_end;
                    uint64_t first_value;

                    if (
                        !decode_bootstrap_varuint(
                            buffer,
                            length,
                            &offset,
                            &decoded_length
                        ) ||
                        (decoded_length & 1u) != 0 ||
                        (decoded_length >> 1u) > length - offset
                    ) {
                        valid = FALSE;
                        break;
                    }
                    frame_start = offset;
                    frame_end = offset + (DWORD)(decoded_length >> 1u);
                    if (
                        frame_start == frame_end ||
                        !decode_bootstrap_varuint(
                            buffer,
                            frame_end,
                            &frame_start,
                            &type_id
                        )
                    ) {
                        valid = FALSE;
                        break;
                    }
                    field_start = frame_start;
                    field_end = frame_start;
                    if (
                        decode_bootstrap_varuint(
                            buffer,
                            frame_end,
                            &field_end,
                            &first_value
                        )
                    ) {
                        record_control_correlation(
                            direction,
                            stream_id,
                            type_id,
                            (DWORD)(decoded_length >> 1u),
                            marker,
                            channel,
                            first_value,
                            field_end - field_start
                        );
                    }
                    if (listed_frames < ISAC_MAX_BOOTSTRAP_FRAME_SUMMARY) {
                        frame_types[listed_frames] = type_id;
                        frame_lengths[listed_frames] =
                            (DWORD)(decoded_length >> 1u);
                        ++listed_frames;
                    }
                    ++frame_count;
                    offset = frame_end;
                }
                if (valid && offset == length) {
                    framing = "envelope";
                    for (index = 0; index < listed_frames; ++index) {
                        if (
                            frame_types[index] == 0x0002u ||
                            frame_types[index] == 0x0005u
                        ) {
                            record_outbound_control_path(
                                context,
                                (USHORT)frame_types[index],
                                length,
                                marker,
                                channel
                            );
                        }
                    }
                }
            }
        } else if (direction == 'I') {
            DWORD frame_start;
            DWORD field_start;
            DWORD field_end;
            uint64_t first_value;

            if (
                decode_bootstrap_varuint(
                    buffer,
                    length,
                    &offset,
                    &decoded_length
                ) &&
                (decoded_length & 1u) == 0 &&
                (decoded_length >> 1u) == length - offset
            ) {
                frame_start = offset;
                if (
                    frame_start < length &&
                    decode_bootstrap_varuint(
                        buffer,
                        length,
                        &frame_start,
                        &type_id
                    )
                ) {
                    frame_types[0] = type_id;
                    frame_lengths[0] = (DWORD)(decoded_length >> 1u);
                    frame_count = 1u;
                    listed_frames = 1u;
                    framing = "frame";
                    field_start = frame_start;
                    field_end = frame_start;
                    if (
                        decode_bootstrap_varuint(
                            buffer,
                            length,
                            &field_end,
                            &first_value
                        )
                    ) {
                        record_control_correlation(
                            direction,
                            stream_id,
                            type_id,
                            (DWORD)(decoded_length >> 1u),
                            -1,
                            -1,
                            first_value,
                            field_end - field_start
                        );
                    }
                }
            }
        }
    } else if (length > ISAC_MAX_BOOTSTRAP_INSPECT_BYTES) {
        framing = "oversize";
    }

    if (marker < 0) {
        lstrcpyA(marker_text, "-");
        lstrcpyA(channel_text, "-");
    } else {
        snprintf(marker_text, sizeof(marker_text), "0x%02x", marker);
        snprintf(channel_text, sizeof(channel_text), "0x%02x", channel);
    }

    line_offset = (size_t)snprintf(
        line,
        sizeof(line),
        "BOOTSTRAP_RECORD sequence=%ld tick_ms=%llu process=%lu thread=%lu "
        "direction=%s stream_id=%ld length=%lu framing=%s "
        "marker=%s channel=%s frame_count=%lu listed_frames=%lu "
        "frame_types=",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        direction == 'O' ? "outbound" : "inbound",
        stream_id,
        (unsigned long)length,
        framing,
        marker_text,
        channel_text,
        (unsigned long)frame_count,
        (unsigned long)listed_frames
    );
    for (index = 0; index < listed_frames && line_offset < sizeof(line); ++index) {
        int written = snprintf(
            line + line_offset,
            sizeof(line) - line_offset,
            "%s0x%04llx",
            index == 0 ? "" : ",",
            (unsigned long long)frame_types[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - line_offset) {
            return;
        }
        line_offset += (size_t)written;
    }
    if (listed_frames == 0u) {
        line_offset += (size_t)snprintf(
            line + line_offset,
            sizeof(line) - line_offset,
            "-"
        );
    }
    line_offset += (size_t)snprintf(
        line + line_offset,
        sizeof(line) - line_offset,
        " frame_lengths="
    );
    for (index = 0; index < listed_frames && line_offset < sizeof(line); ++index) {
        int written = snprintf(
            line + line_offset,
            sizeof(line) - line_offset,
            "%s%lu",
            index == 0 ? "" : ",",
            (unsigned long)frame_lengths[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - line_offset) {
            return;
        }
        line_offset += (size_t)written;
    }
    if (listed_frames == 0u) {
        line_offset += (size_t)snprintf(
            line + line_offset,
            sizeof(line) - line_offset,
            "-"
        );
    }
    if (line_offset + 2u >= sizeof(line)) {
        return;
    }
    line[line_offset++] = '\r';
    line[line_offset++] = '\n';
    line[line_offset] = '\0';
    append_plaintext_log(line);
}

static void capture_plaintext(
    char direction,
    const BYTE *buffer,
    DWORD length,
    LONG stream_id,
    const CONTEXT *context
) {
    volatile LONG *count = direction == 'I'
        ? &g_plaintext_in_count
        : &g_plaintext_count;
    volatile LONG *limit_logged = direction == 'I'
        ? &g_plaintext_in_limit_logged
        : &g_plaintext_limit_logged;
    const char *record_name = direction == 'I'
        ? "PLAINTEXT_IN"
        : "PLAINTEXT_OUT";
    LONG sequence;
    char line[2304];
    size_t offset;
    DWORD index;

    if (!g_plaintext_probe_enabled) {
        return;
    }
    if (
        g_plaintext_world_active == 0 ||
        g_bootstrap_redacted_only
    ) {
        if (g_bootstrap_probe_enabled) {
            capture_bootstrap_record(
                direction,
                stream_id,
                buffer,
                length,
                context
            );
        }
        return;
    }
    if (direction == 'I' && length > ISAC_MAX_PLAINTEXT_BYTES) {
        if (
            InterlockedCompareExchange(
                &g_plaintext_in_oversize_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "PLAINTEXT_IN_SKIPPED",
                "oversize-candidate-window"
            );
        }
        return;
    }
    if (
        buffer == NULL ||
        length == 0 ||
        length > ISAC_MAX_PLAINTEXT_BYTES ||
        !readable_memory_window(buffer, length)
    ) {
        if (
            InterlockedCompareExchange(
                &g_plaintext_error_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "PLAINTEXT_PROBE_ERROR",
                direction == 'I'
                    ? "invalid-inbound-window"
                    : "invalid-outbound-window"
            );
        }
        return;
    }
    sequence = InterlockedIncrement(count);
    if (sequence > (LONG)ISAC_MAX_PLAINTEXT_RECORDS) {
        if (
            InterlockedCompareExchange(
                limit_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "PLAINTEXT_PROBE_LIMIT",
                direction == 'I'
                    ? "direction=inbound,record-capacity-reached"
                    : "direction=outbound,record-capacity-reached"
            );
        }
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "%s sequence=%ld tick_ms=%llu process=%lu thread=%lu "
        "length=%lu bytes=",
        record_name,
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long)length
    );
    for (index = 0; index < length && offset + 2 < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)buffer[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (index != length || offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_plaintext_log(line);
}

static void capture_serialized_writer(
    const BYTE *writer,
    CONTEXT *context
) {
    static const BYTE transport_call[3] = {0xff, 0x50, 0x08};
    BOOL world_request_matched;
    const BYTE *buffer;
    DWORD length;

    if (
        writer == NULL ||
        !readable_memory_window(
            writer + ISAC_SERIALIZED_BUFFER_POINTER_OFFSET,
            sizeof(buffer) + sizeof(length)
        )
    ) {
        if (
            InterlockedCompareExchange(
                &g_plaintext_error_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "PLAINTEXT_PROBE_ERROR",
                "invalid-writer-metadata"
            );
        }
        return;
    }
    buffer = *(const BYTE *const *)(
        writer + ISAC_SERIALIZED_BUFFER_POINTER_OFFSET
    );
    length = *(const DWORD *)(
        writer + ISAC_SERIALIZED_BUFFER_LENGTH_OFFSET
    );
    world_request_matched = local_bridge_enqueue_writer(
        writer,
        context != NULL
            ? (const BYTE *)(uintptr_t)context->Rcx
            : NULL,
        buffer,
        length
    );
    capture_plaintext(
        'O',
        buffer,
        length,
        bootstrap_stream_id('O', writer),
        context
    );
    if (
        !world_request_matched &&
        g_world_replay_enabled &&
        InterlockedCompareExchange(&g_world_replay_armed, 0, 0) == 1 &&
        InterlockedCompareExchangePointer(
            &g_local_bridge_writer,
            NULL,
            NULL
        ) != NULL &&
        local_bridge_valid_envelope(buffer, length)
    ) {
        LONG sequence;
        char detail[192];
        const BYTE *instruction;

        if (context == NULL) {
            if (
                InterlockedCompareExchange(
                    &g_world_replay_outbound_suppression_error_logged,
                    1,
                    0
                ) == 0
            ) {
                log_dispatch_status(
                    "WORLD_REPLAY_OUTBOUND_ISOLATION_ERROR",
                    "reason=missing-exception-context"
                );
            }
            return;
        }
        instruction = (const BYTE *)(uintptr_t)context->Rip;
        if (
            instruction != g_game_base + 0x0d6bbfu ||
            !readable_code_window(instruction, sizeof(transport_call)) ||
            memcmp(instruction, transport_call, sizeof(transport_call)) != 0
        ) {
            if (
                InterlockedCompareExchange(
                    &g_world_replay_outbound_suppression_error_logged,
                    1,
                    0
                ) == 0
            ) {
                log_dispatch_status(
                    "WORLD_REPLAY_OUTBOUND_ISOLATION_ERROR",
                    "reason=unexpected-transport-call-site"
                );
            }
            return;
        }
        context->Rip += sizeof(transport_call);
        sequence = InterlockedIncrement(
            &g_world_replay_outbound_suppression_count
        );
        if (sequence == 1 || sequence <= 16 || sequence % 1024 == 0) {
            snprintf(
                detail,
                sizeof(detail),
                "sequence=%ld,envelope_length=%lu,marker=%s,channel=%s,"
                "action=retail-transport-call-skipped,"
                "loopback-copy=retained",
                sequence,
                (unsigned long)length,
                buffer != NULL && length >= 1u && buffer[0] == 0x03u
                    ? "0x03"
                    : "other",
                buffer != NULL && length >= 2u && buffer[1] == 0x00u
                    ? "0x00"
                    : "other"
            );
            log_dispatch_status(
                sequence == 1
                    ? "WORLD_REPLAY_OUTBOUND_ISOLATION_STARTED"
                    : "WORLD_REPLAY_OUTBOUND_SUPPRESSED",
                detail
            );
        }
    }
}

static void capture_inbound_plaintext_record(const BYTE *record) {
    const BYTE *buffer;
    DWORD length;

    if (
        record == NULL ||
        !readable_memory_window(record + 0x08u, sizeof(buffer) + sizeof(length))
    ) {
        if (
            InterlockedCompareExchange(
                &g_plaintext_error_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "PLAINTEXT_PROBE_ERROR",
                "invalid-inbound-record-metadata"
            );
        }
        return;
    }
    buffer = *(const BYTE *const *)(record + 0x08u);
    length = *(const DWORD *)(record + 0x10u);
    capture_plaintext(
        'I',
        buffer,
        length,
        bootstrap_stream_id('I', record),
        NULL
    );
}

typedef struct isac_inbound_candidate_state {
    LONG event;
    unsigned int count;
    const BYTE *buffers[ISAC_MAX_INBOUND_CANDIDATES_PER_EVENT];
    DWORD lengths[ISAC_MAX_INBOUND_CANDIDATES_PER_EVENT];
} isac_inbound_candidate_state;

static void log_inbound_object(
    LONG event,
    const char *role,
    unsigned int depth,
    unsigned int parent_offset,
    const BYTE *object
) {
    char line[640];
    size_t offset;
    unsigned int index;

    if (!readable_memory_window(object, ISAC_INBOUND_OBJECT_BYTES)) {
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_OBJECT event=%ld tick_ms=%llu process=%lu thread=%lu "
        "role=%s depth=%u parent_offset=0x%x length=%u bytes=",
        event,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        role,
        depth,
        parent_offset,
        ISAC_INBOUND_OBJECT_BYTES
    );
    for (
        index = 0;
        index < ISAC_INBOUND_OBJECT_BYTES && offset + 2 < sizeof(line);
        ++index
    ) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)object[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (index != ISAC_INBOUND_OBJECT_BYTES || offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_plaintext_log(line);
}

static void log_inbound_span_candidate(
    isac_inbound_candidate_state *state,
    const char *role,
    unsigned int depth,
    unsigned int object_offset,
    const char *encoding,
    const BYTE *buffer,
    DWORD length
) {
    char line[2304];
    size_t offset;
    unsigned int index;

    if (
        state->count >= ISAC_MAX_INBOUND_CANDIDATES_PER_EVENT ||
        buffer == NULL ||
        length == 0 ||
        length > ISAC_MAX_PLAINTEXT_BYTES ||
        (uintptr_t)buffer > UINTPTR_MAX - length ||
        !readable_memory_window(buffer, length)
    ) {
        return;
    }
    for (index = 0; index < state->count; ++index) {
        if (
            state->buffers[index] == buffer &&
            state->lengths[index] == length
        ) {
            return;
        }
    }
    state->buffers[state->count] = buffer;
    state->lengths[state->count] = length;
    ++state->count;

    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_SPAN_CANDIDATE event=%ld candidate=%u tick_ms=%llu "
        "process=%lu thread=%lu role=%s depth=%u object_offset=0x%x "
        "encoding=%s length=%lu bytes=",
        state->event,
        state->count,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        role,
        depth,
        object_offset,
        encoding,
        (unsigned long)length
    );
    for (index = 0; index < length && offset + 2 < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)buffer[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (index != length || offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_plaintext_log(line);
}

static void scan_inbound_object_spans(
    isac_inbound_candidate_state *state,
    const char *role,
    unsigned int depth,
    const BYTE *object
) {
    unsigned int object_offset;

    if (!readable_memory_window(object, ISAC_INBOUND_OBJECT_BYTES)) {
        return;
    }
    for (
        object_offset = 0;
        object_offset + 16u <= ISAC_INBOUND_OBJECT_BYTES;
        object_offset += sizeof(uintptr_t)
    ) {
        const BYTE *buffer = *(const BYTE *const *)(object + object_offset);
        uintptr_t end = *(const uintptr_t *)(object + object_offset + 8u);
        DWORD length = *(const DWORD *)(object + object_offset + 8u);

        log_inbound_span_candidate(
            state,
            role,
            depth,
            object_offset,
            "pointer-u32",
            buffer,
            length
        );
        if (
            (uintptr_t)buffer < end &&
            end - (uintptr_t)buffer <= ISAC_MAX_PLAINTEXT_BYTES
        ) {
            log_inbound_span_candidate(
                state,
                role,
                depth,
                object_offset,
                "pointer-end",
                buffer,
                (DWORD)(end - (uintptr_t)buffer)
            );
        }
        if (object_offset + 20u <= ISAC_INBOUND_OBJECT_BYTES) {
            length = *(const DWORD *)(object + object_offset + 16u);
            log_inbound_span_candidate(
                state,
                role,
                depth,
                object_offset,
                "pointer-gap-u32",
                buffer,
                length
            );
        }
    }
}

static void capture_inbound_handoff_root(
    isac_inbound_candidate_state *state,
    const char *role,
    const BYTE *object
) {
    const BYTE *nested_objects[ISAC_MAX_INBOUND_NESTED_OBJECTS];
    unsigned int nested_count = 0;
    unsigned int object_offset;

    if (!readable_memory_window(object, ISAC_INBOUND_OBJECT_BYTES)) {
        return;
    }
    log_inbound_object(state->event, role, 0u, 0u, object);
    scan_inbound_object_spans(state, role, 0u, object);
    for (
        object_offset = 0;
        object_offset + sizeof(uintptr_t) <= ISAC_INBOUND_OBJECT_BYTES &&
            nested_count < ISAC_MAX_INBOUND_NESTED_OBJECTS;
        object_offset += sizeof(uintptr_t)
    ) {
        const BYTE *nested = *(const BYTE *const *)(object + object_offset);
        unsigned int index;
        BOOL duplicate = FALSE;

        if (
            nested == NULL ||
            (nested >= g_game_base && nested < g_game_base + g_game_size) ||
            !readable_memory_window(nested, ISAC_INBOUND_OBJECT_BYTES)
        ) {
            continue;
        }
        for (index = 0; index < nested_count; ++index) {
            if (nested_objects[index] == nested) {
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        nested_objects[nested_count++] = nested;
        log_inbound_object(
            state->event,
            role,
            1u,
            object_offset,
            nested
        );
        scan_inbound_object_spans(state, role, 1u, nested);
    }
}

static BOOL decode_inbound_frame_length(
    const BYTE *buffer,
    DWORD available,
    DWORD *frame_length,
    DWORD *prefix_length
) {
    uint64_t value = 0;
    unsigned int shift = 0;
    DWORD index;

    for (index = 0; index < available && index < 10u; ++index) {
        BYTE current = buffer[index];

        if (shift >= 64u && (current & 0x7fu) != 0) {
            return FALSE;
        }
        value |= (uint64_t)(current & 0x7fu) << shift;
        if ((current & 0x80u) == 0) {
            if (
                (value & 1u) != 0 ||
                (value >> 1u) > ISAC_MAX_PLAINTEXT_BYTES - (index + 1u)
            ) {
                return FALSE;
            }
            *prefix_length = index + 1u;
            *frame_length = (DWORD)(value >> 1u) + *prefix_length;
            return TRUE;
        }
        shift += 7u;
    }
    return FALSE;
}

static void log_inbound_frame_error(const char *detail) {
    if (
        InterlockedCompareExchange(
            &g_inbound_frame_error_logged,
            1,
            0
        ) == 0
    ) {
        log_plaintext_status("PLAINTEXT_PROBE_ERROR", detail);
    }
}

static void capture_inbound_frame(
    const BYTE *reader,
    const BYTE *source
) {
    const BYTE *buffer_object;
    const BYTE *buffer;
    DWORD buffer_length;
    DWORD cursor;
    DWORD prefix_length;
    DWORD frame_length;
    DWORD available;

    if (
        reader == NULL ||
        source == NULL ||
        !readable_memory_window(source + 0x48u, 0x0cu)
    ) {
        log_inbound_frame_error("invalid-inbound-frame-source");
        return;
    }
    buffer_object = *(const BYTE *const *)(source + 0x48u);
    cursor = *(const DWORD *)(source + 0x50u);
    if (buffer_object == NULL) {
        return;
    }
    if (!readable_memory_window(buffer_object, 0x10u)) {
        log_inbound_frame_error("invalid-inbound-frame-buffer-object");
        return;
    }
    buffer_length = *(const DWORD *)(buffer_object + 0x0cu);
    buffer = buffer_object + 0x10u;
    if (
        cursor > buffer_length ||
        buffer_length > 0x10000u ||
        !readable_memory_window(buffer, buffer_length)
    ) {
        log_inbound_frame_error("invalid-inbound-frame-window");
        return;
    }
    if (InterlockedCompareExchange(&g_inbound_frame_lock, 1, 0) != 0) {
        log_inbound_frame_error("inbound-frame-lock-contention");
        return;
    }

    if (g_inbound_pending_length != 0) {
        DWORD needed;
        DWORD continuation;

        if (g_inbound_pending_reader != reader) {
            g_inbound_pending_length = 0;
            g_inbound_pending_expected = 0;
            g_inbound_pending_reader = NULL;
            InterlockedExchange(&g_inbound_frame_lock, 0);
            log_inbound_frame_error("inbound-frame-reader-changed");
            return;
        }
        needed = g_inbound_pending_expected - g_inbound_pending_length;
        continuation = cursor < needed ? cursor : needed;
        CopyMemory(
            g_inbound_pending + g_inbound_pending_length,
            buffer,
            continuation
        );
        g_inbound_pending_length += continuation;
        if (g_inbound_pending_length == g_inbound_pending_expected) {
            capture_plaintext(
                'I',
                g_inbound_pending,
                g_inbound_pending_expected,
                bootstrap_stream_id('I', reader),
                NULL
            );
            g_inbound_pending_length = 0;
            g_inbound_pending_expected = 0;
            g_inbound_pending_reader = NULL;
        } else {
            InterlockedExchange(&g_inbound_frame_lock, 0);
            return;
        }
    }

    if (cursor == buffer_length) {
        InterlockedExchange(&g_inbound_frame_lock, 0);
        return;
    }
    available = buffer_length - cursor;
    if (!decode_inbound_frame_length(
            buffer + cursor,
            available,
            &frame_length,
            &prefix_length
        )) {
        InterlockedExchange(&g_inbound_frame_lock, 0);
        if (
            g_bootstrap_probe_enabled &&
            g_plaintext_world_active == 0
        ) {
            capture_plaintext(
                'I',
                buffer + cursor,
                available,
                bootstrap_stream_id('I', reader),
                NULL
            );
            return;
        }
        log_inbound_frame_error("invalid-inbound-frame-length");
        return;
    }
    (void)prefix_length;
    if (frame_length <= available) {
        capture_plaintext(
            'I',
            buffer + cursor,
            frame_length,
            bootstrap_stream_id('I', reader),
            NULL
        );
    } else {
        CopyMemory(g_inbound_pending, buffer + cursor, available);
        g_inbound_pending_reader = reader;
        g_inbound_pending_expected = frame_length;
        g_inbound_pending_length = available;
    }
    InterlockedExchange(&g_inbound_frame_lock, 0);
}

static void capture_inbound_source_vtable(const BYTE *reader) {
    const BYTE *const *vtable;
    uintptr_t vtable_rva;
    unsigned int slot;
    char line[768];
    size_t offset;
    BYTE *cursor;
    BYTE *image_end;
    unsigned int xref_count = 0;
    LONG capture_index;
    LONG existing_index;

    if (
        reader == NULL ||
        !readable_memory_window(reader, sizeof(vtable))
    ) {
        return;
    }
    vtable = *(const BYTE *const *const *)reader;
    if (
        vtable == NULL ||
        (const BYTE *)vtable < g_game_base ||
        (const BYTE *)vtable >= g_game_base + g_game_size ||
        !readable_memory_window(
            vtable,
            ISAC_MAX_INBOUND_VTABLE_SLOTS * sizeof(*vtable)
        )
    ) {
        log_dispatch_status(
            "INBOUND_SOURCE_VTABLE_ERROR",
            "reader-vtable-outside-game"
        );
        return;
    }
    vtable_rva = (uintptr_t)((const BYTE *)vtable - g_game_base);
    if (
        InterlockedCompareExchange(
            &g_inbound_source_vtable_lock,
            1,
            0
        ) != 0
    ) {
        return;
    }
    for (
        existing_index = 0;
        existing_index < g_inbound_source_vtable_count;
        ++existing_index
    ) {
        if (g_inbound_source_vtables[existing_index] == vtable_rva) {
            InterlockedExchange(&g_inbound_source_vtable_lock, 0);
            return;
        }
    }
    if (g_inbound_source_vtable_count >= (LONG)ISAC_MAX_INBOUND_VTABLES) {
        InterlockedExchange(&g_inbound_source_vtable_lock, 0);
        if (
            InterlockedCompareExchange(
                &g_inbound_source_vtable_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_SOURCE_VTABLE_LIMIT",
                "vtable-capacity-reached"
            );
        }
        return;
    }
    capture_index = g_inbound_source_vtable_count;
    g_inbound_source_vtables[capture_index] = vtable_rva;
    g_inbound_source_vtable_count = capture_index + 1;
    InterlockedExchange(&g_inbound_source_vtable_lock, 0);
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_SOURCE_VTABLE tick_ms=%llu process=%lu thread=%lu "
        "sequence=%ld vtable_rva=0x%llx slot_count=%u slot_rvas=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        capture_index + 1,
        (unsigned long long)vtable_rva,
        ISAC_MAX_INBOUND_VTABLE_SLOTS
    );
    for (
        slot = 0;
        slot < ISAC_MAX_INBOUND_VTABLE_SLOTS && offset < sizeof(line);
        ++slot
    ) {
        uintptr_t target_rva = 0;
        int written;

        if (
            vtable[slot] >= g_game_base &&
            vtable[slot] < g_game_base + g_game_size
        ) {
            target_rva = (uintptr_t)(vtable[slot] - g_game_base);
        }
        written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            slot == 0 ? "" : ",",
            (unsigned long long)target_rva
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            return;
        }
        offset += (size_t)written;
    }
    if (offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);

    if (
        InterlockedCompareExchange(
            &g_inbound_source_setup_code_captured,
            1,
            0
        ) == 0
    ) {
        capture_inbound_reader_forward_window(
            "source-object-constructor",
            ISAC_SOURCE_OBJECT_CONSTRUCTOR_RVA
        );
        capture_inbound_reader_function(
            "source-object-constructor",
            ISAC_SOURCE_OBJECT_CONSTRUCTOR_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-constructor-a",
            ISAC_READER_CONSTRUCTOR_A_RVA
        );
        capture_inbound_reader_function(
            "reader-constructor-a",
            ISAC_READER_CONSTRUCTOR_A_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-constructor-b",
            ISAC_READER_CONSTRUCTOR_B_RVA
        );
        capture_inbound_reader_function(
            "reader-constructor-b",
            ISAC_READER_CONSTRUCTOR_B_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-setup-a",
            ISAC_READER_SETUP_A_RVA
        );
        capture_inbound_reader_function(
            "reader-setup-a",
            ISAC_READER_SETUP_A_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-setup-b",
            ISAC_READER_SETUP_B_RVA
        );
        capture_inbound_reader_function(
            "reader-setup-b",
            ISAC_READER_SETUP_B_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-register",
            ISAC_READER_REGISTER_RVA
        );
        capture_inbound_reader_function(
            "reader-register",
            ISAC_READER_REGISTER_RVA
        );
        capture_inbound_reader_forward_window(
            "registration-constructor",
            ISAC_REGISTRATION_CONSTRUCTOR_RVA
        );
        capture_inbound_reader_function(
            "registration-constructor",
            ISAC_REGISTRATION_CONSTRUCTOR_RVA
        );
    }

    for (slot = 0; slot < ISAC_MAX_INBOUND_VTABLE_SLOTS; ++slot) {
        if (
            vtable[slot] >= g_game_base &&
            vtable[slot] < g_game_base + g_game_size
        ) {
            capture_queue_code_anchor(
                "vtable-method",
                (BYTE *)vtable[slot],
                (uintptr_t)(vtable[slot] - g_game_base)
            );
        }
    }

    cursor = g_game_base;
    image_end = g_game_base + g_game_size;
    while (cursor < image_end && xref_count < ISAC_MAX_INBOUND_VTABLE_XREFS) {
        MEMORY_BASIC_INFORMATION memory;
        BYTE *region_start;
        BYTE *region_end;
        BYTE *instruction;
        DWORD protection;

        if (VirtualQuery(cursor, &memory, sizeof(memory)) != sizeof(memory)) {
            break;
        }
        region_start = (BYTE *)memory.BaseAddress;
        region_end = region_start + memory.RegionSize;
        if (region_start < g_game_base) {
            region_start = g_game_base;
        }
        if (region_end > image_end) {
            region_end = image_end;
        }
        protection = memory.Protect & 0xffu;
        if (
            memory.State == MEM_COMMIT &&
            (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
            (
                protection == PAGE_EXECUTE ||
                protection == PAGE_EXECUTE_READ ||
                protection == PAGE_EXECUTE_READWRITE ||
                protection == PAGE_EXECUTE_WRITECOPY
            ) &&
            region_end >= region_start + 7u
        ) {
            for (
                instruction = region_start;
                instruction + 7u <= region_end &&
                    xref_count < ISAC_MAX_INBOUND_VTABLE_XREFS;
                ++instruction
            ) {
                int32_t displacement;
                const BYTE *resolved;
                uintptr_t instruction_rva;
                int length;

                if (
                    (instruction[0] & 0xf8u) != 0x48u ||
                    instruction[1] != 0x8du ||
                    (instruction[2] & 0xc7u) != 0x05u
                ) {
                    continue;
                }
                CopyMemory(&displacement, instruction + 3u, sizeof(displacement));
                resolved = instruction + 7 + (intptr_t)displacement;
                if (resolved != (const BYTE *)vtable) {
                    continue;
                }
                instruction_rva = (uintptr_t)(instruction - g_game_base);
                length = snprintf(
                    line,
                    sizeof(line),
                    "INBOUND_SOURCE_VTABLE_XREF tick_ms=%llu process=%lu "
                    "thread=%lu vtable_sequence=%ld sequence=%u "
                    "instruction_rva=0x%llx\r\n",
                    (unsigned long long)GetTickCount64(),
                    (unsigned long)GetCurrentProcessId(),
                    (unsigned long)GetCurrentThreadId(),
                    capture_index + 1,
                    xref_count + 1u,
                    (unsigned long long)instruction_rva
                );
                if (length > 0 && (size_t)length < sizeof(line)) {
                    append_dispatch_log(line);
                }
                capture_queue_code_anchor(
                    "reader-vtable-xref",
                    instruction,
                    instruction_rva
                );
                ++xref_count;
            }
        }
        if (region_end <= cursor) {
            break;
        }
        cursor = region_end;
    }
    snprintf(
        line,
        sizeof(line),
        "INBOUND_SOURCE_VTABLE_XREF_SUMMARY tick_ms=%llu process=%lu "
        "thread=%lu vtable_sequence=%ld count=%u limit=%u "
        "payloads=disabled\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        capture_index + 1,
        xref_count,
        ISAC_MAX_INBOUND_VTABLE_XREFS
    );
    append_dispatch_log(line);
}

static BOOL capture_inbound_registration_handle(
    const char *role,
    const BYTE *handle
) {
    const BYTE *const *vtable;
    uintptr_t vtable_rva;
    unsigned int method;
    char line[384];

    if (role == NULL) {
        return FALSE;
    }
    if (
        handle == NULL ||
        !readable_memory_window(handle, sizeof(vtable))
    ) {
        snprintf(
            line,
            sizeof(line),
            "INBOUND_REGISTRATION_HANDLE tick_ms=%llu process=%lu "
            "thread=%lu role=%s state=absent payloads=disabled\r\n",
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            role
        );
        append_dispatch_log(line);
        return FALSE;
    }
    vtable = *(const BYTE *const *const *)handle;
    if (
        vtable == NULL ||
        (const BYTE *)vtable < g_game_base ||
        (const BYTE *)vtable >= g_game_base + g_game_size ||
        !readable_memory_window(vtable, 3u * sizeof(*vtable))
    ) {
        snprintf(
            line,
            sizeof(line),
            "INBOUND_REGISTRATION_HANDLE tick_ms=%llu process=%lu "
            "thread=%lu role=%s state=non-object payloads=disabled\r\n",
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            role
        );
        append_dispatch_log(line);
        return FALSE;
    }
    for (method = 0; method < 3u; ++method) {
        if (
            vtable[method] < g_game_base ||
            vtable[method] >= g_game_base + g_game_size ||
            !readable_code_window(vtable[method], 1u)
        ) {
            snprintf(
                line,
                sizeof(line),
                "INBOUND_REGISTRATION_HANDLE tick_ms=%llu process=%lu "
                "thread=%lu role=%s state=non-object "
                "payloads=disabled\r\n",
                (unsigned long long)GetTickCount64(),
                (unsigned long)GetCurrentProcessId(),
                (unsigned long)GetCurrentThreadId(),
                role
            );
            append_dispatch_log(line);
            return FALSE;
        }
    }
    vtable_rva = (uintptr_t)((const BYTE *)vtable - g_game_base);
    snprintf(
        line,
        sizeof(line),
        "INBOUND_REGISTRATION_HANDLE tick_ms=%llu process=%lu thread=%lu "
        "role=%s state=object vtable_rva=0x%llx payloads=disabled\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        role,
        (unsigned long long)vtable_rva
    );
    append_dispatch_log(line);
    capture_inbound_source_vtable(handle);
    return TRUE;
}

static void capture_inbound_registration_object(CONTEXT *context) {
    const BYTE *object;
    const BYTE *resolved_context;
    size_t object_offset;
    unsigned int interface_count = 0;
    unsigned int handle_count = 0;
    char line[384];

    if (
        !g_inbound_source_probe_enabled ||
        context == NULL ||
        InterlockedCompareExchange(
            &g_inbound_registration_object_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    object = (const BYTE *)(uintptr_t)context->Rax;
    if (
        object == NULL ||
        !readable_memory_window(object, ISAC_REGISTRATION_OBJECT_BYTES)
    ) {
        log_dispatch_status(
            "INBOUND_REGISTRATION_OBJECT_ERROR",
            "invalid-registration-object"
        );
        return;
    }
    for (
        object_offset = 0;
        object_offset + sizeof(void *) <= ISAC_REGISTRATION_OBJECT_BYTES;
        object_offset += sizeof(void *)
    ) {
        const BYTE *const *vtable = *(const BYTE *const *const *)(
            object + object_offset
        );
        uintptr_t vtable_rva;
        unsigned int method;
        BOOL valid = TRUE;

        if (
            vtable == NULL ||
            (const BYTE *)vtable < g_game_base ||
            (const BYTE *)vtable >= g_game_base + g_game_size ||
            !readable_memory_window(vtable, 3u * sizeof(*vtable))
        ) {
            continue;
        }
        for (method = 0; method < 3u; ++method) {
            if (
                vtable[method] < g_game_base ||
                vtable[method] >= g_game_base + g_game_size ||
                !readable_code_window(vtable[method], 1u)
            ) {
                valid = FALSE;
                break;
            }
        }
        if (!valid) {
            continue;
        }
        vtable_rva = (uintptr_t)((const BYTE *)vtable - g_game_base);
        snprintf(
            line,
            sizeof(line),
            "INBOUND_REGISTRATION_INTERFACE tick_ms=%llu process=%lu "
            "thread=%lu sequence=%u object_offset=0x%llx "
            "vtable_rva=0x%llx payloads=disabled\r\n",
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            interface_count + 1u,
            (unsigned long long)object_offset,
            (unsigned long long)vtable_rva
        );
        append_dispatch_log(line);
        capture_inbound_source_vtable(object + object_offset);
        ++interface_count;
    }
    resolved_context = *(const BYTE *const *)(object + 0x90u);
    if (capture_inbound_registration_handle(
            "transport-reference",
            (const BYTE *)(uintptr_t)context->Rbp
        )) {
        ++handle_count;
    }
    if (capture_inbound_registration_handle(
            "registration-input",
            (const BYTE *)(uintptr_t)context->R14
        )) {
        ++handle_count;
    }
    if (capture_inbound_registration_handle(
            "resolved-context",
            resolved_context
        )) {
        ++handle_count;
    }
    snprintf(
        line,
        sizeof(line),
        "INBOUND_REGISTRATION_OBJECT tick_ms=%llu process=%lu thread=%lu "
        "size=0x98 interface_count=%u handle_count=%u "
        "payloads=disabled\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        interface_count,
        handle_count
    );
    append_dispatch_log(line);
}

static void record_inbound_transport_delivery(CONTEXT *context) {
    uintptr_t rvas[ISAC_MAX_CONTROL_STACK_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    const BYTE *chain_reference;
    const BYTE *chunk = NULL;
    uint64_t total_length = 0;
    DWORD first_length = 0;
    unsigned int chunk_count = 0;
    BOOL complete = TRUE;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char line[1024];
    size_t offset;

    if (!g_inbound_source_probe_enabled || context == NULL) {
        return;
    }
    sequence = InterlockedIncrement(&g_inbound_transport_delivery_count);
    if (sequence > (LONG)ISAC_MAX_INBOUND_DELIVERY_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_inbound_transport_delivery_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_TRANSPORT_DELIVERY_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    chain_reference = (const BYTE *)(uintptr_t)context->Rdx;
    if (!readable_memory_window(chain_reference, sizeof(chunk))) {
        complete = FALSE;
    } else {
        chunk = *(const BYTE *const *)chain_reference;
    }
    while (chunk != NULL && chunk_count < ISAC_MAX_INBOUND_DELIVERY_CHUNKS) {
        const BYTE *next;
        DWORD chunk_length;

        if (
            !readable_memory_window(chunk + 0x0cu, sizeof(chunk_length)) ||
            !readable_memory_window(chunk + 0x3f8u, sizeof(next))
        ) {
            complete = FALSE;
            break;
        }
        chunk_length = *(const DWORD *)(chunk + 0x0cu);
        next = *(const BYTE *const *)(chunk + 0x3f8u);
        if (chunk_count == 0u) {
            first_length = chunk_length;
        }
        total_length += chunk_length;
        ++chunk_count;
        if (next == chunk) {
            complete = FALSE;
            break;
        }
        chunk = next;
    }
    if (chunk != NULL && chunk_count == ISAC_MAX_INBOUND_DELIVERY_CHUNKS) {
        complete = FALSE;
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_MAX_CONTROL_STACK_FRAMES,
        &function_rva,
        &function_end_rva
    );
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_TRANSPORT_DELIVERY sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu function_rva=0x%llx function_end_rva=0x%llx "
        "chunk_count=%u first_length=%lu total_length=%llu complete=%s "
        "frame_count=%u rvas=",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        chunk_count,
        (unsigned long)first_length,
        (unsigned long long)total_length,
        complete ? "yes" : "no",
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            return;
        }
        offset += (size_t)written;
    }
    if (offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    if (sequence == 1) {
        capture_inbound_reader_forward_window(
            "transport-delivery",
            ISAC_INBOUND_TRANSPORT_DELIVERY_RVA
        );
        capture_inbound_reader_function(
            "transport-delivery",
            ISAC_INBOUND_TRANSPORT_DELIVERY_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-lock",
            ISAC_INBOUND_READER_LOCK_RVA
        );
        capture_inbound_reader_function(
            "reader-lock",
            ISAC_INBOUND_READER_LOCK_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-notify",
            ISAC_INBOUND_READER_NOTIFY_RVA
        );
        capture_inbound_reader_function(
            "reader-notify",
            ISAC_INBOUND_READER_NOTIFY_RVA
        );
        capture_inbound_reader_forward_window(
            "reader-unlock",
            ISAC_INBOUND_READER_UNLOCK_RVA
        );
        capture_inbound_reader_function(
            "reader-unlock",
            ISAC_INBOUND_READER_UNLOCK_RVA
        );
    }
}

static void record_inbound_source_append(CONTEXT *context) {
    uintptr_t rvas[ISAC_MAX_CONTROL_STACK_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    DWORD byte_length;
    BOOL readable;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char line[1024];
    size_t offset;

    if (!g_inbound_source_probe_enabled || context == NULL) {
        return;
    }
    sequence = InterlockedIncrement(&g_inbound_source_append_count);
    if (sequence > (LONG)ISAC_MAX_INBOUND_DELIVERY_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_inbound_source_append_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_SOURCE_APPEND_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    byte_length = (DWORD)context->R8;
    readable = byte_length == 0u || (
        byte_length <= 0x100000u &&
        readable_memory_window(
            (const BYTE *)(uintptr_t)context->Rdx,
            byte_length
        )
    );
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_MAX_CONTROL_STACK_FRAMES,
        &function_rva,
        &function_end_rva
    );
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_SOURCE_APPEND sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu function_rva=0x%llx function_end_rva=0x%llx "
        "byte_length=%lu readable=%s frame_count=%u rvas=",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        (unsigned long)byte_length,
        readable ? "yes" : "no",
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            return;
        }
        offset += (size_t)written;
    }
    if (offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    if (sequence == 1) {
        capture_inbound_reader_forward_window(
            "source-append",
            ISAC_INBOUND_SOURCE_APPEND_RVA
        );
        capture_inbound_reader_function(
            "source-append",
            ISAC_INBOUND_SOURCE_APPEND_RVA
        );
    }
}

static void activate_inbound_source_advance(
    const BYTE *reader,
    CONTEXT *context
) {
    if (
        !g_inbound_source_probe_enabled ||
        reader == NULL ||
        context == NULL ||
        !readable_memory_window(reader, sizeof(void *))
    ) {
        return;
    }
    capture_inbound_source_vtable(reader);
    context->Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_INBOUND_ADVANCE_RVA
    );
    context->Dr7 = (context->Dr7 & ~(DWORD64)0x000f0003u) | 0x1u;
    if (
        InterlockedCompareExchange(
            &g_inbound_source_advance_ready_logged,
            1,
            0
        ) == 0
    ) {
        log_dispatch_status(
            "INBOUND_SOURCE_ADVANCE_READY",
            "reader-advance-rva=0x9a851,vtable-offset=0x38,"
            "payloads=disabled"
        );
    }
}

static void capture_inbound_source_advance(CONTEXT *context) {
    const BYTE *reader;
    const BYTE *const *vtable;
    const BYTE *target;
    uintptr_t target_rva;
    char line[320];
    int length;

    if (!g_inbound_source_probe_enabled || context == NULL) {
        return;
    }
    reader = (const BYTE *)(uintptr_t)context->Rdi;
    if (
        reader == NULL ||
        !readable_memory_window(reader, sizeof(vtable)) ||
        !readable_memory_window(reader + 0x70u, sizeof(void *))
    ) {
        log_dispatch_status(
            "INBOUND_SOURCE_ADVANCE_ERROR",
            "invalid-reader-object"
        );
        return;
    }
    vtable = *(const BYTE *const *const *)reader;
    if (
        vtable == NULL ||
        !readable_memory_window(vtable, 8u * sizeof(*vtable))
    ) {
        log_dispatch_status(
            "INBOUND_SOURCE_ADVANCE_ERROR",
            "invalid-reader-vtable"
        );
        return;
    }
    target = vtable[7];
    if (
        target < g_game_base ||
        target >= g_game_base + g_game_size ||
        !readable_code_window(target, 1u)
    ) {
        log_dispatch_status(
            "INBOUND_SOURCE_ADVANCE_ERROR",
            "advance-target-outside-game"
        );
        return;
    }
    target_rva = (uintptr_t)(target - g_game_base);
    if (
        InterlockedCompareExchange(
            &g_inbound_source_advance_captured,
            1,
            0
        ) == 0
    ) {
        length = snprintf(
            line,
            sizeof(line),
            "INBOUND_SOURCE_ADVANCE tick_ms=%llu process=%lu thread=%lu "
            "vtable_offset=0x38 target_rva=0x%llx payloads=disabled\r\n",
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            (unsigned long long)target_rva
        );
        if (length > 0 && (size_t)length < sizeof(line)) {
            append_dispatch_log(line);
        }
        capture_inbound_reader_forward_window(
            "source-advance",
            target_rva
        );
        capture_inbound_reader_function("source-advance", target_rva);
    }
    if (
        InterlockedCompareExchange(
            &g_inbound_source_watch_ready_logged,
            1,
            0
        ) == 0
    ) {
        log_dispatch_status(
            "INBOUND_SOURCE_WATCH_READY",
            "transport-delivery-rva=0x84bd0,"
            "source-append-rva=0x223d140,per-thread=enabled,"
            "payloads=disabled"
        );
    }
}

static void record_inbound_source_write(CONTEXT *context) {
    uintptr_t rvas[ISAC_MAX_CONTROL_STACK_FRAMES];
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t instruction_rva = 0;
    USHORT depth;
    USHORT index;
    LONG sequence;
    char line[1024];
    size_t offset;

    if (!g_inbound_source_probe_enabled || context == NULL) {
        return;
    }
    if (
        context->Rip >= (DWORD64)(uintptr_t)g_game_base &&
        context->Rip < (DWORD64)(uintptr_t)(g_game_base + g_game_size)
    ) {
        instruction_rva = (uintptr_t)(
            context->Rip - (DWORD64)(uintptr_t)g_game_base
        );
    }
    depth = unwind_queue_producer_callers(
        context,
        rvas,
        ISAC_MAX_CONTROL_STACK_FRAMES,
        &function_rva,
        &function_end_rva
    );
    sequence = InterlockedIncrement(&g_inbound_source_event_count);
    if (sequence > (LONG)ISAC_MAX_INBOUND_SOURCE_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_inbound_source_event_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_SOURCE_WRITE_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "INBOUND_SOURCE_WRITE sequence=%ld tick_ms=%llu process=%lu "
        "thread=%lu instruction_rva=0x%llx function_rva=0x%llx "
        "function_end_rva=0x%llx frame_count=%u rvas=",
        sequence,
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)instruction_rva,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            return;
        }
        offset += (size_t)written;
    }
    if (offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);

    if (instruction_rva != 0) {
        capture_queue_code_anchor(
            "inbound-source-write",
            g_game_base + instruction_rva,
            instruction_rva
        );
    }
    for (index = 0; index < depth; ++index) {
        capture_queue_code_anchor(
            "inbound-source-caller",
            g_game_base + rvas[index],
            rvas[index]
        );
    }
}

static void capture_inbound_handoff(CONTEXT *context) {
    const BYTE *reader = (const BYTE *)(uintptr_t)context->Rdi;
    const BYTE *destination = (const BYTE *)(uintptr_t)context->Rsi;
    const BYTE *source;
    USHORT control_type_id = 0;
    DWORD control_frame_length = 0;
    DWORD control_absolute_cursor = 0;
    DWORD control_local_cursor = 0;
    LONG event;
    isac_inbound_candidate_state state;

    if (
        !g_plaintext_probe_enabled ||
        (
            g_plaintext_world_active == 0 &&
            !g_bootstrap_probe_enabled
        ) ||
        reader == NULL ||
        !readable_memory_window(reader + 0x70u, sizeof(source))
    ) {
        return;
    }
    source = *(const BYTE *const *)(reader + 0x70u);
    if (!g_bootstrap_type3_probe_enabled) {
        activate_inbound_source_advance(reader, context);
    }
    capture_inbound_source_vtable(source);
    if (
        g_control_probe_enabled &&
        peek_control_frame(
            source,
            &control_type_id,
            &control_frame_length,
            &control_absolute_cursor,
            &control_local_cursor
        )
    ) {
        record_control_path(
            context,
            reader,
            control_type_id,
            control_frame_length,
            control_absolute_cursor,
            control_local_cursor
        );
    }
    capture_inbound_frame(reader, source);
    if (g_plaintext_world_active == 0) {
        return;
    }

    event = InterlockedIncrement(&g_inbound_handoff_count);
    if (event > (LONG)ISAC_MAX_INBOUND_HANDOFF_EVENTS) {
        if (
            InterlockedCompareExchange(
                &g_inbound_handoff_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_plaintext_status(
                "INBOUND_HANDOFF_LIMIT",
                "event-capacity-reached"
            );
        }
        return;
    }
    ZeroMemory(&state, sizeof(state));
    state.event = event;
    capture_inbound_handoff_root(&state, "source", source);
    capture_inbound_handoff_root(&state, "destination", destination);

    if (
        InterlockedCompareExchange(
            &g_inbound_handoff_code_captured,
            1,
            0
        ) == 0
    ) {
        capture_inbound_reader_forward_window(
            "virtual-context-copy",
            0x223ebb0u
        );
        capture_inbound_reader_function(
            "virtual-context-copy",
            0x223ebb0u
        );
    }
}

static void capture_bootstrap_type3_read_entry(CONTEXT *context) {
    const BYTE *reader;
    const BYTE *source;
    USHORT type_id = 0;
    DWORD frame_length = 0;
    DWORD absolute_cursor = 0;
    DWORD local_cursor = 0;

    if (
        (
            !g_bootstrap_type3_probe_enabled &&
            !g_local_bridge_injection_enabled
        ) ||
        context == NULL
    ) {
        return;
    }
    reader = (const BYTE *)(uintptr_t)context->Rcx;
    if (
        reader == NULL ||
        !readable_memory_window(reader + 0x70u, sizeof(source))
    ) {
        return;
    }
    source = *(const BYTE *const *)(reader + 0x70u);
    if (
        peek_control_frame(
            source,
            &type_id,
            &frame_length,
            &absolute_cursor,
            &local_cursor
        ) &&
        type_id == 0x0003u
    ) {
        record_control_path(
            context,
            reader,
            type_id,
            frame_length,
            absolute_cursor,
            local_cursor
        );
    }
}

static uintptr_t schema_method_rva(const BYTE *const *vtable, size_t slot) {
    const BYTE *target = vtable[slot];

    if (target < g_game_base || target >= g_game_base + g_game_size) {
        return 0;
    }
    return (uintptr_t)(target - g_game_base);
}

static uintptr_t resolve_schema_thunk(
    uintptr_t target_rva,
    intptr_t *object_adjustment,
    unsigned int *resolution_steps
) {
    uintptr_t current = target_rva;
    intptr_t adjustment = 0;
    unsigned int steps = 0;

    while (steps < 4u) {
        const BYTE *code;
        unsigned int jump_offset = 0;
        unsigned int instruction_length = 0;
        intptr_t current_adjustment = 0;
        int32_t displacement;
        uintptr_t next;

        if (
            current >= g_game_size ||
            g_game_size - current < 16u
        ) {
            break;
        }
        code = g_game_base + current;
        if (!readable_code_window(code, 16u)) {
            break;
        }
        if (
            code[0] == 0x48u && code[1] == 0x83u &&
            code[2] == 0xc1u && code[4] == 0xe9u
        ) {
            current_adjustment = (int8_t)code[3];
            jump_offset = 4u;
            instruction_length = 9u;
        } else if (
            code[0] == 0x48u && code[1] == 0x81u &&
            code[2] == 0xc1u && code[7] == 0xe9u
        ) {
            int32_t immediate;

            CopyMemory(&immediate, code + 3u, sizeof(immediate));
            current_adjustment = immediate;
            jump_offset = 7u;
            instruction_length = 12u;
        } else if (code[0] == 0xe9u) {
            jump_offset = 0u;
            instruction_length = 5u;
        } else {
            break;
        }
        CopyMemory(
            &displacement,
            code + jump_offset + 1u,
            sizeof(displacement)
        );
        next = (uintptr_t)(
            (intptr_t)(current + instruction_length) +
            (intptr_t)displacement
        );
        if (next >= g_game_size || next == current) {
            break;
        }
        adjustment += current_adjustment;
        current = next;
        ++steps;
    }
    *object_adjustment = adjustment;
    *resolution_steps = steps;
    return current;
}

static void capture_schema_code(USHORT type_id, uintptr_t target_rva) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t resolved_rva;
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t available;
    intptr_t object_adjustment;
    unsigned int resolution_steps;
    BYTE *start;
    unsigned int length;
    BOOL truncated;
    BOOL exact_range = FALSE;
    char line[8704];
    size_t offset;
    unsigned int index;

    resolved_rva = resolve_schema_thunk(
        target_rva,
        &object_adjustment,
        &resolution_steps
    );
    function_rva = resolved_rva;
    if (resolution_steps != 0u) {
        int line_length = snprintf(
            line,
            sizeof(line),
            "SCHEMA_RESOLUTION tick_ms=%llu process=%lu thread=%lu "
            "type_id=0x%04x target_rva=0x%llx resolved_rva=0x%llx "
            "object_adjustment=%lld steps=%u\r\n",
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            (unsigned int)type_id,
            (unsigned long long)target_rva,
            (unsigned long long)resolved_rva,
            (long long)object_adjustment,
            resolution_steps
        );
        if (line_length > 0 && (size_t)line_length < sizeof(line)) {
            append_dispatch_log(line);
        }
    }

    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + resolved_rva),
        &image_base,
        NULL
    );
    if (
        function_entry != NULL &&
        image_base == (DWORD64)(uintptr_t)g_game_base
    ) {
        function_rva = (uintptr_t)function_entry->BeginAddress;
        function_end_rva = (uintptr_t)function_entry->EndAddress;
        exact_range = TRUE;
    } else {
        function_end_rva = resolved_rva + ISAC_MAX_SCHEMA_CODE_BYTES;
    }
    if (
        function_rva >= function_end_rva ||
        function_end_rva > g_game_size
    ) {
        log_dispatch_status("SCHEMA_CODE_ERROR", "invalid-function-range");
        return;
    }
    available = function_end_rva - function_rva;
    truncated = !exact_range || available > ISAC_MAX_SCHEMA_CODE_BYTES;
    length = truncated
        ? ISAC_MAX_SCHEMA_CODE_BYTES
        : (unsigned int)available;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status("SCHEMA_CODE_ERROR", "function-window-unreadable");
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "SCHEMA_CODE tick_ms=%llu process=%lu thread=%lu "
        "type_id=0x%04x target_rva=0x%llx function_rva=0x%llx "
        "function_end_rva=0x%llx length=%u truncated=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long long)target_rva,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length,
        truncated ? 1u : 0u
    );
    for (index = 0; index < length && offset + 2 < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2;
    }
    if (index != length || offset + 2 >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void capture_schema_helper_code(uintptr_t target_rva) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t resolved_rva;
    uintptr_t function_rva;
    uintptr_t function_end_rva;
    uintptr_t available;
    intptr_t object_adjustment;
    unsigned int resolution_steps;
    BYTE *start;
    unsigned int length;
    BOOL truncated;
    BOOL exact_range = FALSE;
    char line[4608];
    size_t offset;
    unsigned int index;

    resolved_rva = resolve_schema_thunk(
        target_rva,
        &object_adjustment,
        &resolution_steps
    );
    function_rva = resolved_rva;
    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + resolved_rva),
        &image_base,
        NULL
    );
    if (
        function_entry != NULL &&
        image_base == (DWORD64)(uintptr_t)g_game_base
    ) {
        function_rva = (uintptr_t)function_entry->BeginAddress;
        function_end_rva = (uintptr_t)function_entry->EndAddress;
        exact_range = TRUE;
    } else {
        function_end_rva = resolved_rva + ISAC_MAX_SCHEMA_HELPER_CODE_BYTES;
    }
    if (
        function_rva >= function_end_rva ||
        function_end_rva > g_game_size
    ) {
        log_dispatch_status(
            "SCHEMA_HELPER_CODE_ERROR",
            "invalid-function-range"
        );
        return;
    }
    available = function_end_rva - function_rva;
    truncated = !exact_range || available > ISAC_MAX_SCHEMA_HELPER_CODE_BYTES;
    length = available > ISAC_MAX_SCHEMA_HELPER_CODE_BYTES
        ? ISAC_MAX_SCHEMA_HELPER_CODE_BYTES
        : (unsigned int)available;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "SCHEMA_HELPER_CODE_ERROR",
            "function-window-unreadable"
        );
        return;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "SCHEMA_HELPER_CODE tick_ms=%llu process=%lu thread=%lu "
        "target_rva=0x%llx resolved_rva=0x%llx "
        "object_adjustment=%lld steps=%u function_rva=0x%llx "
        "function_end_rva=0x%llx length=%u truncated=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)target_rva,
        (unsigned long long)resolved_rva,
        (long long)object_adjustment,
        resolution_steps,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length,
        truncated ? 1u : 0u
    );
    for (index = 0; index < length && offset + 2u < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return;
        }
        offset += 2u;
    }
    if (index != length || offset + 2u >= sizeof(line)) {
        return;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
}

static void capture_all_schema_helper_code(void) {
    unsigned int index;

    if (
        !g_schema_field_probe_enabled ||
        InterlockedCompareExchange(
            &g_schema_helper_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    for (index = 0; index < ISAC_MAX_SCHEMA_FIELD_HELPERS; ++index) {
        capture_schema_helper_code(g_schema_field_helpers[index]);
    }
}

static BOOL schema_field_helper_allowed(uintptr_t target_rva) {
    unsigned int index;

    for (index = 0; index < ISAC_MAX_SCHEMA_FIELD_HELPERS; ++index) {
        if (g_schema_field_helpers[index] == target_rva) {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL capture_schema_nested_function(
    uintptr_t root_rva,
    unsigned int depth,
    uintptr_t target_rva,
    unsigned int maximum_bytes,
    uintptr_t *captured_function_rva,
    unsigned int *captured_length
) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t function_rva = target_rva;
    uintptr_t function_end_rva;
    uintptr_t available;
    BYTE *start;
    unsigned int length;
    BOOL truncated;
    BOOL exact_range = FALSE;
    char line[17000];
    size_t offset;
    unsigned int index;

    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + target_rva),
        &image_base,
        NULL
    );
    if (
        function_entry != NULL &&
        image_base == (DWORD64)(uintptr_t)g_game_base
    ) {
        function_rva = (uintptr_t)function_entry->BeginAddress;
        function_end_rva = (uintptr_t)function_entry->EndAddress;
        exact_range = TRUE;
    } else {
        function_end_rva = target_rva + maximum_bytes;
    }
    if (
        function_rva >= function_end_rva ||
        function_end_rva > g_game_size
    ) {
        log_dispatch_status(
            "SCHEMA_NESTED_CODE_ERROR",
            "invalid-function-range"
        );
        return FALSE;
    }
    available = function_end_rva - function_rva;
    truncated = !exact_range || available > maximum_bytes;
    length = available > maximum_bytes
        ? maximum_bytes
        : (unsigned int)available;
    start = g_game_base + function_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "SCHEMA_NESTED_CODE_ERROR",
            "function-window-unreadable"
        );
        return FALSE;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "SCHEMA_NESTED_CODE tick_ms=%llu process=%lu thread=%lu "
        "root_rva=0x%llx depth=%u target_rva=0x%llx "
        "function_rva=0x%llx function_end_rva=0x%llx "
        "length=%u truncated=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)root_rva,
        depth,
        (unsigned long long)target_rva,
        (unsigned long long)function_rva,
        (unsigned long long)function_end_rva,
        length,
        truncated ? 1u : 0u
    );
    for (index = 0; index < length && offset + 2u < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return FALSE;
        }
        offset += 2u;
    }
    if (index != length || offset + 2u >= sizeof(line)) {
        return FALSE;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    *captured_function_rva = function_rva;
    *captured_length = length;
    return TRUE;
}

static BOOL capture_schema_nested_forward_window(uintptr_t root_rva) {
    const unsigned int length = ISAC_SCHEMA_NESTED_FORWARD_BYTES;
    BYTE *start;
    char line[4400];
    size_t offset;
    unsigned int index;

    if (
        root_rva >= g_game_size ||
        length > g_game_size - root_rva
    ) {
        log_dispatch_status(
            "SCHEMA_NESTED_FORWARD_CODE_ERROR",
            "invalid-forward-range"
        );
        return FALSE;
    }
    start = g_game_base + root_rva;
    if (!readable_code_window(start, length)) {
        log_dispatch_status(
            "SCHEMA_NESTED_FORWARD_CODE_ERROR",
            "forward-window-unreadable"
        );
        return FALSE;
    }
    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "SCHEMA_NESTED_FORWARD_CODE tick_ms=%llu process=%lu thread=%lu "
        "root_rva=0x%llx window_start_rva=0x%llx "
        "window_end_rva=0x%llx length=%u bytes=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)root_rva,
        (unsigned long long)root_rva,
        (unsigned long long)(root_rva + length),
        length
    );
    for (index = 0; index < length && offset + 2u < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%02x",
            (unsigned int)start[index]
        );
        if (written != 2) {
            return FALSE;
        }
        offset += 2u;
    }
    if (index != length || offset + 2u >= sizeof(line)) {
        return FALSE;
    }
    line[offset++] = '\r';
    line[offset++] = '\n';
    line[offset] = '\0';
    append_dispatch_log(line);
    return TRUE;
}

static void capture_schema_nested_graph(void) {
    const uintptr_t root_rva = 0x0c47de0u;
    uintptr_t function_rva;
    unsigned int length;
    const BYTE *code;
    uintptr_t captured[ISAC_MAX_SCHEMA_NESTED_CALLEES];
    unsigned int captured_count = 0;
    unsigned int offset;

    if (
        !g_schema_field_probe_enabled ||
        InterlockedCompareExchange(
            &g_schema_nested_code_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    capture_schema_nested_forward_window(root_rva);
    if (!capture_schema_nested_function(
        root_rva,
        0u,
        root_rva,
        ISAC_MAX_SCHEMA_NESTED_CODE_BYTES,
        &function_rva,
        &length
    )) {
        return;
    }
    code = g_game_base + function_rva;
    for (offset = 0; offset + 5u <= length; ++offset) {
        int32_t displacement;
        uintptr_t instruction_rva;
        uintptr_t target_rva;
        uintptr_t unused_function_rva;
        unsigned int unused_length;
        unsigned int index;
        BOOL duplicate = FALSE;

        if (code[offset] != 0xe8u) {
            continue;
        }
        CopyMemory(&displacement, code + offset + 1u, sizeof(displacement));
        instruction_rva = function_rva + offset;
        target_rva = (uintptr_t)(
            (intptr_t)(instruction_rva + 5u) + (intptr_t)displacement
        );
        if (
            target_rva >= g_game_size ||
            target_rva == root_rva ||
            schema_field_helper_allowed(target_rva)
        ) {
            continue;
        }
        for (index = 0; index < captured_count; ++index) {
            if (captured[index] == target_rva) {
                duplicate = TRUE;
                break;
            }
        }
        if (duplicate) {
            continue;
        }
        if (captured_count >= ISAC_MAX_SCHEMA_NESTED_CALLEES) {
            log_dispatch_status(
                "SCHEMA_NESTED_CODE_LIMIT",
                "direct-callee-capacity-reached"
            );
            break;
        }
        captured[captured_count++] = target_rva;
        capture_schema_nested_function(
            root_rva,
            1u,
            target_rva,
            ISAC_MAX_SCHEMA_NESTED_CALLEE_BYTES,
            &unused_function_rva,
            &unused_length
        );
    }
}

static isac_schema_field_thread *schema_field_thread_state(BOOL create) {
    DWORD thread_id = GetCurrentThreadId();
    unsigned int index;

    for (index = 0; index < ISAC_MAX_SCHEMA_FIELD_THREADS; ++index) {
        LONG current = g_schema_field_threads[index].thread_id;

        if ((DWORD)current == thread_id) {
            return &g_schema_field_threads[index];
        }
        if (
            create &&
            current == 0 &&
            InterlockedCompareExchange(
                &g_schema_field_threads[index].thread_id,
                (LONG)thread_id,
                0
            ) == 0
        ) {
            return &g_schema_field_threads[index];
        }
    }
    return NULL;
}

static BOOL schema_field_cursor(
    const BYTE *decode_context,
    DWORD *absolute_cursor,
    DWORD *local_cursor,
    DWORD *buffer_length,
    const BYTE **buffer
) {
    const BYTE *source;
    const BYTE *buffer_object;

    if (
        decode_context == NULL ||
        !readable_memory_window(decode_context, sizeof(source))
    ) {
        return FALSE;
    }
    source = *(const BYTE *const *)decode_context;
    if (
        source == NULL ||
        !readable_memory_window(source + 0x40u, 0x14u)
    ) {
        return FALSE;
    }
    buffer_object = *(const BYTE *const *)(source + 0x48u);
    if (
        buffer_object == NULL ||
        !readable_memory_window(buffer_object, 0x10u)
    ) {
        return FALSE;
    }
    *absolute_cursor = *(const DWORD *)(source + 0x40u);
    *local_cursor = *(const DWORD *)(source + 0x50u);
    *buffer_length = *(const DWORD *)(buffer_object + 0x0cu);
    *buffer = buffer_object + 0x10u;
    return *local_cursor <= *buffer_length &&
        *buffer_length <= 0x10000u &&
        readable_memory_window(*buffer, *buffer_length);
}

static uintptr_t schema_deserializer_return_address(void) {
    unsigned int offset;

    for (
        offset = 0;
        offset + 3u <= sizeof(g_schema_deserialize_signature);
        ++offset
    ) {
        if (
            g_schema_deserialize_signature[offset] == 0xffu &&
            g_schema_deserialize_signature[offset + 1u] == 0x50u &&
            g_schema_deserialize_signature[offset + 2u] == 0x38u
        ) {
            return (uintptr_t)(
                g_game_base + ISAC_SCHEMA_BOUNDARY_RVA + offset + 3u
            );
        }
    }
    return 0;
}

static void begin_schema_message(
    CONTEXT *context,
    isac_schema_field_thread *state
) {
    const BYTE *buffer = NULL;
    DWORD absolute_cursor = 0;
    DWORD local_cursor = 0;
    DWORD buffer_length = 0;
    DWORD available;
    uintptr_t return_address;

    if (!g_schema_miner_enabled || state == NULL) {
        return;
    }
    if (state->message_pending) {
        log_dispatch_status(
            "SCHEMA_MESSAGE_ERROR",
            "previous-message-return-not-observed"
        );
    }
    state->message_pending = FALSE;
    state->message_prefix_length = 0;
    return_address = schema_deserializer_return_address();
    if (return_address == 0u) {
        log_dispatch_status(
            "SCHEMA_MESSAGE_ERROR",
            "deserializer-return-opcode-not-found"
        );
        return;
    }
    if (
        !schema_field_cursor(
            state->decode_context,
            &absolute_cursor,
            &local_cursor,
            &buffer_length,
            &buffer
        )
    ) {
        log_dispatch_status(
            "SCHEMA_MESSAGE_ERROR",
            "invalid-start-cursor"
        );
        return;
    }
    available = buffer_length - local_cursor;
    state->message_return_address = return_address;
    state->message_start_buffer = buffer;
    state->message_start_absolute = absolute_cursor;
    state->message_start_local = local_cursor;
    state->message_start_available = available;
    state->message_prefix_length = available < ISAC_MAX_SCHEMA_MESSAGE_BYTES
        ? available
        : ISAC_MAX_SCHEMA_MESSAGE_BYTES;
    if (state->message_prefix_length != 0u) {
        CopyMemory(
            state->message_prefix,
            buffer + local_cursor,
            state->message_prefix_length
        );
    }
    state->message_pending = TRUE;
    context->Dr0 = (DWORD64)state->message_return_address;
    context->Dr7 = (context->Dr7 & ~(DWORD64)0x3u) | 0x1u;
}

static void finish_schema_message(
    CONTEXT *context,
    isac_schema_field_thread *state
) {
    const BYTE *after_buffer = NULL;
    DWORD after_absolute = state->message_start_absolute;
    DWORD after_local = 0;
    DWORD after_buffer_length = 0;
    DWORD consumed = 0;
    DWORD captured;
    BOOL complete = FALSE;
    LONG sequence;
    char line[4608];
    size_t offset;
    unsigned int index;

    if (!state->message_pending) {
        return;
    }
    captured = 0;
    if (
        schema_field_cursor(
            state->decode_context,
            &after_absolute,
            &after_local,
            &after_buffer_length,
            &after_buffer
        ) &&
        after_absolute >= state->message_start_absolute
    ) {
        consumed = after_absolute - state->message_start_absolute;
        captured = state->message_prefix_length;
        if (consumed <= state->message_prefix_length) {
            captured = consumed;
            complete = TRUE;
        } else if (
            consumed <= ISAC_MAX_SCHEMA_MESSAGE_BYTES &&
            state->message_prefix_length == state->message_start_available &&
            after_buffer != state->message_start_buffer &&
            after_local == consumed - state->message_prefix_length &&
            after_local <= after_buffer_length &&
            readable_memory_window(after_buffer, after_local)
        ) {
            CopyMemory(
                state->message_prefix + state->message_prefix_length,
                after_buffer,
                after_local
            );
            captured = consumed;
            complete = TRUE;
        } else if (captured > consumed) {
            captured = consumed;
        }
    }
    sequence = InterlockedIncrement(&g_schema_message_count);
    if (sequence <= (LONG)ISAC_MAX_SCHEMA_MESSAGE_RECORDS) {
        offset = (size_t)snprintf(
            line,
            sizeof(line),
            "SCHEMA_MESSAGE sequence=%ld message_sequence=%ld "
            "tick_ms=%llu process=%lu thread=%lu type_id=0x%04x "
            "deserializer_rva=0x%llx start_absolute=%lu end_absolute=%lu "
            "length=%lu captured=%lu complete=%u bytes=",
            sequence,
            state->message_sequence,
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            (unsigned int)state->type_id,
            (unsigned long long)state->deserializer_rva,
            (unsigned long)state->message_start_absolute,
            (unsigned long)after_absolute,
            (unsigned long)consumed,
            (unsigned long)captured,
            complete ? 1u : 0u
        );
        for (
            index = 0;
            index < captured && offset + 2u < sizeof(line);
            ++index
        ) {
            offset += (size_t)snprintf(
                line + offset,
                sizeof(line) - offset,
                "%02x",
                (unsigned int)state->message_prefix[index]
            );
        }
        if (index == captured && offset + 2u < sizeof(line)) {
            line[offset++] = '\r';
            line[offset++] = '\n';
            line[offset] = '\0';
            append_dispatch_log(line);
        }
    } else if (
        InterlockedCompareExchange(
            &g_schema_message_limit_logged,
            1,
            0
        ) == 0
    ) {
        log_dispatch_status("SCHEMA_MESSAGE_LIMIT", "record-capacity-reached");
    }
    state->message_pending = FALSE;
    context->Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_SCHEMA_BOUNDARY_RVA
    );
    context->Dr7 = (context->Dr7 & ~(DWORD64)0x3u) | 0x1u;
}

static unsigned int schema_field_helpers(
    uintptr_t deserializer_rva,
    uintptr_t helpers[ISAC_MAX_SCHEMA_FIELD_HELPERS]
) {
    DWORD64 image_base = 0;
    PRUNTIME_FUNCTION function_entry;
    uintptr_t begin_rva;
    uintptr_t end_rva;
    const BYTE *code;
    unsigned int length;
    unsigned int offset;
    unsigned int count = 0;
    intptr_t object_adjustment;
    unsigned int resolution_steps;

    deserializer_rva = resolve_schema_thunk(
        deserializer_rva,
        &object_adjustment,
        &resolution_steps
    );
    (void)object_adjustment;
    (void)resolution_steps;

    function_entry = RtlLookupFunctionEntry(
        (DWORD64)(uintptr_t)(g_game_base + deserializer_rva),
        &image_base,
        NULL
    );
    if (
        function_entry != NULL &&
        image_base == (DWORD64)(uintptr_t)g_game_base
    ) {
        begin_rva = (uintptr_t)function_entry->BeginAddress;
        end_rva = (uintptr_t)function_entry->EndAddress;
    } else {
        begin_rva = deserializer_rva;
        end_rva = deserializer_rva + ISAC_MAX_SCHEMA_CODE_BYTES;
    }
    if (
        begin_rva >= end_rva ||
        end_rva > g_game_size ||
        end_rva - begin_rva > ISAC_MAX_SCHEMA_CODE_BYTES
    ) {
        return 0;
    }
    code = g_game_base + begin_rva;
    length = (unsigned int)(end_rva - begin_rva);
    if (!readable_code_window(code, length)) {
        return 0;
    }
    for (offset = 0; offset + 5u <= length; ++offset) {
        int32_t displacement;
        uintptr_t instruction_rva;
        uintptr_t target_rva;
        unsigned int index;
        BOOL duplicate = FALSE;

        if (code[offset] != 0xe8u) {
            continue;
        }
        CopyMemory(&displacement, code + offset + 1u, sizeof(displacement));
        instruction_rva = begin_rva + offset;
        target_rva = (uintptr_t)(
            (intptr_t)(instruction_rva + 5u) + (intptr_t)displacement
        );
        if (!schema_field_helper_allowed(target_rva)) {
            continue;
        }
        for (index = 0; index < count; ++index) {
            if (helpers[index] == target_rva) {
                duplicate = TRUE;
                break;
            }
        }
        if (!duplicate && count < ISAC_MAX_SCHEMA_FIELD_HELPERS) {
            helpers[count++] = target_rva;
        }
    }
    return count;
}

static void arm_schema_field_helpers(
    CONTEXT *context,
    LONG message_sequence,
    USHORT type_id,
    const BYTE *message,
    const BYTE *decode_context,
    uintptr_t deserializer_rva
) {
    isac_schema_field_thread *state;
    uintptr_t helpers[ISAC_MAX_SCHEMA_FIELD_HELPERS];
    unsigned int helper_count;
    unsigned int group_count;
    unsigned int group;
    unsigned int index;
    DWORD64 enable = 0x1u;

    if (!g_schema_field_probe_enabled) {
        return;
    }
    state = schema_field_thread_state(TRUE);
    if (state == NULL) {
        return;
    }
    if (
        g_schema_field_type_filter >= 0 &&
        type_id != (USHORT)g_schema_field_type_filter
    ) {
        state->type_id = type_id;
        state->message = NULL;
        state->decode_context = NULL;
        state->deserializer_rva = 0;
        ZeroMemory(state->helpers, sizeof(state->helpers));
        ZeroMemory(state->slots, sizeof(state->slots));
        context->Dr0 = (DWORD64)(uintptr_t)(
            g_game_base + ISAC_SCHEMA_BOUNDARY_RVA
        );
        context->Dr1 = 0;
        context->Dr2 = 0;
        context->Dr3 = 0;
        context->Dr7 = (context->Dr7 & ~(DWORD64)0xfcu) | 0x1u;
        return;
    }
    helper_count = schema_field_helpers(deserializer_rva, helpers);
    group_count = (helper_count + 2u) / 3u;
    group = group_count == 0u
        ? 0u
        : (unsigned int)(
            InterlockedIncrement(&g_schema_field_rotations[type_id]) - 1
        ) % group_count;

    state->type_id = type_id;
    state->message_sequence = message_sequence;
    state->message = message;
    state->decode_context = decode_context;
    state->deserializer_rva = deserializer_rva;
    ZeroMemory(state->helpers, sizeof(state->helpers));
    ZeroMemory(state->slots, sizeof(state->slots));
    for (index = 0; index < 3u; ++index) {
        unsigned int helper_index = group * 3u + index;

        if (helper_index < helper_count) {
            state->helpers[index] = helpers[helper_index];
            state->slots[index].helper_rva = helpers[helper_index];
            enable |= (DWORD64)1u << ((index + 1u) * 2u);
        }
    }
    context->Dr0 = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_SCHEMA_BOUNDARY_RVA
    );
    context->Dr1 = state->helpers[0] == 0u
        ? 0u
        : (DWORD64)(uintptr_t)(g_game_base + state->helpers[0]);
    context->Dr2 = state->helpers[1] == 0u
        ? 0u
        : (DWORD64)(uintptr_t)(g_game_base + state->helpers[1]);
    context->Dr3 = state->helpers[2] == 0u
        ? 0u
        : (DWORD64)(uintptr_t)(g_game_base + state->helpers[2]);
    context->Dr7 = (context->Dr7 & ~(DWORD64)0xffff00ffu) | enable;
}

static void begin_schema_field(
    CONTEXT *context,
    isac_schema_field_thread *state,
    unsigned int slot_index
) {
    isac_schema_field_slot *slot = &state->slots[slot_index];
    const BYTE *buffer = NULL;
    uintptr_t return_address;
    DWORD available;

    if (
        slot->pending ||
        context->Rcx != (DWORD64)(uintptr_t)state->decode_context ||
        !readable_memory_window(
            (const void *)(uintptr_t)context->Rsp,
            sizeof(return_address)
        )
    ) {
        return;
    }
    return_address = *(const uintptr_t *)(uintptr_t)context->Rsp;
    if (
        return_address < (uintptr_t)g_game_base ||
        return_address >= (uintptr_t)(g_game_base + g_game_size)
    ) {
        return;
    }
    ZeroMemory(slot, sizeof(*slot));
    slot->helper_rva = state->helpers[slot_index];
    slot->return_address = return_address;
    slot->destination = (const BYTE *)(uintptr_t)context->Rdx;
    slot->argument_r8 = context->R8;
    slot->argument_r9 = context->R9;
    if (
        schema_field_cursor(
            state->decode_context,
            &slot->absolute_cursor,
            &slot->local_cursor,
            &slot->buffer_length,
            &buffer
        )
    ) {
        available = slot->buffer_length - slot->local_cursor;
        slot->wire_length = available < ISAC_SCHEMA_FIELD_BYTES
            ? available
            : ISAC_SCHEMA_FIELD_BYTES;
        if (slot->wire_length != 0u) {
            CopyMemory(
                slot->wire,
                buffer + slot->local_cursor,
                slot->wire_length
            );
        }
    }
    if (
        slot->destination != NULL &&
        readable_memory_window(slot->destination, ISAC_SCHEMA_FIELD_BYTES)
    ) {
        slot->before_length = ISAC_SCHEMA_FIELD_BYTES;
        CopyMemory(
            slot->before,
            slot->destination,
            ISAC_SCHEMA_FIELD_BYTES
        );
    }
    slot->pending = TRUE;
    if (slot_index == 0u) {
        context->Dr1 = (DWORD64)return_address;
    } else if (slot_index == 1u) {
        context->Dr2 = (DWORD64)return_address;
    } else {
        context->Dr3 = (DWORD64)return_address;
    }
}

static void finish_schema_field(
    CONTEXT *context,
    isac_schema_field_thread *state,
    unsigned int slot_index
) {
    isac_schema_field_slot *slot = &state->slots[slot_index];
    const BYTE *unused_buffer = NULL;
    BYTE after[ISAC_SCHEMA_FIELD_BYTES];
    DWORD after_absolute = 0;
    DWORD after_local = 0;
    DWORD after_buffer_length = 0;
    DWORD after_length = 0;
    DWORD consumed = 0;
    LONG type_sample;
    LONG sequence;
    LONG sample_limit;
    intptr_t destination_offset = -1;
    char line[1024];
    size_t offset;
    unsigned int index;

    if (!slot->pending) {
        return;
    }
    if (
        schema_field_cursor(
            state->decode_context,
            &after_absolute,
            &after_local,
            &after_buffer_length,
            &unused_buffer
        ) &&
        after_absolute >= slot->absolute_cursor
    ) {
        consumed = after_absolute - slot->absolute_cursor;
    }
    if (
        slot->destination != NULL &&
        readable_memory_window(slot->destination, ISAC_SCHEMA_FIELD_BYTES)
    ) {
        after_length = ISAC_SCHEMA_FIELD_BYTES;
        CopyMemory(after, slot->destination, after_length);
    }
    if (
        (uintptr_t)slot->destination >= (uintptr_t)state->message &&
        (uintptr_t)slot->destination - (uintptr_t)state->message < 0x10000u
    ) {
        destination_offset = (intptr_t)(
            (uintptr_t)slot->destination - (uintptr_t)state->message
        );
    }
    type_sample = InterlockedIncrement(&g_schema_field_samples[state->type_id]);
    sample_limit = g_schema_field_type_filter >= 0
        ? (LONG)ISAC_MAX_SCHEMA_FIELD_FILTERED_SAMPLES
        : (
            g_schema_miner_enabled
                ? (LONG)ISAC_MAX_SCHEMA_FIELD_MINER_SAMPLES_PER_TYPE
                : (LONG)ISAC_MAX_SCHEMA_FIELD_SAMPLES_PER_TYPE
        );
    sequence = type_sample <= sample_limit
        ? InterlockedIncrement(&g_schema_field_count)
        : 0;
    if (
        type_sample <= sample_limit &&
        sequence > 0 &&
        sequence <= (LONG)ISAC_MAX_SCHEMA_FIELD_RECORDS
    ) {
        offset = (size_t)snprintf(
            line,
            sizeof(line),
            "SCHEMA_FIELD sequence=%ld message_sequence=%ld "
            "tick_ms=%llu process=%lu thread=%lu "
            "type_id=0x%04x deserializer_rva=0x%llx helper_rva=0x%llx "
            "return_rva=0x%llx "
            "destination_offset=%lld argument_r8=0x%llx argument_r9=0x%llx "
            "before_absolute=%lu after_absolute=%lu consumed=%lu "
            "return_value=0x%llx wire_captured=%lu wire=",
            sequence,
            state->message_sequence,
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            (unsigned int)state->type_id,
            (unsigned long long)state->deserializer_rva,
            (unsigned long long)slot->helper_rva,
            (unsigned long long)(
                slot->return_address - (uintptr_t)g_game_base
            ),
            (long long)destination_offset,
            (unsigned long long)slot->argument_r8,
            (unsigned long long)slot->argument_r9,
            (unsigned long)slot->absolute_cursor,
            (unsigned long)after_absolute,
            (unsigned long)consumed,
            (unsigned long long)context->Rax,
            (unsigned long)slot->wire_length
        );
        for (
            index = 0;
            index < slot->wire_length && offset + 2u < sizeof(line);
            ++index
        ) {
            offset += (size_t)snprintf(
                line + offset,
                sizeof(line) - offset,
                "%02x",
                (unsigned int)slot->wire[index]
            );
        }
        offset += (size_t)snprintf(
            line + offset,
            sizeof(line) - offset,
            " before="
        );
        for (
            index = 0;
            index < slot->before_length && offset + 2u < sizeof(line);
            ++index
        ) {
            offset += (size_t)snprintf(
                line + offset,
                sizeof(line) - offset,
                "%02x",
                (unsigned int)slot->before[index]
            );
        }
        offset += (size_t)snprintf(
            line + offset,
            sizeof(line) - offset,
            " after="
        );
        for (
            index = 0;
            index < after_length && offset + 2u < sizeof(line);
            ++index
        ) {
            offset += (size_t)snprintf(
                line + offset,
                sizeof(line) - offset,
                "%02x",
                (unsigned int)after[index]
            );
        }
        if (offset + 2u < sizeof(line)) {
            line[offset++] = '\r';
            line[offset++] = '\n';
            line[offset] = '\0';
            append_dispatch_log(line);
        }
    } else if (
        sequence > (LONG)ISAC_MAX_SCHEMA_FIELD_RECORDS &&
        InterlockedCompareExchange(&g_schema_field_limit_logged, 1, 0) == 0
    ) {
        log_dispatch_status("SCHEMA_FIELD_LIMIT", "record-capacity-reached");
    }
    slot->pending = FALSE;
    if (slot_index == 0u) {
        context->Dr1 = state->helpers[0] == 0u
            ? 0u
            : (DWORD64)(uintptr_t)(g_game_base + state->helpers[0]);
    } else if (slot_index == 1u) {
        context->Dr2 = state->helpers[1] == 0u
            ? 0u
            : (DWORD64)(uintptr_t)(g_game_base + state->helpers[1]);
    } else {
        context->Dr3 = state->helpers[2] == 0u
            ? 0u
            : (DWORD64)(uintptr_t)(g_game_base + state->helpers[2]);
    }
}

static BOOL handle_schema_field_breakpoint(CONTEXT *context) {
    isac_schema_field_thread *state;
    uintptr_t instruction = (uintptr_t)context->Rip;
    unsigned int index;

    if (!g_schema_field_probe_enabled) {
        return FALSE;
    }
    state = schema_field_thread_state(FALSE);
    if (state == NULL) {
        return FALSE;
    }
    if (
        state->message_pending &&
        instruction == state->message_return_address
    ) {
        finish_schema_message(context, state);
        return TRUE;
    }
    for (index = 0; index < 3u; ++index) {
        isac_schema_field_slot *slot = &state->slots[index];

        if (slot->pending && instruction == slot->return_address) {
            finish_schema_field(context, state, index);
            return TRUE;
        }
        if (
            !slot->pending &&
            state->helpers[index] != 0u &&
            instruction == (uintptr_t)(g_game_base + state->helpers[index])
        ) {
            begin_schema_field(context, state, index);
            return TRUE;
        }
    }
    return FALSE;
}

static void record_schema_deserializer(CONTEXT *context) {
    const BYTE *message = (const BYTE *)(uintptr_t)context->Rdi;
    const BYTE *decode_context = (const BYTE *)(uintptr_t)(context->Rsp + 0x20u);
    const BYTE *source = NULL;
    const BYTE *buffer_object = NULL;
    const BYTE *const *vtable;
    uintptr_t vtable_rva = 0;
    uintptr_t deserialize_rva;
    uintptr_t slot08_rva;
    uintptr_t slot28_rva;
    USHORT type_id;
    DWORD absolute_cursor = 0;
    DWORD local_cursor = 0;
    DWORD buffer_length = 0;
    BOOL has_cursor = FALSE;
    BOOL world_phase = g_plaintext_world_active != 0;
    LONG sequence;
    LONG count;
    LONG index;
    BOOL unique = TRUE;
    char line[512];
    int line_length;

    if (!world_phase && !g_bootstrap_probe_enabled) {
        return;
    }
    if (
        message == NULL ||
        !readable_memory_window(message, sizeof(vtable)) ||
        !readable_memory_window(
            (const void *)(uintptr_t)(context->Rsp + 0x90u),
            sizeof(type_id)
        ) ||
        !readable_memory_window(decode_context, sizeof(source))
    ) {
        log_dispatch_status("SCHEMA_EVENT_ERROR", "invalid-boundary-state");
        return;
    }
    type_id = *(const USHORT *)(uintptr_t)(context->Rsp + 0x90u);
    vtable = *(const BYTE *const *const *)message;
    if (
        vtable == NULL ||
        !readable_memory_window(vtable, 8u * sizeof(*vtable))
    ) {
        log_dispatch_status("SCHEMA_EVENT_ERROR", "invalid-message-vtable");
        return;
    }
    deserialize_rva = schema_method_rva(vtable, 7u);
    slot08_rva = schema_method_rva(vtable, 1u);
    slot28_rva = schema_method_rva(vtable, 5u);
    if (deserialize_rva == 0) {
        log_dispatch_status("SCHEMA_EVENT_ERROR", "deserializer-outside-game");
        return;
    }
    if (
        (const BYTE *)vtable >= g_game_base &&
        (const BYTE *)vtable < g_game_base + g_game_size
    ) {
        vtable_rva = (uintptr_t)((const BYTE *)vtable - g_game_base);
    }
    source = *(const BYTE *const *)decode_context;
    if (
        source != NULL &&
        readable_memory_window(source + 0x40u, 0x14u)
    ) {
        absolute_cursor = *(const DWORD *)(source + 0x40u);
        buffer_object = *(const BYTE *const *)(source + 0x48u);
        local_cursor = *(const DWORD *)(source + 0x50u);
        if (
            buffer_object != NULL &&
            readable_memory_window(buffer_object + 0x0cu, sizeof(DWORD))
        ) {
            buffer_length = *(const DWORD *)(buffer_object + 0x0cu);
            has_cursor = TRUE;
        }
    }

    sequence = InterlockedIncrement(&g_schema_event_count);
    capture_all_schema_helper_code();
    capture_schema_nested_graph();
    if (world_phase) {
        arm_schema_field_helpers(
            context,
            sequence,
            type_id,
            message,
            decode_context,
            deserialize_rva
        );
        begin_schema_message(
            context,
            schema_field_thread_state(FALSE)
        );
    }

    if (sequence <= (LONG)ISAC_MAX_SCHEMA_EVENTS) {
        line_length = snprintf(
            line,
            sizeof(line),
            "SCHEMA_EVENT sequence=%ld tick_ms=%llu process=%lu thread=%lu "
            "type_id=0x%04x vtable_rva=0x%llx "
            "deserialize_rva=0x%llx slot08_rva=0x%llx "
            "slot28_rva=0x%llx has_cursor=%u absolute_cursor=%lu "
            "local_cursor=%lu buffer_length=%lu\r\n",
            sequence,
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            (unsigned int)type_id,
            (unsigned long long)vtable_rva,
            (unsigned long long)deserialize_rva,
            (unsigned long long)slot08_rva,
            (unsigned long long)slot28_rva,
            has_cursor ? 1u : 0u,
            (unsigned long)absolute_cursor,
            (unsigned long)local_cursor,
            (unsigned long)buffer_length
        );
        if (line_length > 0 && (size_t)line_length < sizeof(line)) {
            append_dispatch_log(line);
        }
    } else if (
        InterlockedCompareExchange(&g_schema_event_limit_logged, 1, 0) == 0
    ) {
        log_dispatch_status("SCHEMA_EVENT_LIMIT", "event-capacity-reached");
    }

    if (InterlockedCompareExchange(&g_schema_target_lock, 1, 0) != 0) {
        return;
    }
    count = g_schema_target_count;
    for (index = 0; index < count; ++index) {
        if (
            g_schema_targets[index].type_id == type_id &&
            g_schema_targets[index].deserializer_rva == deserialize_rva
        ) {
            unique = FALSE;
            break;
        }
    }
    if (unique && count < (LONG)ISAC_MAX_SCHEMA_TARGETS) {
        g_schema_targets[count].type_id = type_id;
        g_schema_targets[count].deserializer_rva = deserialize_rva;
        g_schema_target_count = count + 1;
    } else if (unique) {
        unique = FALSE;
        if (
            InterlockedCompareExchange(
                &g_schema_target_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "SCHEMA_TARGET_LIMIT",
                "unique-type-deserializer-capacity-reached"
            );
        }
    }
    InterlockedExchange(&g_schema_target_lock, 0);
    if (unique) {
        line_length = snprintf(
            line,
            sizeof(line),
            "SCHEMA_TARGET tick_ms=%llu process=%lu thread=%lu "
            "type_id=0x%04x vtable_rva=0x%llx "
            "deserialize_rva=0x%llx slot08_rva=0x%llx "
            "slot28_rva=0x%llx\r\n",
            (unsigned long long)GetTickCount64(),
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            (unsigned int)type_id,
            (unsigned long long)vtable_rva,
            (unsigned long long)deserialize_rva,
            (unsigned long long)slot08_rva,
            (unsigned long long)slot28_rva
        );
        if (line_length > 0 && (size_t)line_length < sizeof(line)) {
            append_dispatch_log(line);
        }
        capture_schema_code(type_id, deserialize_rva);
    }
}

static void capture_inbound_virtual_reader(const BYTE *parser) {
    const BYTE *reader;
    const BYTE *const *vtable;
    BYTE *target;
    uintptr_t target_rva;
    char line[384];
    int length;

    if (
        InterlockedCompareExchange(
            &g_inbound_virtual_reader_captured,
            1,
            0
        ) != 0
    ) {
        return;
    }
    if (
        parser == NULL ||
        !readable_memory_window(parser + 0x48u, sizeof(reader))
    ) {
        log_dispatch_status(
            "INBOUND_READER_VIRTUAL_ERROR",
            "invalid-parser-object"
        );
        return;
    }
    reader = *(const BYTE *const *)(parser + 0x48u);
    if (
        reader == NULL ||
        !readable_memory_window(reader, sizeof(vtable))
    ) {
        log_dispatch_status(
            "INBOUND_READER_VIRTUAL_ERROR",
            "invalid-reader-object"
        );
        return;
    }
    vtable = *(const BYTE *const *const *)reader;
    if (
        vtable == NULL ||
        !readable_memory_window(vtable, 4u * sizeof(*vtable))
    ) {
        log_dispatch_status(
            "INBOUND_READER_VIRTUAL_ERROR",
            "invalid-reader-vtable"
        );
        return;
    }
    target = (BYTE *)vtable[3];
    if (
        target < g_game_base ||
        target >= g_game_base + g_game_size ||
        !readable_code_window(target, 1u)
    ) {
        log_dispatch_status(
            "INBOUND_READER_VIRTUAL_ERROR",
            "reader-target-outside-game"
        );
        return;
    }
    target_rva = (uintptr_t)(target - g_game_base);
    length = snprintf(
        line,
        sizeof(line),
        "INBOUND_READER_VIRTUAL tick_ms=%llu process=%lu thread=%lu "
        "object_offset=0x48 vtable_offset=0x18 target_rva=0x%llx\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)target_rva
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
    capture_inbound_reader_forward_window("virtual-read-next", target_rva);
    capture_inbound_reader_forward_window("virtual-read-helper", 0x009a7c0u);
    capture_inbound_reader_function("virtual-read-helper", 0x009a7c0u);
}

static void record_dispatch_target(char kind, void *object, unsigned int slot) {
    void **vtable;
    BYTE *target;
    uintptr_t rva;
    LONG target_count;
    LONG index;
    uintptr_t source_rva = 0;
    USHORT type_id = 0;
    BOOL has_type_id = FALSE;
    char line[384];
    int length;

    if (
        !g_dispatch_probe_enabled ||
        object == NULL ||
        !readable_memory_window(object, sizeof(vtable))
    ) {
        return;
    }
    vtable = *(void ***)object;
    if (
        vtable == NULL ||
        !readable_memory_window(
            vtable,
            ((SIZE_T)slot + 1u) * sizeof(*vtable)
        )
    ) {
        return;
    }
    target = (BYTE *)vtable[slot];
    if (
        target < g_game_base ||
        target >= g_game_base + g_game_size ||
        !readable_code_window(target, 1u)
    ) {
        return;
    }
    rva = (uintptr_t)(target - g_game_base);
    if (kind == 'M' || kind == 'O') {
        has_type_id = decode_dispatch_type_id(
            target,
            rva,
            &source_rva,
            &type_id
        );
        if (has_type_id) {
            if (
                kind == 'M' &&
                type_id == 0x0012u &&
                InterlockedCompareExchange(
                    &g_plaintext_world_active,
                    1,
                    0
                ) == 0 &&
                g_plaintext_probe_enabled
            ) {
                log_plaintext_status(
                    "PLAINTEXT_PROBE_ACTIVE",
                    "world-type-gate=0x0012"
                );
                if (g_bootstrap_probe_enabled) {
                    log_plaintext_status(
                        "BOOTSTRAP_PHASE",
                        g_bootstrap_redacted_only
                            ? "phase=world,gate-type=0x0012,"
                                "gameplay-payloads=disabled,metadata=enabled"
                            : "phase=world,gate-type=0x0012,"
                                "gameplay-payloads=enabled"
                    );
                }
            }
            record_dispatch_event(kind, rva, type_id);
        }
    }

    if (InterlockedCompareExchange(&g_dispatch_target_lock, 1, 0) != 0) {
        return;
    }
    target_count = g_dispatch_target_count;
    for (index = 0; index < target_count; ++index) {
        if (
            g_dispatch_targets[index].kind == kind &&
            g_dispatch_targets[index].rva == rva
        ) {
            InterlockedExchange(&g_dispatch_target_lock, 0);
            return;
        }
    }
    if (target_count >= (LONG)ISAC_MAX_DISPATCH_TARGETS) {
        if (InterlockedCompareExchange(&g_dispatch_limit_logged, 1, 0) == 0) {
            log_dispatch_status(
                "DISPATCH_PROBE_LIMIT",
                "unique-target-capacity-reached"
            );
        }
        InterlockedExchange(&g_dispatch_target_lock, 0);
        return;
    }
    g_dispatch_targets[target_count].kind = kind;
    g_dispatch_targets[target_count].rva = rva;
    g_dispatch_target_count = target_count + 1;

    length = snprintf(
        line,
        sizeof(line),
        "DISPATCH_TARGET tick_ms=%llu process=%lu thread=%lu "
        "kind=%s target_rva=0x%llx\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        kind == 'I'
            ? "inbound-handler"
            : kind == 'O'
                ? "outbound-type-method"
                : "message-type-method",
        (unsigned long long)rva
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
    if (!capture_dispatch_code_window(kind, target, rva)) {
        char detail[192];

        length = snprintf(
            detail,
            sizeof(detail),
            "code-window-unreadable,kind=%s,target-rva=0x%llx",
            kind == 'I'
                ? "inbound-handler"
                : kind == 'O'
                    ? "outbound-type-method"
                    : "message-type-method",
            (unsigned long long)rva
        );
        if (length > 0 && (size_t)length < sizeof(detail)) {
            log_dispatch_status("DISPATCH_CODE_SKIPPED", detail);
        }
    }
    if (has_type_id) {
        log_dispatch_type_id(rva, source_rva, type_id);
    }
    InterlockedExchange(&g_dispatch_target_lock, 0);
}

static void record_dispatch_caller(void *object, DWORD64 stack_pointer) {
    void **vtable;
    BYTE *type_target;
    BYTE *return_address;
    uintptr_t type_target_rva;
    uintptr_t source_rva;
    uintptr_t return_rva;
    USHORT type_id;
    LONG caller_count;
    LONG index;
    BOOL return_seen = FALSE;
    char line[384];
    int length;

    if (
        !g_dispatch_probe_enabled ||
        object == NULL ||
        stack_pointer == 0 ||
        !readable_memory_window(object, sizeof(vtable)) ||
        !readable_memory_window(
            (const void *)(uintptr_t)stack_pointer,
            sizeof(return_address)
        )
    ) {
        return;
    }
    vtable = *(void ***)object;
    if (
        vtable == NULL ||
        !readable_memory_window(vtable, 4u * sizeof(*vtable))
    ) {
        return;
    }
    type_target = (BYTE *)vtable[3];
    if (
        type_target < g_game_base ||
        type_target >= g_game_base + g_game_size
    ) {
        return;
    }
    type_target_rva = (uintptr_t)(type_target - g_game_base);
    if (!decode_dispatch_type_id(
            type_target,
            type_target_rva,
            &source_rva,
            &type_id
        )) {
        return;
    }
    CopyMemory(
        &return_address,
        (const void *)(uintptr_t)stack_pointer,
        sizeof(return_address)
    );
    if (
        return_address < g_game_base ||
        return_address >= g_game_base + g_game_size
    ) {
        return;
    }
    return_rva = (uintptr_t)(return_address - g_game_base);

    if (InterlockedCompareExchange(&g_dispatch_caller_lock, 1, 0) != 0) {
        return;
    }
    caller_count = g_dispatch_caller_count;
    for (index = 0; index < caller_count; ++index) {
        if (g_dispatch_callers[index].return_rva == return_rva) {
            return_seen = TRUE;
        }
        if (
            g_dispatch_callers[index].type_id == type_id &&
            g_dispatch_callers[index].return_rva == return_rva
        ) {
            InterlockedExchange(&g_dispatch_caller_lock, 0);
            return;
        }
    }
    if (caller_count >= (LONG)ISAC_MAX_DISPATCH_CALLERS) {
        if (
            InterlockedCompareExchange(
                &g_dispatch_caller_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "DISPATCH_CALLER_LIMIT",
                "unique-type-return-capacity-reached"
            );
        }
        InterlockedExchange(&g_dispatch_caller_lock, 0);
        return;
    }
    g_dispatch_callers[caller_count].type_id = type_id;
    g_dispatch_callers[caller_count].return_rva = return_rva;
    g_dispatch_caller_count = caller_count + 1;

    length = snprintf(
        line,
        sizeof(line),
        "DISPATCH_CALLER tick_ms=%llu process=%lu thread=%lu "
        "type_id=0x%04x return_rva=0x%llx\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned int)type_id,
        (unsigned long long)return_rva
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
    if (
        !return_seen &&
        !capture_dispatch_caller_code_window(return_address, return_rva)
    ) {
        char detail[160];

        length = snprintf(
            detail,
            sizeof(detail),
            "caller-window-unreadable,return-rva=0x%llx",
            (unsigned long long)return_rva
        );
        if (length > 0 && (size_t)length < sizeof(detail)) {
            log_dispatch_status("DISPATCH_CODE_SKIPPED", detail);
        }
    }
    InterlockedExchange(&g_dispatch_caller_lock, 0);
}

static void record_inbound_scheduler_caller(DWORD64 stack_pointer) {
    BYTE *return_address;
    uintptr_t return_rva;
    LONG caller_count;
    LONG index;
    char line[320];
    int length;

    if (
        stack_pointer == 0 ||
        !readable_memory_window(
            (const void *)(uintptr_t)stack_pointer,
            sizeof(return_address)
        )
    ) {
        return;
    }
    CopyMemory(
        &return_address,
        (const void *)(uintptr_t)stack_pointer,
        sizeof(return_address)
    );
    if (
        return_address < g_game_base ||
        return_address >= g_game_base + g_game_size
    ) {
        return;
    }
    return_rva = (uintptr_t)(return_address - g_game_base);

    if (
        InterlockedCompareExchange(&g_inbound_batch_caller_lock, 1, 0) != 0
    ) {
        return;
    }
    caller_count = g_inbound_batch_caller_count;
    for (index = 0; index < caller_count; ++index) {
        if (g_inbound_batch_callers[index] == return_rva) {
            InterlockedExchange(&g_inbound_batch_caller_lock, 0);
            return;
        }
    }
    if (caller_count >= (LONG)ISAC_MAX_INBOUND_BATCH_CALLERS) {
        if (
            InterlockedCompareExchange(
                &g_inbound_batch_caller_limit_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_SCHEDULER_CALLER_LIMIT",
                "unique-return-capacity-reached"
            );
        }
        InterlockedExchange(&g_inbound_batch_caller_lock, 0);
        return;
    }
    g_inbound_batch_callers[caller_count] = return_rva;
    g_inbound_batch_caller_count = caller_count + 1;

    length = snprintf(
        line,
        sizeof(line),
        "INBOUND_SCHEDULER_CALLER tick_ms=%llu process=%lu thread=%lu "
        "return_rva=0x%llx\r\n",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        (unsigned long long)return_rva
    );
    if (length > 0 && (size_t)length < sizeof(line)) {
        append_dispatch_log(line);
    }
    if (!capture_dispatch_caller_code_window(return_address, return_rva)) {
        char detail[160];

        length = snprintf(
            detail,
            sizeof(detail),
            "inbound-scheduler-caller-window-unreadable,return-rva=0x%llx",
            (unsigned long long)return_rva
        );
        if (length > 0 && (size_t)length < sizeof(detail)) {
            log_dispatch_status("DISPATCH_CODE_SKIPPED", detail);
        }
    }
    InterlockedExchange(&g_inbound_batch_caller_lock, 0);
}

static void activate_inbound_queue_watch(
    void *scheduler_object,
    CONTEXT *context
) {
    BYTE *descriptor;
    PVOID watch_address;
    PVOID existing;

    if (
        scheduler_object == NULL ||
        !readable_memory_window(
            (BYTE *)scheduler_object + 0x18u,
            sizeof(descriptor)
        )
    ) {
        return;
    }
    descriptor = *(BYTE **)((BYTE *)scheduler_object + 0x18u);
    if (
        descriptor == NULL ||
        !readable_memory_window(descriptor + 0x10u, sizeof(DWORD))
    ) {
        return;
    }
    watch_address = descriptor + 0x10u;
    existing = InterlockedCompareExchangePointer(
        &g_inbound_queue_watch_address,
        watch_address,
        NULL
    );
    if (existing != NULL && existing != watch_address) {
        if (
            InterlockedCompareExchange(
                &g_inbound_queue_watch_error_logged,
                1,
                0
            ) == 0
        ) {
            log_dispatch_status(
                "INBOUND_QUEUE_WATCH_ERROR",
                "descriptor-address-changed"
            );
        }
        return;
    }
    context->Dr3 = (DWORD64)(uintptr_t)watch_address;
    context->Dr7 =
        (context->Dr7 & ~(DWORD64)0xf00000c0u) |
        (DWORD64)0xd0000040u;
    if (existing == NULL) {
        log_dispatch_status(
            "INBOUND_QUEUE_WATCH_ARMED",
            "field=count,width=4,scope=scheduler-thread,"
            "stack-scan-slots=128,max-frames=16"
        );
    }
}

static void release_hook_storage(isac_inline_hook *hook) {
    if (!hook->installed && hook->trampoline != NULL) {
        VirtualFree(hook->trampoline, 0, MEM_RELEASE);
        ZeroMemory(hook, sizeof(*hook));
    }
}

static BOOL dispatch_thread_recorded(DWORD thread_id) {
    LONG count;
    LONG index;
    BOOL found = FALSE;

    if (InterlockedCompareExchange(&g_dispatch_thread_lock, 1, 0) != 0) {
        return FALSE;
    }
    count = g_dispatch_thread_count;
    for (index = 0; index < count; ++index) {
        if (g_dispatch_threads[index] == thread_id) {
            found = TRUE;
            break;
        }
    }
    InterlockedExchange(&g_dispatch_thread_lock, 0);
    return found;
}

static void remember_dispatch_thread(DWORD thread_id) {
    LONG count;
    LONG index;

    if (InterlockedCompareExchange(&g_dispatch_thread_lock, 1, 0) != 0) {
        return;
    }
    count = g_dispatch_thread_count;
    for (index = 0; index < count; ++index) {
        if (g_dispatch_threads[index] == thread_id) {
            InterlockedExchange(&g_dispatch_thread_lock, 0);
            return;
        }
    }
    if (count < (LONG)ISAC_MAX_DISPATCH_THREADS) {
        g_dispatch_threads[count] = thread_id;
        g_dispatch_thread_count = count + 1;
    }
    InterlockedExchange(&g_dispatch_thread_lock, 0);
}

#include "tctd_allocation_capture.inc"
#include "startup_leads_capture.inc"
#include "login_handoff_probe.inc"
#include "tctd_echo_checkpoints.inc"
#include "login_handoff_threads.inc"
#include "login_handoff_resume.inc"
#include "login_handoff_faults.inc"

static BOOL set_dispatch_breakpoints(HANDLE thread, BOOL enabled) {
    if (g_tctd_echo_enabled) {
        return echo_breakpoints(thread, enabled);
    }
    if (g_tctd_allocation_enabled) {
        return allocation_breakpoints(thread, enabled);
    }
    CONTEXT context;
    DWORD64 queue_producer_address = (DWORD64)(uintptr_t)(
        g_game_base + 0x0f843b6u
    );
    DWORD64 inbound_virtual_reader_address = (DWORD64)(uintptr_t)(
        g_game_base + 0x0f84315u
    );
    DWORD64 inbound_handoff_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_INBOUND_HANDOFF_RVA
    );
    DWORD64 virtual_read_helper_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_VIRTUAL_READ_HELPER_RVA
    );
    DWORD64 inbound_advance_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_INBOUND_ADVANCE_RVA
    );
    DWORD64 bridge_reader_register_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_READER_REGISTER_RVA
    );
    DWORD64 world_address = (DWORD64)(uintptr_t)(
        g_game_base + 0x0f8e8d0u
    );
    DWORD64 reader_setup_a_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_READER_SETUP_A_RVA
    );
    DWORD64 reader_setup_b_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_READER_SETUP_B_RVA
    );
    DWORD64 outbound_plaintext_address = (DWORD64)(uintptr_t)(
        g_game_base + 0x0d6bbfu
    );
    DWORD64 registration_return_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_REGISTRATION_RETURN_RVA
    );
    DWORD64 inbound_transport_delivery_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_INBOUND_TRANSPORT_DELIVERY_RVA
    );
    DWORD64 inbound_source_append_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA
    );
    DWORD64 dr0_address = g_transport_startup_probe_enabled
        ? reader_setup_a_address
        : g_bootstrap_type3_probe_enabled
        ? virtual_read_helper_address
        : (
            g_local_bridge_enabled
                ? inbound_transport_delivery_address
                : (
                    g_plaintext_probe_enabled
                        ? inbound_handoff_address
                        : queue_producer_address
                )
        );
    DWORD64 dr1_address = g_transport_startup_probe_enabled
        ? reader_setup_b_address
        : world_address;
    DWORD64 dr2_address = g_local_bridge_enabled
        ? outbound_plaintext_address
        : (
            g_inbound_source_probe_enabled
                ? inbound_transport_delivery_address
                : outbound_plaintext_address
        );
    DWORD64 inbound_batch_address = (DWORD64)(uintptr_t)(
        g_game_base + 0x1814360u
    );
    DWORD64 schema_deserialize_address = (DWORD64)(uintptr_t)(
        g_game_base + ISAC_SCHEMA_BOUNDARY_RVA
    );
    PVOID queue_watch = InterlockedCompareExchangePointer(
        &g_inbound_queue_watch_address,
        NULL,
        NULL
    );
    DWORD64 dr3_address = g_local_bridge_enabled
        ? bridge_reader_register_address
        : (
            g_inbound_source_probe_enabled
                ? inbound_source_append_address
                : (
                    g_plaintext_probe_enabled
                        ? schema_deserialize_address
                        : (
                            queue_watch != NULL
                                ? (DWORD64)(uintptr_t)queue_watch
                                : inbound_batch_address
                        )
                )
        );

    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &context)) {
        return FALSE;
    }
    if (!enabled && g_schema_field_probe_enabled) {
        context.Dr0 = 0;
        context.Dr1 = 0;
        context.Dr2 = 0;
        context.Dr3 = 0;
        context.Dr6 = 0;
        context.Dr7 &= ~(DWORD64)0xffff00ffu;
        return SetThreadContext(thread, &context);
    }
    if (enabled) {
        if (
            (
                (context.Dr7 & 0x3u) != 0 &&
                context.Dr0 != dr0_address &&
                context.Dr0 != inbound_advance_address
            ) ||
            ((context.Dr7 & 0xcu) != 0 && context.Dr1 != dr1_address) ||
            (
                g_plaintext_probe_enabled &&
                (context.Dr7 & 0x30u) != 0 &&
                context.Dr2 != dr2_address
            ) ||
            (
                (context.Dr7 & 0xc0u) != 0 &&
                context.Dr3 != inbound_batch_address &&
                context.Dr3 != schema_deserialize_address &&
                context.Dr3 != dr3_address
            )
        ) {
            return FALSE;
        }
        context.Dr0 = dr0_address;
        context.Dr1 = dr1_address;
        if (g_plaintext_probe_enabled) {
            context.Dr2 = dr2_address;
        }
        context.Dr3 = dr3_address;
        context.Dr6 = 0;
        if (g_plaintext_probe_enabled) {
            context.Dr7 =
                (context.Dr7 & ~(DWORD64)0xffff00ffu) | 0x55u;
        } else if (queue_watch != NULL) {
            context.Dr7 =
                (context.Dr7 & ~(DWORD64)0xf0ff00cfu) |
                (DWORD64)0xd0000045u;
        } else {
            context.Dr7 =
                (context.Dr7 & ~(DWORD64)0xf0ff00cfu) | 0x45u;
        }
    } else {
        if (
            g_tctd_certificate_probe_enabled &&
            (context.Dr7 & (DWORD64)0x000f0000u) ==
                (DWORD64)0x000b0000u
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            g_tctd_validation_probe_enabled &&
            (
                context.Dr0 == (DWORD64)(uintptr_t)(
                    g_game_base + ISAC_TCTD_KEY_RETURN_RVA
                ) ||
                context.Dr0 == (DWORD64)(uintptr_t)(
                    g_game_base + ISAC_TCTD_TLS_RETURN_A_RVA
                ) ||
                context.Dr0 == (DWORD64)(uintptr_t)(
                    g_game_base + ISAC_TCTD_TLS_RETURN_B_RVA
                ) ||
                context.Dr0 == (DWORD64)(uintptr_t)(
                    g_game_base + ISAC_TCTD_VALIDATION_CALLER_RVA
                ) ||
                context.Dr0 == (DWORD64)(uintptr_t)(
                    g_game_base + ISAC_TCTD_VALIDATION_RESULT_RVA
                )
            )
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            g_tctd_chain_probe_enabled &&
            InterlockedCompareExchange(&g_tctd_chain_stage, 0, 0) != 0
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            g_tctd_parser_code_enabled &&
            InterlockedCompareExchange(
                &g_tctd_parser_code_armed,
                0,
                0
            ) == 1
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            g_tctd_local_accept_enabled &&
            context.Dr0 == (DWORD64)(uintptr_t)(
                g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA
            )
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            g_tctd_state_watch_enabled &&
            InterlockedCompareExchange(
                &g_tctd_state_watch_stage,
                0,
                0
            ) != 0
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            g_tctd_owner_watch_enabled &&
            InterlockedCompareExchange(
                &g_tctd_owner_watch_stage,
                0,
                0
            ) != 0
        ) {
            context.Dr0 = 0;
            context.Dr1 = 0;
            context.Dr2 = 0;
            context.Dr7 &= ~(DWORD64)0x0fff003fu;
        }
        if (
            g_tctd_completion_probe_enabled &&
            InterlockedCompareExchange(
                &g_tctd_completion_armed,
                0,
                0
            ) != 0
        ) {
            context.Dr0 = 0;
            context.Dr1 = 0;
            context.Dr2 = 0;
            context.Dr7 &= ~(DWORD64)0x0fff003fu;
        }
        if (
            g_tctd_branch_probe_enabled &&
            InterlockedCompareExchange(&g_tctd_branch_armed, 0, 0) != 0
        ) {
            context.Dr0 = 0;
            context.Dr1 = 0;
            context.Dr2 = 0;
            context.Dr3 = 0;
            context.Dr7 &= ~(DWORD64)0xffff00ffu;
        }
        if (
            context.Dr0 == queue_producer_address ||
            context.Dr0 == inbound_virtual_reader_address ||
            context.Dr0 == virtual_read_helper_address ||
            context.Dr0 == inbound_handoff_address ||
            context.Dr0 == inbound_advance_address ||
            context.Dr0 == inbound_transport_delivery_address ||
            context.Dr0 == reader_setup_a_address
        ) {
            context.Dr0 = 0;
            context.Dr7 &= ~(DWORD64)0x000f0003u;
        }
        if (
            context.Dr1 == world_address ||
            context.Dr1 == reader_setup_b_address
        ) {
            context.Dr1 = 0;
            context.Dr7 &= ~(DWORD64)0x00f0000cu;
        }
        if (
            g_plaintext_probe_enabled &&
            (
                context.Dr2 == outbound_plaintext_address ||
                context.Dr2 == registration_return_address ||
                context.Dr2 == inbound_transport_delivery_address
            )
        ) {
            context.Dr2 = 0;
            context.Dr7 &= ~(DWORD64)0x0f000030u;
        }
        if (
            g_inbound_source_probe_enabled &&
            context.Dr3 == inbound_source_append_address
        ) {
            context.Dr3 = 0;
            context.Dr7 &= ~(DWORD64)0xf00000c0u;
        } else if (
            context.Dr3 == inbound_batch_address ||
            context.Dr3 == schema_deserialize_address ||
            context.Dr3 == bridge_reader_register_address ||
            context.Dr3 == dr3_address
        ) {
            context.Dr3 = 0;
            context.Dr7 &= ~(DWORD64)0xf00000c0u;
        }
        context.Dr6 = 0;
    }
    return SetThreadContext(thread, &context);
}

static BOOL arm_current_dispatch_thread(void) {
    DWORD thread_id = GetCurrentThreadId();

    if (dispatch_thread_recorded(thread_id)) {
        return TRUE;
    }
    if (
        g_schema_field_probe_enabled &&
        schema_field_thread_state(FALSE) != NULL
    ) {
        remember_dispatch_thread(thread_id);
        return TRUE;
    }
    if (!set_dispatch_breakpoints(GetCurrentThread(), TRUE)) {
        return FALSE;
    }
    remember_dispatch_thread(thread_id);
    return TRUE;
}

static void refresh_dispatch_thread_breakpoints(void) {
    HANDLE suspended[ISAC_MAX_SUSPENDED_THREADS];
    DWORD armed_thread_ids[ISAC_MAX_SUSPENDED_THREADS];
    size_t suspended_count;
    size_t index;
    unsigned int armed_count = 0;
    unsigned int failed_count = 0;
    BOOL suspended_complete;
    char detail[192];

    if (
        !g_bootstrap_type3_probe_enabled ||
        g_dispatch_install_state != 2
    ) {
        return;
    }
    suspended_count = suspend_other_threads(
        suspended,
        &suspended_complete
    );
    if (!suspended_complete) {
        resume_threads(suspended, suspended_count);
        log_dispatch_status(
            "BOOTSTRAP_TYPE3_REARM_ERROR",
            "thread-suspension-incomplete"
        );
        return;
    }
    for (index = 0; index < suspended_count; ++index) {
        if (set_dispatch_breakpoints(suspended[index], TRUE)) {
            armed_thread_ids[armed_count++] = GetThreadId(suspended[index]);
        } else {
            ++failed_count;
        }
    }
    resume_threads(suspended, suspended_count);
    for (index = 0; index < armed_count; ++index) {
        remember_dispatch_thread(armed_thread_ids[index]);
    }
    snprintf(
        detail,
        sizeof(detail),
        "pass=%ld,armed-threads=%u,unarmed-threads=%u",
        (long)(
            ISAC_TYPE3_REARM_PASSES -
            g_bootstrap_type3_rearm_passes + 1
        ),
        armed_count,
        failed_count
    );
    log_dispatch_status(
        g_local_bridge_injection_enabled
            ? "LOCAL_BRIDGE_INJECTION_REARM"
            : "BOOTSTRAP_TYPE3_REARM",
        detail
    );
}

static void record_transport_startup_milestone(
    const char *milestone,
    const CONTEXT *context
) {
    LONG sequence = next_transport_startup_event();
    char detail[224];

    if (sequence == 0) {
        return;
    }
    snprintf(
        detail,
        sizeof(detail),
        "sequence=%ld,milestone=%s,rcx=%s,rdx=%s,r8=%s,r9=%s",
        sequence,
        milestone,
        context->Rcx == 0u ? "null" : "set",
        context->Rdx == 0u ? "null" : "set",
        context->R8 == 0u ? "null" : "set",
        context->R9 == 0u ? "null" : "set"
    );
    log_dispatch_status("TRANSPORT_STARTUP_MILESTONE", detail);
}

static LONG CALLBACK dispatch_exception_handler(
    EXCEPTION_POINTERS *exception
) {
    DWORD64 instruction;
    LONG validation_stage;
    uintptr_t validation_target_rva;
    const char *validation_checkpoint;
    LONG chain_stage;
    uintptr_t chain_target_rva;
    const char *chain_checkpoint;

    if (handle_handoff_zero_debug(exception)) return EXCEPTION_CONTINUE_EXECUTION;
    record_handoff_exception(exception);
    if (exception->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    instruction = exception->ContextRecord->Rip;
    if (handle_echo_breakpoint(exception->ContextRecord)) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (handle_allocation_breakpoint(exception->ContextRecord)) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_branch_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_branch_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_BRANCH_READY_RVA
        )
    ) {
        record_tctd_branch_checkpoint(
            "operation-ready",
            (unsigned int)(exception->ContextRecord->Rax & 0xffu),
            exception->ContextRecord,
            FALSE
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_branch_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_branch_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x2u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_BRANCH_STATUS_READY_RVA
        )
    ) {
        record_tctd_branch_checkpoint(
            "status-ready",
            (unsigned int)(exception->ContextRecord->Rax & 0xffu),
            exception->ContextRecord,
            FALSE
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_branch_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_branch_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x4u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_BRANCH_STATUS_RVA
        )
    ) {
        USHORT *status = (USHORT *)(uintptr_t)(
            exception->ContextRecord->Rsp + 0x30u
        );
        unsigned int value;

        if (!readable_memory_window(status, sizeof(*status))) {
            log_status(
                "TCTD_BRANCH_PROBE_ERROR",
                "tls-status-not-readable,breakpoints=disabled"
            );
            exception->ContextRecord->Dr0 = 0;
            exception->ContextRecord->Dr1 = 0;
            exception->ContextRecord->Dr2 = 0;
            exception->ContextRecord->Dr3 = 0;
            exception->ContextRecord->Dr6 = 0;
            exception->ContextRecord->Dr7 &= ~(DWORD64)0xffff00ffu;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        value = (unsigned int)*status;
        record_tctd_branch_checkpoint(
            "tls-status",
            value,
            exception->ContextRecord,
            value != 0u
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_branch_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_branch_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x8u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_BRANCH_FINAL_RVA
        )
    ) {
        record_tctd_branch_checkpoint(
            "final-helper",
            (unsigned int)(exception->ContextRecord->Rax & 0xffu),
            exception->ContextRecord,
            TRUE
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_completion_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_completion_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_COMPLETION_ENTRY_RVA
        )
    ) {
        record_tctd_completion_checkpoint(
            "worker-entry",
            (BYTE *)(uintptr_t)exception->ContextRecord->Rcx,
            exception->ContextRecord,
            FALSE
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_completion_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_completion_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x2u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_VALIDATOR_SUCCESS_RESUME_RVA
        )
    ) {
        InterlockedIncrement(&g_tctd_completion_setter_count);
        record_tctd_completion_checkpoint(
            "completion-setter",
            (BYTE *)(uintptr_t)exception->ContextRecord->Rbx,
            exception->ContextRecord,
            TRUE
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_completion_probe_enabled &&
        InterlockedCompareExchange(&g_tctd_completion_armed, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x4u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_COMPLETION_RETURN_RVA
        )
    ) {
        record_tctd_completion_checkpoint(
            "shared-return",
            (BYTE *)(uintptr_t)exception->ContextRecord->Rbx,
            exception->ContextRecord,
            FALSE
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_parser_code_enabled &&
        InterlockedCompareExchange(&g_tctd_parser_code_armed, 0, 0) == 1 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_PARSER_CALL_RVA
        )
    ) {
        DWORD64 *slot = (DWORD64 *)(uintptr_t)(
            exception->ContextRecord->Rax + 0x10u
        );
        DWORD64 target = 0u;
        uintptr_t target_rva = 0u;
        char detail[256];

        exception->ContextRecord->Dr0 = 0;
        exception->ContextRecord->Dr6 = 0;
        exception->ContextRecord->Dr7 &= ~(DWORD64)0x000f0003u;
        InterlockedExchange(&g_tctd_parser_code_armed, 2);
        if (readable_memory_window(slot, sizeof(*slot))) {
            target = *slot;
        }
        if (
            target < (DWORD64)(uintptr_t)g_game_base ||
            target >= (DWORD64)(uintptr_t)(g_game_base + g_game_size)
        ) {
            log_status(
                "TCTD_PARSER_CODE_ERROR",
                "vtable-slot-target-outside-game,breakpoint=disabled"
            );
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        target_rva = (uintptr_t)(
            target - (DWORD64)(uintptr_t)g_game_base
        );
        snprintf(
            detail,
            sizeof(detail),
            "call-rva=0x%llx,target-rva=0x%llx,input-length=%lu,"
            "callback=%s,breakpoint=disabled,mutation=disabled,"
            "payloads=disabled",
            (unsigned long long)ISAC_TCTD_PARSER_CALL_RVA,
            (unsigned long long)target_rva,
            (unsigned long)(exception->ContextRecord->R8 & 0xffffffffu),
            exception->ContextRecord->Rdi == 0u ? "null" : "set"
        );
        log_status("TCTD_PARSER_CODE_TARGET", detail);
        capture_tctd_parser_body(target_rva);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_certificate_probe_enabled &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        (exception->ContextRecord->Dr7 & (DWORD64)0x000f0000u) ==
            (DWORD64)0x000b0000u
    ) {
        if (g_tctd_cert_flow_enabled) {
            record_tctd_certificate_flow(exception->ContextRecord);
        } else {
            record_tctd_certificate_read(exception->ContextRecord);
        }
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_owner_watch_enabled &&
        InterlockedCompareExchange(&g_tctd_owner_watch_stage, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x2u) != 0 &&
        (exception->ContextRecord->Dr7 & (DWORD64)0x00f00000u) ==
            (DWORD64)0x00900000u
    ) {
        record_tctd_owner_field_write(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_owner_watch_enabled &&
        InterlockedCompareExchange(&g_tctd_owner_watch_stage, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x4u) != 0 &&
        (exception->ContextRecord->Dr7 & (DWORD64)0x0f000000u) ==
            (DWORD64)0x01000000u
    ) {
        record_tctd_owner_state_write(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_owner_watch_enabled &&
        InterlockedCompareExchange(&g_tctd_owner_watch_stage, 0, 0) != 0 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_COMPLETION_DECISION_RVA
        )
    ) {
        begin_or_refresh_tctd_owner_watch(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_state_watch_enabled &&
        InterlockedCompareExchange(&g_tctd_state_watch_stage, 0, 0) == 2 &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        (exception->ContextRecord->Dr7 & (DWORD64)0x000f0000u) ==
            (DWORD64)0x00010000u
    ) {
        record_tctd_state_write(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_state_watch_enabled &&
        InterlockedCompareExchange(&g_tctd_state_watch_stage, 0, 0) == 1 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_COMPLETION_DECISION_RVA
        )
    ) {
        begin_tctd_state_write_watch(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_tctd_local_accept_enabled &&
        InterlockedCompareExchange(&g_tctd_local_accept_armed, 0, 0) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_TCTD_LOCAL_ACCEPT_RVA
        )
    ) {
        apply_tctd_local_acceptance(exception->ContextRecord);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    validation_stage = InterlockedCompareExchange(
        &g_tctd_validation_stage,
        0,
        0
    );
    validation_target_rva =
        tctd_validation_checkpoint_rva(validation_stage);
    validation_checkpoint =
        tctd_validation_checkpoint_name(validation_stage);
    if (
        g_tctd_validation_probe_enabled &&
        validation_target_rva != 0u &&
        validation_checkpoint != NULL &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + validation_target_rva
        )
    ) {
        record_tctd_validation_checkpoint(
            validation_checkpoint,
            exception->ContextRecord
        );
        if (
            InterlockedCompareExchange(
                &g_tctd_validation_event_count,
                0,
                0
            ) < ISAC_MAX_TCTD_VALIDATION_EVENTS
        ) {
            stage_tctd_validation_checkpoint(
                exception->ContextRecord,
                validation_stage + 1
            );
        }
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    chain_stage = InterlockedCompareExchange(&g_tctd_chain_stage, 0, 0);
    chain_target_rva = tctd_chain_checkpoint_rva(chain_stage);
    chain_checkpoint = tctd_chain_checkpoint_name(chain_stage);
    if (
        g_tctd_chain_probe_enabled &&
        chain_target_rva != 0u &&
        chain_checkpoint != NULL &&
        (exception->ContextRecord->Dr6 & (DWORD64)0x1u) != 0 &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + chain_target_rva
        )
    ) {
        record_tctd_chain_checkpoint(
            chain_checkpoint,
            exception->ContextRecord
        );
        if (
            InterlockedCompareExchange(
                &g_tctd_chain_event_count,
                0,
                0
            ) < ISAC_MAX_TCTD_CHAIN_EVENTS
        ) {
            stage_tctd_chain_checkpoint(
                exception->ContextRecord,
                chain_stage + 1
            );
        }
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_transport_startup_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_READER_SETUP_A_RVA
        )
    ) {
        record_transport_startup_milestone(
            "reader-setup-a",
            exception->ContextRecord
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_transport_startup_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_READER_SETUP_B_RVA
        )
    ) {
        record_transport_startup_milestone(
            "reader-setup-b",
            exception->ContextRecord
        );
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        (g_local_bridge_enabled || g_transport_startup_probe_enabled) &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_READER_REGISTER_RVA
        )
    ) {
        if (g_transport_startup_probe_enabled) {
            record_transport_startup_milestone(
                "reader-registration",
                exception->ContextRecord
            );
        }
        if (g_local_bridge_enabled) {
            local_bridge_record_reader(
                (const BYTE *)(uintptr_t)exception->ContextRecord->Rcx,
                "registration",
                FALSE
            );
        }
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        (exception->ContextRecord->Dr6 & (DWORD64)0x8u) != 0 &&
        g_inbound_source_probe_enabled &&
        exception->ContextRecord->Dr3 == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA
        )
    ) {
        record_inbound_source_append(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        (exception->ContextRecord->Dr6 & (DWORD64)0x8u) != 0 &&
        g_inbound_source_probe_enabled &&
        exception->ContextRecord->Dr3 !=
            (DWORD64)(uintptr_t)(g_game_base + ISAC_SCHEMA_BOUNDARY_RVA) &&
        exception->ContextRecord->Dr3 != (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_SOURCE_APPEND_RVA
        )
    ) {
        record_inbound_source_write(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        (exception->ContextRecord->Dr6 & (DWORD64)0x8u) != 0 &&
        g_inbound_queue_watch_address != NULL &&
        exception->ContextRecord->Dr3 ==
            (DWORD64)(uintptr_t)g_inbound_queue_watch_address
    ) {
        record_inbound_queue_write(exception->ContextRecord);
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (handle_schema_field_breakpoint(exception->ContextRecord)) {
        exception->ContextRecord->Dr6 = 0;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (
        g_bootstrap_type3_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_VIRTUAL_READ_HELPER_RVA
        )
    ) {
        capture_bootstrap_type3_read_entry(exception->ContextRecord);
    } else if (
        g_plaintext_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_HANDOFF_RVA
        )
    ) {
        capture_inbound_handoff(exception->ContextRecord);
    } else if (
        g_inbound_source_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_ADVANCE_RVA
        )
    ) {
        capture_inbound_source_advance(exception->ContextRecord);
    } else if (
        g_plaintext_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(g_game_base + 0x0f84315u)
    ) {
        capture_inbound_virtual_reader(
            (const BYTE *)(uintptr_t)exception->ContextRecord->Rbx
        );
    } else if (
        g_plaintext_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(g_game_base + 0x111d78au)
    ) {
        capture_inbound_plaintext_record(
            (const BYTE *)(uintptr_t)exception->ContextRecord->Rsi
        );
    } else if (
        g_plaintext_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_SCHEMA_BOUNDARY_RVA
        )
    ) {
        record_schema_deserializer(exception->ContextRecord);
    } else if (
        instruction == (DWORD64)(uintptr_t)(g_game_base + 0x0f843b6u)
    ) {
        record_inbound_queue_producer(exception->ContextRecord);
    } else if (
        instruction == (DWORD64)(uintptr_t)(g_game_base + 0x0f8e8d0u)
    ) {
        record_dispatch_caller(
            (void *)(uintptr_t)exception->ContextRecord->Rdx,
            exception->ContextRecord->Rsp
        );
        record_dispatch_target(
            'M',
            (void *)(uintptr_t)exception->ContextRecord->Rdx,
            3u
        );
    } else if (
        instruction == (DWORD64)(uintptr_t)(g_game_base + 0x1814360u)
    ) {
        record_inbound_scheduler_caller(exception->ContextRecord->Rsp);
        activate_inbound_queue_watch(
            (void *)(uintptr_t)exception->ContextRecord->Rcx,
            exception->ContextRecord
        );
    } else if (
        g_local_bridge_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_TRANSPORT_DELIVERY_RVA
        )
    ) {
        local_bridge_record_delivery(exception->ContextRecord);
    } else if (
        g_inbound_source_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_INBOUND_TRANSPORT_DELIVERY_RVA
        )
    ) {
        record_inbound_transport_delivery(exception->ContextRecord);
    } else if (
        g_inbound_source_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(
            g_game_base + ISAC_REGISTRATION_RETURN_RVA
        )
    ) {
        capture_inbound_registration_object(exception->ContextRecord);
    } else if (
        g_plaintext_probe_enabled &&
        instruction == (DWORD64)(uintptr_t)(g_game_base + 0x0d6bbfu)
    ) {
        if (g_transport_startup_probe_enabled) {
            record_transport_startup_milestone(
                "outbound-writer-handoff",
                exception->ContextRecord
            );
        }
        capture_serialized_writer(
            (const BYTE *)(uintptr_t)exception->ContextRecord->Rdx,
            exception->ContextRecord
        );
    } else {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    exception->ContextRecord->Dr6 = 0;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void enable_dispatch_event_probe(void) {
    if (!g_dispatch_event_requested) {
        return;
    }
    g_dispatch_event_file = CreateFileW(
        g_dispatch_log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (g_dispatch_event_file == INVALID_HANDLE_VALUE) {
        log_dispatch_status(
            "DISPATCH_EVENT_ERROR",
            "event-log-open-failed"
        );
        return;
    }
    g_dispatch_event_enabled = TRUE;
    log_dispatch_status(
        "DISPATCH_EVENT_READY",
        "max-events=32768,payloads=disabled"
    );
}

static void ensure_dispatch_hooks(void) {
    BYTE *inbound_target;
    BYTE *world_target;
    BYTE *inbound_batch_target;
    BYTE *outbound_plaintext_target;
    BYTE *inbound_plaintext_target;
    BYTE *inbound_virtual_reader_target;
    BYTE *inbound_handoff_target;
    BYTE *schema_deserialize_target;
    BYTE *reader_register_target;
    BYTE *reader_setup_a_target;
    BYTE *reader_setup_b_target;
    HANDLE suspended[ISAC_MAX_SUSPENDED_THREADS];
    size_t suspended_count;
    size_t index;
    unsigned int armed_count = 0;
    unsigned int failed_count = 0;
    BOOL suspended_complete;
    char ready_detail[256];
    char field_detail[320];

    if (
        !g_dispatch_probe_enabled ||
        InterlockedCompareExchange(&g_dispatch_install_state, 1, 0) != 0
    ) {
        return;
    }

    inbound_target = g_game_base + 0x0f843b6u;
    world_target = g_game_base + 0x0f8e8d0u;
    inbound_batch_target = g_game_base + 0x1814360u;
    outbound_plaintext_target = g_game_base + 0x0d6bbfu;
    inbound_plaintext_target = g_game_base + 0x111d78au;
    inbound_virtual_reader_target = g_game_base + 0x0f84315u;
    inbound_handoff_target = g_game_base + 0x009a845u;
    schema_deserialize_target = g_game_base + ISAC_SCHEMA_BOUNDARY_RVA;
    reader_register_target = g_game_base + ISAC_READER_REGISTER_RVA;
    reader_setup_a_target = g_game_base + ISAC_READER_SETUP_A_RVA;
    reader_setup_b_target = g_game_base + ISAC_READER_SETUP_B_RVA;
    if (
        !readable_code_window(
            inbound_target,
            sizeof(g_inbound_queue_producer_signature)
        ) ||
        !readable_code_window(
            world_target,
            sizeof(g_world_dispatch_signature)
        ) ||
        !readable_code_window(
            inbound_batch_target,
            sizeof(g_inbound_batch_signature)
        ) ||
        memcmp(
            inbound_target,
            g_inbound_queue_producer_signature,
            sizeof(g_inbound_queue_producer_signature)
        ) != 0 ||
        memcmp(
            world_target,
            g_world_dispatch_signature,
            sizeof(g_world_dispatch_signature)
        ) != 0 ||
        memcmp(
            inbound_batch_target,
            g_inbound_batch_signature,
            sizeof(g_inbound_batch_signature)
        ) != 0
    ) {
        log_dispatch_status("DISPATCH_PROBE_ERROR", "target-signature");
        InterlockedExchange(&g_dispatch_install_state, -1);
        return;
    }
    if (g_plaintext_probe_requested) {
        if (
            !readable_code_window(
                outbound_plaintext_target,
                sizeof(g_outbound_plaintext_signature)
            ) ||
            !readable_code_window(
                inbound_plaintext_target,
                sizeof(g_inbound_plaintext_signature)
            ) ||
            !readable_code_window(
                inbound_virtual_reader_target,
                sizeof(g_inbound_virtual_reader_signature)
            ) ||
            !readable_code_window(
                inbound_handoff_target,
                sizeof(g_inbound_handoff_signature)
            ) ||
            !readable_code_window(
                schema_deserialize_target,
                sizeof(g_schema_deserialize_signature)
            ) ||
            (
                (g_local_bridge_requested ||
                    g_transport_startup_probe_requested) &&
                (
                    !readable_code_window(
                        reader_register_target,
                        sizeof(g_reader_register_signature)
                    ) ||
                    memcmp(
                        reader_register_target,
                        g_reader_register_signature,
                        sizeof(g_reader_register_signature)
                    ) != 0
                )
            ) ||
            (
                g_transport_startup_probe_requested &&
                (
                    !readable_code_window(
                        reader_setup_a_target,
                        sizeof(g_reader_setup_a_signature)
                    ) ||
                    !readable_code_window(
                        reader_setup_b_target,
                        sizeof(g_reader_setup_b_signature)
                    ) ||
                    memcmp(
                        reader_setup_a_target,
                        g_reader_setup_a_signature,
                        sizeof(g_reader_setup_a_signature)
                    ) != 0 ||
                    memcmp(
                        reader_setup_b_target,
                        g_reader_setup_b_signature,
                        sizeof(g_reader_setup_b_signature)
                    ) != 0
                )
            ) ||
            memcmp(
                outbound_plaintext_target,
                g_outbound_plaintext_signature,
                sizeof(g_outbound_plaintext_signature)
            ) != 0 ||
            memcmp(
                inbound_plaintext_target,
                g_inbound_plaintext_signature,
                sizeof(g_inbound_plaintext_signature)
            ) != 0 ||
            memcmp(
                inbound_virtual_reader_target,
                g_inbound_virtual_reader_signature,
                sizeof(g_inbound_virtual_reader_signature)
            ) != 0 ||
            memcmp(
                inbound_handoff_target,
                g_inbound_handoff_signature,
                sizeof(g_inbound_handoff_signature)
            ) != 0 ||
            memcmp(
                schema_deserialize_target,
                g_schema_deserialize_signature,
                sizeof(g_schema_deserialize_signature)
            ) != 0
        ) {
            log_plaintext_status(
                "PLAINTEXT_PROBE_ERROR",
                "plaintext-boundary-signature"
            );
            g_plaintext_probe_requested = FALSE;
        } else {
            g_plaintext_probe_enabled = TRUE;
            g_bootstrap_probe_enabled = g_bootstrap_probe_requested;
            g_control_probe_enabled = g_control_probe_requested;
            g_bootstrap_type3_probe_enabled =
                g_bootstrap_type3_probe_requested;
            g_outbound_control_probe_enabled =
                g_outbound_control_probe_requested;
            g_inbound_source_probe_enabled =
                g_inbound_source_probe_requested;
            g_schema_miner_enabled = g_schema_miner_requested;
            g_schema_field_probe_enabled =
                g_schema_field_probe_requested || g_schema_miner_enabled;
            g_local_bridge_enabled = g_local_bridge_requested;
            g_local_bridge_injection_enabled =
                g_local_bridge_enabled &&
                g_local_bridge_injection_requested;
            g_local_bridge_type3_isolation_enabled =
                g_local_bridge_injection_enabled &&
                g_local_bridge_type3_isolation_requested;
            g_type3_profile_capture_enabled =
                g_local_bridge_enabled &&
                g_type3_profile_capture_requested &&
                !g_local_bridge_injection_enabled &&
                !g_bootstrap_type3_probe_enabled;
            g_world_bootstrap_probe_enabled =
                g_local_bridge_injection_enabled &&
                g_world_bootstrap_probe_requested;
            g_world_snapshot_capture_enabled =
                g_world_bootstrap_probe_enabled &&
                g_world_snapshot_capture_requested;
            g_world_continuation_capture_enabled =
                g_world_snapshot_capture_enabled &&
                g_world_continuation_capture_requested;
            g_world_replay_enabled =
                g_world_bootstrap_probe_enabled &&
                g_world_replay_requested;
            g_transport_startup_probe_enabled =
                g_transport_startup_probe_requested;
            g_tctd_certificate_probe_enabled =
                g_transport_startup_probe_enabled &&
                (
                    g_tctd_pc_loopback_requested ||
                    g_tctd_validation_remote_requested ||
                    g_tctd_completion_remote_requested ||
                    g_tctd_branch_remote_requested ||
                    g_tctd_chain_remote_requested ||
                    g_tctd_cert_flow_remote_requested
                ) &&
                g_tctd_certificate_probe_requested;
            g_tctd_validation_probe_enabled =
                g_tctd_certificate_probe_enabled &&
                g_tctd_validation_probe_requested &&
                g_code_probe_enabled;
            g_tctd_local_accept_enabled =
                g_transport_startup_probe_enabled &&
                g_tctd_pc_loopback_requested &&
                g_tctd_local_accept_requested;
            g_tctd_validator_code_enabled =
                g_transport_startup_probe_enabled &&
                g_tctd_pc_loopback_requested &&
                g_tctd_validator_code_requested &&
                g_code_probe_enabled;
            g_tctd_state_watch_enabled =
                g_transport_startup_probe_enabled &&
                g_tctd_pc_loopback_requested &&
                g_tctd_state_watch_requested &&
                g_code_probe_enabled;
            g_tctd_owner_watch_enabled =
                g_transport_startup_probe_enabled &&
                (
                    g_tctd_pc_loopback_requested ||
                    g_tctd_owner_remote_requested
                ) &&
                g_tctd_owner_watch_requested &&
                g_code_probe_enabled;
            g_tctd_completion_probe_enabled =
                g_transport_startup_probe_enabled &&
                (
                    g_tctd_pc_loopback_requested ||
                    g_tctd_completion_remote_requested
                ) &&
                g_tctd_completion_probe_requested &&
                g_code_probe_enabled;
            g_tctd_branch_probe_enabled =
                g_transport_startup_probe_enabled &&
                (
                    g_tctd_pc_loopback_requested ||
                    g_tctd_branch_remote_requested
                ) &&
                g_tctd_branch_probe_requested &&
                g_code_probe_enabled;
            g_tctd_chain_probe_enabled =
                g_tctd_certificate_probe_enabled &&
                g_tctd_chain_probe_requested &&
                g_code_probe_enabled;
            g_tctd_parser_code_enabled =
                g_tctd_certificate_probe_enabled &&
                g_tctd_pc_loopback_requested &&
                g_tctd_parser_code_requested &&
                g_code_probe_enabled;
            g_tctd_cert_flow_enabled =
                g_tctd_certificate_probe_enabled &&
                g_tctd_cert_flow_requested &&
                g_code_probe_enabled;
        }
    }
    if (g_tctd_echo_requested) {
        if (!g_transport_startup_probe_enabled || !g_tctd_pc_loopback_requested ||
            g_tctd_allocation_requested || !initialize_echo_checkpoints()) {
            log_status("TCTD_ECHO_ERROR", "checkpoint-configuration-or-signature");
            InterlockedExchange(&g_dispatch_install_state, -1);
            return;
        }
        g_tctd_echo_enabled = TRUE;
    }
    if (g_tctd_allocation_requested) {
        if (g_tctd_pc_loopback_requested || g_tctd_certificate_probe_requested ||
            g_tctd_local_accept_requested || !initialize_allocation_capture()) {
            log_status("TCTD_ALLOCATION_ERROR", "capture-config-or-signature-invalid");
            InterlockedExchange(&g_dispatch_install_state, -1);
            return;
        }
        g_tctd_allocation_enabled = TRUE;
    }
    if (g_login_handoff_requested && !initialize_handoff_faults()) {
        log_status("LOGIN_HANDOFF_ERROR", "exception-log-open-failed");
        InterlockedExchange(&g_dispatch_install_state, -1);
        return;
    }
    g_dispatch_exception_handler = AddVectoredExceptionHandler(
        1,
        dispatch_exception_handler
    );
    if (g_dispatch_exception_handler == NULL) {
        log_dispatch_status("DISPATCH_PROBE_ERROR", "exception-handler");
        InterlockedExchange(&g_dispatch_install_state, -1);
        return;
    }

    suspended_count = suspend_other_threads(suspended, &suspended_complete);
    if (!suspended_complete) {
        resume_threads(suspended, suspended_count);
        RemoveVectoredExceptionHandler(g_dispatch_exception_handler);
        g_dispatch_exception_handler = NULL;
        log_dispatch_status("DISPATCH_PROBE_ERROR", "thread-suspension");
        InterlockedExchange(&g_dispatch_install_state, -1);
        return;
    }
    for (index = 0; index < suspended_count; ++index) {
        if (set_dispatch_breakpoints(suspended[index], TRUE)) {
            remember_dispatch_thread(GetThreadId(suspended[index]));
            ++armed_count;
        } else {
            ++failed_count;
        }
    }
    if (!arm_current_dispatch_thread()) {
        for (index = 0; index < suspended_count; ++index) {
            set_dispatch_breakpoints(suspended[index], FALSE);
        }
        resume_threads(suspended, suspended_count);
        RemoveVectoredExceptionHandler(g_dispatch_exception_handler);
        g_dispatch_exception_handler = NULL;
        log_dispatch_status("DISPATCH_PROBE_ERROR", "current-thread-breakpoints");
        InterlockedExchange(&g_dispatch_install_state, -1);
        return;
    }
    ++armed_count;
    enable_dispatch_event_probe();
    if (g_plaintext_probe_enabled) {
        log_plaintext_status(
            "PLAINTEXT_PROBE_READY",
            "directions=inbound,outbound,max-records-per-direction=512,"
            "max-bytes=1000,"
            "gate=inbound-type-0x0012,inbound-stage=virtual-handoff,"
            "bootstrap-metadata-before-gate=optional"
        );
        if (g_bootstrap_probe_enabled) {
            log_plaintext_status(
                "BOOTSTRAP_PROBE_READY",
                "phase=startup,payloads=redacted,frame-types=enabled,"
                "connection-ids=bounded,stream-ids=bounded"
            );
        }
        if (g_control_probe_enabled) {
            log_dispatch_status(
                "CONTROL_PROBE_READY",
                g_bootstrap_type3_probe_enabled
                    ? "target-types=0x0003,max-events=32,"
                        "max-code-functions=32,max-code-bytes=4096,"
                        "direct-code-targets=4,forward-bytes=4096,"
                        "payloads=disabled"
                    : "target-types=0x0002,0x0006,max-events=32,"
                "max-code-functions=32,max-code-bytes=4096,"
                "direct-code-targets=9,forward-bytes=4096,"
                "payloads=disabled"
            );
            if (!g_bootstrap_type3_probe_enabled) {
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_TYPE_0002_DECODER_RVA
                );
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_TYPE_0002_SCHEMA_RVA
                );
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_FIXED_READERS_RVA
                );
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_TYPE_0002_AUX_LOW_RVA
                );
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_TYPE_0002_SUBOBJECT_RVA
                );
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_TYPE_0002_AUX_HIGH_RVA
                );
                capture_control_code(
                    0x0002u,
                    ISAC_CONTROL_TYPE_0002_NESTED_RVA
                );
                capture_control_code(
                    0x0006u,
                    ISAC_CONTROL_TYPE_0006_DECODER_RVA
                );
                capture_control_code(
                    0x0006u,
                    ISAC_CONTROL_TYPE_0006_SCHEMA_RVA
                );
            } else {
                capture_control_code(
                    0x0003u,
                    ISAC_CONTROL_TYPE_0003_DISPATCHER_RVA
                );
                capture_control_code(
                    0x0003u,
                    ISAC_CONTROL_TYPE_0003_DECODER_RVA
                );
                capture_control_code(
                    0x0003u,
                    ISAC_CONTROL_TYPE_0003_SCHEMA_RVA
                );
                capture_control_code(
                    0x0003u,
                    ISAC_CONTROL_TYPE_0003_COLLECTION_READERS_RVA
                );
            }
        }
        if (g_bootstrap_type3_probe_enabled) {
            log_dispatch_status(
                "BOOTSTRAP_TYPE3_PROBE_READY",
                "target-type=0x0003,dr0=virtual-read-helper,"
                "helper-rva=0x9a7c0,rearm-after-login-request=12x25ms,"
                "max-events=32,"
                "max-code-functions=32,max-code-bytes=4096,"
                "payloads=disabled"
            );
        }
        if (g_outbound_control_probe_enabled) {
            log_dispatch_status(
                "OUTBOUND_CONTROL_PROBE_READY",
                "target-types=0x0002,0x0005,max-events=32,"
                "max-code-functions=32,max-code-bytes=4096,"
                "correlation-types=outbound-0x0002/0x0005-and-"
                "inbound-0x0002/0x0006,max-correlation-events=64,"
                "payloads=disabled,redacted-only=enabled"
            );
        }
        if (g_inbound_source_probe_enabled) {
            log_dispatch_status(
                "INBOUND_SOURCE_PROBE_READY",
                "max-reader-vtables=8,reader-vtable-slots=16,"
                "max-vtable-xrefs=32,"
                "transport-delivery-rva=0x84bd0,"
                "source-append-rva=0x223d140,"
                "injection-helper-rvas=0xb7e0/0x1e0a0/0xc6c0,"
                "reader-advance-rva=0x9a851,vtable-offset=0x38,"
                "per-thread=enabled,max-delivery-events=128,"
                "max-delivery-chunks=32,code-windows=bounded,"
                "payloads=disabled"
            );
        }
        if (g_local_bridge_enabled) {
            log_dispatch_status(
                "LOCAL_BRIDGE_ARMED",
                g_transport_startup_probe_enabled
                    ? "mode=transport-startup-diagnostic,"
                        "dr0=reader-setup-a,dr1=reader-setup-b,"
                        "dr2=outbound-plaintext,dr3=reader-registration,"
                        "injection=disabled"
                    : g_local_bridge_injection_enabled
                    ? g_local_bridge_type3_isolation_enabled
                        ? "mode=type-0x0003-inject-once,"
                            "dr0=transport-delivery,"
                            "dr2=outbound-plaintext,"
                            "dr3=reader-registration,"
                            "target-reader-id=1,"
                            "retail-type3=blocked-readers-1-through-2"
                        : "mode=type-0x0003-inject-once,"
                            "dr0=transport-delivery,"
                            "dr2=outbound-plaintext,"
                            "dr3=reader-registration,"
                            "target-reader-id=1,retail-path=enabled"
                    : g_type3_profile_capture_enabled
                    ? "mode=receive-observe-only,dr0=transport-delivery,"
                        "dr2=outbound-plaintext,dr3=reader-registration,"
                        "private-type3-capture=reader-1-once,"
                        "retail-path=enabled"
                    : g_bootstrap_type3_probe_enabled
                    ? "mode=receive-observe-only,dr0=virtual-read-helper,"
                        "dr2=outbound-plaintext,dr3=reader-registration,"
                        "delivery-correlation=disabled,injection=disabled"
                    : "mode=receive-observe-only,dr0=transport-delivery,"
                "dr2=outbound-plaintext,dr3=reader-registration,"
                "injection=disabled"
            );
        }
        if (g_transport_startup_probe_enabled) {
            log_dispatch_status(
                "TRANSPORT_STARTUP_PROBE_READY",
                "dr0=reader-setup-a,dr1=reader-setup-b,"
                "dr2=outbound-plaintext,dr3=reader-registration,"
                "socket-hooks=connect/getaddrinfo-a/getaddrinfo-w,"
                "payloads=disabled,endpoints=classified-not-recorded"
            );
            if (g_tctd_certificate_probe_enabled) {
                log_dispatch_status(
                    "TCTD_CERT_PROBE_READY",
                    "source=port-27015-recv,selector=ec-p256-spki,"
                    "watch=first-public-key,max-read-events=64,"
                    "instruction-and-caller-rvas=enabled,"
                    "payloads=disabled"
                );
            }
            if (g_tctd_validation_probe_enabled) {
                log_dispatch_status(
                    "TCTD_VALIDATION_PROBE_READY",
                    "trigger=ec-p256-spki,code-windows=8,"
                    "slot=dr0,mode=data-then-staged-execute,"
                    "return-checkpoints=5,max-events=128,"
                    "register-scalars=enabled,payloads=disabled"
                );
            }
            if (g_tctd_chain_probe_enabled) {
                log_dispatch_status(
                    "TCTD_CHAIN_PROBE_READY",
                    "trigger=ec-p256-spki,key-copy=0x21fea19,slot=dr0,"
                    "mode=data-then-staged-execute,return-checkpoints=6,"
                    "code-windows=6,max-events=32,register-scalars=enabled,"
                    "mutation=disabled,payloads=disabled"
                );
            }
            if (g_tctd_parser_code_enabled) {
                log_dispatch_status(
                    "TCTD_PARSER_CODE_READY",
                    "trigger=ec-p256-spki,call-rva=0x20167d8,"
                    "dynamic-vtable-slot=0x10,max-windows=12,"
                    "mutation=disabled,payloads=disabled"
                );
            }
            if (g_tctd_cert_flow_enabled) {
                log_dispatch_status(
                    "TCTD_CERT_FLOW_READY",
                    "trigger=ec-p256-spki,watch=copy-following-data,"
                    "max-events=256,max-consumer-code-windows=12,"
                    "mutation=disabled,payloads=disabled"
                );
            }
            if (g_tctd_local_accept_enabled) {
                log_dispatch_status(
                    "TCTD_LOCAL_ACCEPT_READY",
                    "trigger=loopback-port-27015-ec-p256-spki,"
                    "target-rva=0x206573b,gate=certificate-verifier-return,"
                    "slot=dr0,rearm=per-certificate,max-attempts=256,payloads=disabled"
                );
            }
            if (g_tctd_validator_code_enabled) {
                log_dispatch_status(
                    "TCTD_VALIDATOR_CODE_READY",
                    "trigger=loopback-port-27015-ec-p256-spki,"
                    "range=runtime-function-containing-0xf12b1,"
                    "max-windows=8,max-window=512,mutation=disabled"
                );
            }
            if (g_tctd_state_watch_enabled) {
                log_dispatch_status(
                    "TCTD_STATE_WATCH_READY",
                    "trigger=loopback-port-27015-ec-p256-spki,"
                    "decision-rva=0xbb4cd,slot=dr0,watch-bytes=1,"
                    "access=write,max-events=64,mutation=disabled"
                );
            }
        }
        if (g_world_bootstrap_probe_enabled) {
            log_dispatch_status(
                "WORLD_BOOTSTRAP_PROBE_READY",
                "request-selector=post-login-channel-0-type-0x0000-"
                "single-frame-512-through-2048-bytes,"
                "private-request-capture=once,"
                "reader-selector=first-post-request-reader,"
                "stream-sync=complete-type-0x0002-frame,"
                "frame-metadata-only=enabled,max-events=4096,"
                "payload-logging=disabled"
            );
        }
        if (g_world_snapshot_capture_enabled) {
            log_dispatch_status(
                "WORLD_SNAPSHOT_CAPTURE_READY",
                g_world_continuation_capture_enabled
                    ? "format=ISACWBS1,source=selected-world-reader,"
                        "start=complete-type-0x0002-sync,"
                        "stop=clean-probe-shutdown-or-safety-cap,"
                        "gate=first-complete-type-0x0012,"
                        "timing=per-span-relative-ms,"
                        "max-payload-bytes=16777216,max-records=65536,"
                        "metadata-records=32768,"
                        "normal-log-payloads=disabled"
                    : "format=ISACWBS1,source=selected-world-reader,"
                        "start=complete-type-0x0002-sync,"
                        "stop=first-complete-type-0x0012,"
                        "timing=per-span-relative-ms,"
                        "max-payload-bytes=2097152,max-records=8192,"
                        "normal-log-payloads=disabled"
            );
        }
        if (g_world_replay_enabled) {
            log_dispatch_status(
                "WORLD_REPLAY_READY",
                "source=loopback-timed-private-corpus,"
                "target=first-post-request-reader,"
                "retail-setup=retained-once,retail-world=isolated-after-arm,"
                "retail-outbound=transport-call-skipped-after-arm,"
                "initial-world-request=retained,"
                "injection=complete-frames,wait-ms=5000,"
                "payload-logging=disabled"
            );
        }
        log_dispatch_status(
            "SCHEMA_PROBE_READY",
            "boundary-rva=0xf8447e,max-events=4096,"
            "max-unique-targets=256,max-code-bytes=4096"
        );
        if (g_schema_field_probe_enabled) {
            snprintf(
                field_detail,
                sizeof(field_detail),
                "mode=rotating-hardware-breakpoints,helpers-per-message=3,"
                "schema-miner=%s,"
                "type-filter=%s,max-records=32768,max-samples=%u,"
                "field-bytes=32,callsite-rvas=enabled,resolved-thunks=enabled,"
                "helper-code-bytes=2048,nested-root=0xc47de0,"
                "nested-code-bytes=8192,nested-forward-bytes=2048",
                g_schema_miner_enabled ? "enabled" : "disabled",
                g_schema_field_type_filter >= 0 ? "enabled" : "all",
                g_schema_field_type_filter >= 0
                    ? ISAC_MAX_SCHEMA_FIELD_FILTERED_SAMPLES
                    : (
                        g_schema_miner_enabled
                            ? ISAC_MAX_SCHEMA_FIELD_MINER_SAMPLES_PER_TYPE
                            : ISAC_MAX_SCHEMA_FIELD_SAMPLES_PER_TYPE
                    )
            );
            log_dispatch_status(
                "SCHEMA_FIELD_PROBE_READY",
                field_detail
            );
            if (g_schema_field_type_filter >= 0) {
                snprintf(
                    field_detail,
                    sizeof(field_detail),
                    "type-id=0x%04lx",
                    (unsigned long)g_schema_field_type_filter
                );
                log_dispatch_status("SCHEMA_FIELD_FILTER", field_detail);
            }
            if (g_schema_miner_enabled) {
                log_dispatch_status(
                    "SCHEMA_MINER_READY",
                    "body-return-rva=0xf8448c,max-messages=8192,"
                    "max-body-bytes=2048,split-block-reassembly=one-boundary"
                );
            }
        }
    }
    InterlockedExchange(&g_dispatch_install_state, 2);
    snprintf(
        ready_detail,
        sizeof(ready_detail),
        "mode=hardware-execute-breakpoints,targets=%u,armed-threads=%u,"
        "unarmed-threads=%u,max-unique=256,schema-bodies=%s,"
        "type-values=static-code-only,event-timeline=%s,max-events=32768,"
        "message-code-bytes=32,"
        "inbound-code-bytes=256",
        g_plaintext_probe_enabled || g_transport_startup_probe_enabled
            ? 4u
            : 3u,
        armed_count,
        failed_count,
        g_schema_miner_enabled ? "enabled" : "disabled",
        g_dispatch_event_enabled ? "enabled" : "disabled"
    );
    log_dispatch_status("DISPATCH_PROBE_READY", ready_detail);
    resume_threads(suspended, suspended_count);
}

static BOOL same_stack(
    const isac_stack_signature *left,
    char direction,
    const uintptr_t *rvas,
    USHORT depth
) {
    return left->direction == direction &&
        left->depth == depth &&
        memcmp(left->rvas, rvas, depth * sizeof(*rvas)) == 0;
}

static void record_stack(char direction, SOCKET socket_handle) {
    PVOID frames[ISAC_CAPTURE_FRAMES];
    uintptr_t rvas[ISAC_MAX_FRAMES];
    USHORT captured;
    USHORT depth = 0;
    USHORT index;
    LONG stack_index;
    char line[768];
    size_t offset;

    if (
        local_bridge_owns_socket(socket_handle) ||
        !is_target_socket(socket_handle)
    ) {
        return;
    }
    record_bootstrap_socket_event(direction, socket_handle);
    ensure_dispatch_hooks();
    if (
        g_dispatch_install_state == 2 &&
        !arm_current_dispatch_thread() &&
        InterlockedCompareExchange(&g_dispatch_arm_error_logged, 1, 0) == 0
    ) {
        log_dispatch_status(
            "DISPATCH_PROBE_ERROR",
            "late-current-thread-breakpoints"
        );
    }
    captured = CaptureStackBackTrace(
        0,
        ISAC_CAPTURE_FRAMES,
        frames,
        NULL
    );
    for (index = 0; index < captured && depth < ISAC_MAX_FRAMES; ++index) {
        BYTE *frame = (BYTE *)frames[index];
        if (frame >= g_game_base && frame < g_game_base + g_game_size) {
            rvas[depth++] = (uintptr_t)(frame - g_game_base);
        }
    }
    if (depth == 0) {
        return;
    }
    capture_matching_code_targets(rvas, depth);
    if (InterlockedCompareExchange(&g_stack_lock, 1, 0) != 0) {
        return;
    }

    stack_index = g_stack_count;
    for (index = 0; index < (USHORT)stack_index; ++index) {
        if (same_stack(&g_stacks[index], direction, rvas, depth)) {
            InterlockedExchange(&g_stack_lock, 0);
            return;
        }
    }
    if (stack_index >= (LONG)ISAC_MAX_STACKS) {
        if (InterlockedCompareExchange(&g_limit_logged, 1, 0) == 0) {
            log_status("STACK_PROBE_LIMIT", "unique-stack-capacity-reached");
        }
        InterlockedExchange(&g_stack_lock, 0);
        return;
    }

    g_stacks[stack_index].direction = direction;
    g_stacks[stack_index].depth = depth;
    CopyMemory(
        g_stacks[stack_index].rvas,
        rvas,
        depth * sizeof(*rvas)
    );
    g_stack_count = stack_index + 1;

    offset = (size_t)snprintf(
        line,
        sizeof(line),
        "STACK tick_ms=%llu process=%lu thread=%lu direction=%s "
        "socket=0x%llx frame_count=%u rvas=",
        (unsigned long long)GetTickCount64(),
        (unsigned long)GetCurrentProcessId(),
        (unsigned long)GetCurrentThreadId(),
        direction == 'S' ? "send" : "recv",
        (unsigned long long)(uintptr_t)socket_handle,
        (unsigned int)depth
    );
    for (index = 0; index < depth && offset < sizeof(line); ++index) {
        int written = snprintf(
            line + offset,
            sizeof(line) - offset,
            "%s0x%llx",
            index == 0 ? "" : ",",
            (unsigned long long)rvas[index]
        );
        if (written <= 0 || (size_t)written >= sizeof(line) - offset) {
            offset = sizeof(line);
            break;
        }
        offset += (size_t)written;
    }
    if (offset + 2 < sizeof(line)) {
        line[offset++] = '\r';
        line[offset++] = '\n';
        line[offset] = '\0';
        append_stack_log(line);
    }
    InterlockedExchange(&g_stack_lock, 0);
}

static LONG next_transport_startup_event(void) {
    LONG sequence = InterlockedIncrement(&g_transport_startup_event_count);

    if (sequence <= ISAC_MAX_TRANSPORT_STARTUP_EVENTS) {
        return sequence;
    }
    if (
        InterlockedCompareExchange(
            &g_transport_startup_limit_logged,
            1,
            0
        ) == 0
    ) {
        log_status(
            "TRANSPORT_STARTUP_LIMIT",
            "event-capacity-reached,max-events=256"
        );
    }
    return 0;
}

static void arm_transport_startup_thread(void) {
    ensure_dispatch_hooks();
    if (
        g_dispatch_install_state == 2 &&
        !arm_current_dispatch_thread() &&
        InterlockedCompareExchange(&g_dispatch_arm_error_logged, 1, 0) == 0
    ) {
        log_dispatch_status(
            "TRANSPORT_STARTUP_PROBE_ERROR",
            "late-current-thread-breakpoints"
        );
    }
}

static void transport_game_callers(char output[128]) {
    PVOID frames[16];
    USHORT captured;
    USHORT index;
    unsigned int count = 0u;
    size_t offset = 0u;

    output[0] = '\0';
    captured = CaptureStackBackTrace(0u, 16u, frames, NULL);
    for (
        index = 0u;
        index < captured && count < ISAC_TRANSPORT_STACK_FRAMES;
        ++index
    ) {
        BYTE *frame = (BYTE *)frames[index];
        int written;

        if (frame < g_game_base || frame >= g_game_base + g_game_size) {
            continue;
        }
        written = snprintf(
            output + offset,
            128u - offset,
            "%s0x%llx",
            count == 0u ? "" : ",",
            (unsigned long long)(frame - g_game_base)
        );
        if (written <= 0 || (size_t)written >= 128u - offset) {
            break;
        }
        offset += (size_t)written;
        ++count;
    }
    if (count == 0u) {
        lstrcpyA(output, "none");
    }
}

static BOOL copy_bounded_ascii(
    const char *source,
    char destination[128]
) {
    unsigned int index;

    if (source == NULL) {
        destination[0] = '\0';
        return TRUE;
    }
    for (index = 0u; index + 1u < 128u; ++index) {
        unsigned char character;

        if (!readable_memory_window(source + index, 1u)) {
            return FALSE;
        }
        character = (unsigned char)source[index];
        if (character == 0u) {
            destination[index] = '\0';
            return TRUE;
        }
        if (character < 0x20u || character > 0x7eu) {
            return FALSE;
        }
        destination[index] = (char)character;
    }
    destination[127] = '\0';
    return FALSE;
}

static BOOL copy_bounded_wide_ascii(
    const WCHAR *source,
    char destination[128]
) {
    unsigned int index;

    if (source == NULL) {
        destination[0] = '\0';
        return TRUE;
    }
    for (index = 0u; index + 1u < 128u; ++index) {
        WCHAR character;

        if (!readable_memory_window(source + index, sizeof(*source))) {
            return FALSE;
        }
        character = source[index];
        if (character == L'\0') {
            destination[index] = '\0';
            return TRUE;
        }
        if (character < 0x20u || character > 0x7eu) {
            return FALSE;
        }
        destination[index] = (char)character;
    }
    destination[127] = '\0';
    return FALSE;
}

static const char *transport_host_class_from_ascii(const char *value) {
    char bounded[128];
    unsigned int index;
    BOOL numeric = TRUE;

    if (value == NULL) {
        return "null";
    }
    if (!copy_bounded_ascii(value, bounded)) {
        return "unreadable-or-long";
    }
    if (lstrcmpiA(bounded, "tctd-pc.ubisoft.com") == 0) {
        return "tctd-pc";
    }
    if (lstrcmpiA(bounded, "tctd-pc-echo.ubisoft.com") == 0) {
        return "tctd-pc-echo";
    }
    if (lstrcmpiA(bounded, "localhost") == 0) {
        return "localhost";
    }
    for (index = 0u; bounded[index] != '\0'; ++index) {
        char character = bounded[index];

        if (
            (character < '0' || character > '9') &&
            character != '.' && character != ':'
        ) {
            numeric = FALSE;
            break;
        }
    }
    return numeric && bounded[0] != '\0' ? "numeric" : "other";
}

static const char *transport_host_class_from_wide(const WCHAR *value) {
    char bounded[128];

    if (value == NULL) {
        return "null";
    }
    if (!copy_bounded_wide_ascii(value, bounded)) {
        return "unreadable-or-long";
    }
    return transport_host_class_from_ascii(bounded);
}

static const char *transport_service_class_from_ascii(const char *value) {
    char bounded[128];

    if (value == NULL) {
        return "null";
    }
    if (!copy_bounded_ascii(value, bounded)) {
        return "unreadable-or-long";
    }
    if (
        strcmp(bounded, "27015") == 0 ||
        strcmp(bounded, "51000") == 0 ||
        strcmp(bounded, "55000") == 0 ||
        strcmp(bounded, "55002") == 0
    ) {
        return bounded[0] == '2' ? "27015" :
            bounded[1] == '1' ? "51000" :
            bounded[4] == '2' ? "55002" : "55000";
    }
    return "other";
}

static const char *transport_service_class_from_wide(const WCHAR *value) {
    char bounded[128];

    if (value == NULL) {
        return "null";
    }
    if (!copy_bounded_wide_ascii(value, bounded)) {
        return "unreadable-or-long";
    }
    return transport_service_class_from_ascii(bounded);
}

static BOOL transport_redirect_tctd_pc_ascii(
    const char *node,
    const char *service
) {
    char bounded_node[128];
    char bounded_service[128];

    return
        copy_bounded_ascii(node, bounded_node) &&
        copy_bounded_ascii(service, bounded_service) &&
        ((g_tctd_pc_loopback_requested &&
          lstrcmpiA(bounded_node, "tctd-pc.ubisoft.com") == 0 &&
          strcmp(bounded_service, "27015") == 0) ||
         (g_tctd_echo_requested &&
          lstrcmpiA(bounded_node, "tctd-pc-echo.ubisoft.com") == 0 &&
          strcmp(bounded_service, "51000") == 0));
}

static BOOL transport_redirect_tctd_pc_wide(
    const WCHAR *node,
    const WCHAR *service
) {
    char bounded_node[128];
    char bounded_service[128];

    return
        copy_bounded_wide_ascii(node, bounded_node) &&
        copy_bounded_wide_ascii(service, bounded_service) &&
        transport_redirect_tctd_pc_ascii(bounded_node, bounded_service);
}

static const char *transport_address_scope(
    const struct sockaddr *address,
    int address_length,
    unsigned int *family,
    unsigned int *port
) {
    const unsigned char *port_bytes;

    *family = 0u;
    *port = 0u;
    if (
        address == NULL ||
        address_length < (int)sizeof(address->sa_family) ||
        !readable_memory_window(address, (SIZE_T)address_length)
    ) {
        return "unreadable";
    }
    *family = (unsigned int)address->sa_family;
    if (
        address->sa_family == AF_INET &&
        address_length >= (int)sizeof(struct sockaddr_in)
    ) {
        const struct sockaddr_in *ipv4 =
            (const struct sockaddr_in *)address;
        uint32_t host_address = ntohl(ipv4->sin_addr.s_addr);

        port_bytes = (const unsigned char *)&ipv4->sin_port;
        *port = ((unsigned int)port_bytes[0] << 8) | port_bytes[1];
        if ((host_address & 0xff000000u) == 0x7f000000u) {
            return "loopback";
        }
        if (
            (host_address & 0xff000000u) == 0x0a000000u ||
            (host_address & 0xfff00000u) == 0xac100000u ||
            (host_address & 0xffff0000u) == 0xc0a80000u
        ) {
            return "private";
        }
        if ((host_address & 0xffff0000u) == 0xa9fe0000u) {
            return "link-local";
        }
        return "remote";
    }
    if (
        address->sa_family == AF_INET6 &&
        address_length >= (int)sizeof(struct sockaddr_in6)
    ) {
        const struct sockaddr_in6 *ipv6 =
            (const struct sockaddr_in6 *)address;
        const unsigned char *bytes =
            (const unsigned char *)&ipv6->sin6_addr;
        unsigned int index;
        BOOL loopback = bytes[15] == 1u;

        port_bytes = (const unsigned char *)&ipv6->sin6_port;
        *port = ((unsigned int)port_bytes[0] << 8) | port_bytes[1];
        for (index = 0u; index < 15u; ++index) {
            if (bytes[index] != 0u) {
                loopback = FALSE;
                break;
            }
        }
        if (loopback) {
            return "loopback";
        }
        if ((bytes[0] & 0xfeu) == 0xfcu) {
            return "private";
        }
        if (bytes[0] == 0xfeu && (bytes[1] & 0xc0u) == 0x80u) {
            return "link-local";
        }
        return "remote";
    }
    return "other-family";
}

static int WSAAPI hook_transport_connect(
    SOCKET socket_handle,
    const struct sockaddr *address,
    int address_length
) {
    unsigned int family;
    unsigned int port;
    const char *scope;
    const char *role;
    char callers[128];
    char detail[320];
    LONG sequence;
    LONG attempt;
    int result;
    int error;

    arm_transport_startup_thread();
    scope = transport_address_scope(
        address,
        address_length,
        &family,
        &port
    );
    role = GetCurrentThreadId() == g_local_bridge_worker_thread_id
        ? "local-bridge"
        : "game-or-runtime";
    transport_game_callers(callers);
    attempt = InterlockedIncrement(&g_transport_connect_count);
    result = g_original_connect(socket_handle, address, address_length);
    error = result == SOCKET_ERROR ? WSAGetLastError() : 0;
    sequence = next_transport_startup_event();
    if (sequence != 0) {
        snprintf(
            detail,
            sizeof(detail),
            "sequence=%ld,attempt=%ld,api=connect,role=%s,family=%u,"
            "port=%u,scope=%s,result=%d,wsa_error=%d,caller_rvas=%s",
            sequence,
            attempt,
            role,
            family,
            port,
            scope,
            result,
            error,
            callers
        );
        log_status("TRANSPORT_CONNECT", detail);
    }
    if (result == SOCKET_ERROR) {
        WSASetLastError(error);
    }
    return result;
}

static INT WSAAPI hook_transport_getaddrinfo_a(
    PCSTR node,
    PCSTR service,
    const ADDRINFOA *hints,
    PADDRINFOA *result_addresses
) {
    const char *host_class;
    const char *service_class;
    char callers[128];
    char detail[320];
    LONG sequence;
    LONG attempt;
    INT result;
    int error;
    BOOL redirected;

    arm_transport_startup_thread();
    host_class = transport_host_class_from_ascii(node);
    service_class = transport_service_class_from_ascii(service);
    redirected = transport_redirect_tctd_pc_ascii(node, service);
    transport_game_callers(callers);
    attempt = InterlockedIncrement(&g_transport_resolve_count);
    result = g_original_getaddrinfo_a(
        redirected ? "127.0.0.1" : node,
        service,
        hints,
        result_addresses
    );
    error = WSAGetLastError();
    if (g_startup_leads_requested) {
        char bounded_node[128], bounded_service[128];
        capture_startup_resolver(attempt, "a",
            copy_bounded_ascii(node, bounded_node) ? bounded_node : NULL,
            copy_bounded_ascii(service, bounded_service) ? bounded_service : NULL,
            result, redirected);
    }
    sequence = next_transport_startup_event();
    if (sequence != 0) {
        snprintf(
            detail,
            sizeof(detail),
            "sequence=%ld,attempt=%ld,api=getaddrinfo-a,host_class=%s,"
            "service=%s,redirect=%s,result=%d,wsa_error=%d,caller_rvas=%s",
            sequence,
            attempt,
            host_class,
            service_class,
            redirected ? "loopback" : "none",
            result,
            error,
            callers
        );
        log_status("TRANSPORT_RESOLVE", detail);
    }
    WSASetLastError(error);
    return result;
}

static INT WSAAPI hook_transport_getaddrinfo_w(
    PCWSTR node,
    PCWSTR service,
    const ADDRINFOW *hints,
    PADDRINFOW *result_addresses
) {
    const char *host_class;
    const char *service_class;
    char callers[128];
    char detail[320];
    LONG sequence;
    LONG attempt;
    INT result;
    int error;
    BOOL redirected;

    arm_transport_startup_thread();
    host_class = transport_host_class_from_wide(node);
    service_class = transport_service_class_from_wide(service);
    redirected = transport_redirect_tctd_pc_wide(node, service);
    transport_game_callers(callers);
    attempt = InterlockedIncrement(&g_transport_resolve_count);
    result = g_original_getaddrinfo_w(
        redirected ? L"127.0.0.1" : node,
        service,
        hints,
        result_addresses
    );
    error = WSAGetLastError();
    if (g_startup_leads_requested) {
        char bounded_node[128], bounded_service[128];
        capture_startup_resolver(attempt, "w",
            copy_bounded_wide_ascii(node, bounded_node) ? bounded_node : NULL,
            copy_bounded_wide_ascii(service, bounded_service) ? bounded_service : NULL,
            result, redirected);
    }
    sequence = next_transport_startup_event();
    if (sequence != 0) {
        snprintf(
            detail,
            sizeof(detail),
            "sequence=%ld,attempt=%ld,api=getaddrinfo-w,host_class=%s,"
            "service=%s,redirect=%s,result=%d,wsa_error=%d,caller_rvas=%s",
            sequence,
            attempt,
            host_class,
            service_class,
            redirected ? "loopback" : "none",
            result,
            error,
            callers
        );
        log_status("TRANSPORT_RESOLVE", detail);
    }
    WSASetLastError(error);
    return result;
}

static int WINAPI hook_recv_base(
    SOCKET socket_handle,
    LPWSABUF buffers,
    DWORD buffer_count,
    LPDWORD received,
    LPDWORD flags,
    struct sockaddr *address,
    LPINT address_length,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion,
    LPWSABUF control
) {
    int result;
    int saved_error;

    record_stack('R', socket_handle);
    result = g_original_recv_base(
        socket_handle,
        buffers,
        buffer_count,
        received,
        flags,
        address,
        address_length,
        overlapped,
        completion,
        control
    );
    saved_error = WSAGetLastError();
    if (
        result == 0 &&
        received != NULL &&
        readable_memory_window(received, sizeof(*received))
    ) {
        inspect_tctd_certificate_receive(
            socket_handle,
            buffers,
            buffer_count,
            *received
        );
    }
    WSASetLastError(saved_error);
    return result;
}

static void record_world_replay_wire_send(
    SOCKET socket_handle,
    const WSABUF *buffers,
    DWORD buffer_count
) {
    ULONGLONG total_length = 0u;
    DWORD index;
    LONG sequence;
    char detail[160];

    if (
        !g_world_replay_enabled ||
        InterlockedCompareExchange(&g_world_replay_armed, 0, 0) != 1 ||
        local_bridge_owns_socket(socket_handle) ||
        !is_target_socket(socket_handle)
    ) {
        return;
    }
    if (
        buffers == NULL ||
        buffer_count == 0u ||
        buffer_count > 64u ||
        !readable_memory_window(
            buffers,
            (SIZE_T)buffer_count * sizeof(*buffers)
        )
    ) {
        total_length = (ULONGLONG)-1;
    } else {
        for (index = 0u; index < buffer_count; ++index) {
            total_length += buffers[index].len;
        }
    }
    sequence = InterlockedIncrement(&g_world_replay_wire_send_count);
    if (sequence <= 16 || sequence % 1024 == 0) {
        snprintf(
            detail,
            sizeof(detail),
            "sequence=%ld,socket_id=%ld,buffer_count=%lu,total_length=%s%llu,"
            "role=post-arm-wire-audit",
            sequence,
            target_socket_id(socket_handle),
            (unsigned long)buffer_count,
            total_length == (ULONGLONG)-1 ? "unknown-" : "",
            (unsigned long long)(
                total_length == (ULONGLONG)-1 ? 0u : total_length
            )
        );
        log_dispatch_status("WORLD_REPLAY_RETAIL_WIRE_SEND", detail);
    }
}

static int WINAPI hook_send_base(
    SOCKET socket_handle,
    LPWSABUF buffers,
    DWORD buffer_count,
    LPDWORD sent,
    DWORD flags,
    const struct sockaddr *address,
    INT address_length,
    LPWSAOVERLAPPED overlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion
) {
    record_stack('S', socket_handle);
    record_world_replay_wire_send(socket_handle, buffers, buffer_count);
    return g_original_send_base(
        socket_handle,
        buffers,
        buffer_count,
        sent,
        flags,
        address,
        address_length,
        overlapped,
        completion
    );
}


void isac_stack_probe_initialize(
    const WCHAR *log_path,
    const WCHAR *code_log_path,
    const WCHAR *dispatch_log_path,
    const WCHAR *plaintext_log_path
) {
    union {
        FARPROC generic;
        isac_getpeername_fn getpeername_function;
    } peer_name;
    union {
        FARPROC generic;
        isac_connect_fn function;
    } connect_entry;
    union {
        FARPROC generic;
        isac_getaddrinfo_a_fn function;
    } getaddrinfo_a_entry;
    union {
        FARPROC generic;
        isac_getaddrinfo_w_fn function;
    } getaddrinfo_w_entry;
    HMODULE ws2_module;
    BYTE *recv_target;
    BYTE *send_target;
    BYTE *connect_target = NULL;
    BYTE *getaddrinfo_a_target = NULL;
    BYTE *getaddrinfo_w_target = NULL;
    SIZE_T connect_hook_size = 0u;
    SIZE_T getaddrinfo_a_hook_size = 0u;
    SIZE_T getaddrinfo_w_hook_size = 0u;
    HANDLE suspended[ISAC_MAX_SUSPENDED_THREADS];
    const isac_inline_hook *winsock_hooks[5] = {
        &g_recv_hook,
        &g_send_hook,
        &g_connect_hook,
        &g_getaddrinfo_a_hook,
        &g_getaddrinfo_w_hook
    };
    size_t winsock_hook_count;
    size_t suspended_count;
    BOOL suspended_complete;

    if (!stack_probe_requested()) {
        return;
    }
    g_local_bridge_requested = local_bridge_requested();
    g_local_bridge_injection_requested =
        local_bridge_injection_requested();
    g_local_bridge_type3_isolation_requested =
        local_bridge_type3_isolation_requested();
    g_type3_profile_capture_requested =
        type3_profile_capture_requested();
    g_world_bootstrap_probe_requested =
        world_bootstrap_probe_requested();
    g_world_snapshot_capture_requested =
        world_snapshot_capture_requested();
    g_world_continuation_capture_requested =
        world_continuation_capture_requested();
    g_world_replay_requested = world_replay_requested();
    g_transport_startup_probe_requested =
        transport_startup_probe_requested();
    g_tctd_pc_loopback_requested = tctd_pc_loopback_requested();
    {
        char echo_mode[8];
        g_tctd_echo_requested = GetEnvironmentVariableA(
            "ISAC_TCTD_ECHO_LOCAL", echo_mode, sizeof(echo_mode)
        ) == 1 && echo_mode[0] == '1';
        g_startup_leads_requested = GetEnvironmentVariableA(
            "ISAC_STARTUP_LEADS", echo_mode, sizeof(echo_mode)
        ) == 1 && echo_mode[0] == '1';
        g_login_handoff_requested = GetEnvironmentVariableA(
            "ISAC_LOGIN_HANDOFF", echo_mode, sizeof(echo_mode)
        ) == 1 && echo_mode[0] == '1';
        g_login_handoff_sweep_requested = GetEnvironmentVariableA(
            "ISAC_LOGIN_HANDOFF_SWEEP", echo_mode, sizeof(echo_mode)
        ) == 1 && echo_mode[0] == '1';
    }
    g_tctd_validation_probe_requested =
        tctd_validation_probe_requested();
    g_tctd_validation_remote_requested =
        tctd_validation_remote_requested();
    g_tctd_local_accept_requested =
        tctd_local_accept_requested();
    {
        char allocation_mode[8];
        g_tctd_allocation_requested = GetEnvironmentVariableA(
            "ISAC_TCTD_ALLOCATION_CAPTURE", allocation_mode, sizeof(allocation_mode)
        ) == 1 && allocation_mode[0] == '1';
    }
    g_tctd_validator_code_requested =
        tctd_validator_code_requested();
    g_tctd_state_watch_requested =
        tctd_state_watch_requested();
    g_tctd_owner_watch_requested =
        tctd_owner_watch_requested();
    g_tctd_owner_remote_requested =
        tctd_owner_remote_requested();
    g_tctd_completion_probe_requested =
        tctd_completion_probe_requested();
    g_tctd_completion_remote_requested =
        tctd_completion_remote_requested();
    g_tctd_branch_probe_requested =
        tctd_branch_probe_requested();
    g_tctd_branch_remote_requested =
        tctd_branch_remote_requested();
    g_tctd_chain_probe_requested =
        tctd_chain_probe_requested();
    g_tctd_chain_remote_requested =
        tctd_chain_remote_requested();
    g_tctd_parser_code_requested =
        tctd_parser_code_requested();
    g_tctd_cert_flow_requested =
        tctd_cert_flow_requested();
    g_tctd_cert_flow_remote_requested =
        tctd_cert_flow_remote_requested();
    g_tctd_text_dump_requested = tctd_text_dump_requested();
    g_tctd_certificate_probe_requested =
        tctd_certificate_probe_requested() ||
        g_tctd_validation_probe_requested ||
        g_tctd_completion_probe_requested ||
        g_tctd_branch_probe_requested ||
        g_tctd_chain_probe_requested ||
        g_tctd_parser_code_requested ||
        g_tctd_cert_flow_requested;
    g_bootstrap_type3_probe_requested =
        bootstrap_type3_probe_requested();
    g_control_probe_requested =
        control_probe_requested() || g_bootstrap_type3_probe_requested;
    g_outbound_control_probe_requested =
        outbound_control_probe_requested();
    g_inbound_source_probe_requested = inbound_source_probe_requested();
    g_bootstrap_redacted_only =
        (
            g_outbound_control_probe_requested ||
            g_inbound_source_probe_requested ||
            g_local_bridge_requested ||
            g_transport_startup_probe_requested
        ) &&
        !bootstrap_probe_requested() &&
        !g_control_probe_requested &&
        !plaintext_probe_requested();
    g_bootstrap_probe_requested =
        bootstrap_probe_requested() ||
        g_control_probe_requested ||
        g_outbound_control_probe_requested ||
        g_inbound_source_probe_requested ||
        g_local_bridge_requested ||
        g_transport_startup_probe_requested;
    if (lstrlenW(log_path) + 1 > MAX_PATH) {
        return;
    }
    lstrcpyW(g_stack_log_path, log_path);
    if (!get_image_range(GetModuleHandleW(NULL), &g_game_base, &g_game_size)) {
        log_status("STACK_PROBE_ERROR", "game-image-range");
        return;
    }
    {
        char sdk_mode[8];
        if (GetEnvironmentVariableA("ISAC_SDK_LOCAL", sdk_mode, sizeof(sdk_mode)) == 1 && sdk_mode[0] == '1') {
            ISAC_SDK_DIAGNOSTIC result;
            char trace_mode[8];
            BOOL protect_trace = GetEnvironmentVariableA("ISAC_SDK_PROTECT_TRACE", trace_mode,
                sizeof(trace_mode)) == 1 && trace_mode[0] == '1';
            if (!verified_game_file_diagnostic(&result) ||
                !isac_sdk_patch_template(g_game_base, g_game_size, ISAC_SDK_TEMPLATE_RVA, &result,
                    protect_trace ? observe_sdk_protection : NULL)) {
                char detail[384];
                snprintf(detail, sizeof(detail),
                    "stage=%s,win32_error=%lu,state=0x%lx,protect=0x%lx,"
                    "memory_type=0x%lx,allocation_protect=0x%lx,write_protect=0x%lx,"
                    "expected=0x%llx,observed=0x%llx,mismatch_offset=%d,"
                    "all_zero=%d,already_local=%d,modified=%d,terminating=1",
                    result.stage, (unsigned long)result.win32_error,
                    (unsigned long)result.state, (unsigned long)result.protection,
                    (unsigned long)result.memory_type,
                    (unsigned long)result.allocation_protection,
                    (unsigned long)result.write_protection,
                    result.expected, result.observed, result.mismatch_offset,
                    (int)result.all_zero, (int)result.already_local, (int)result.modified);
                log_status("SDK_LOCAL_ROUTE_ERROR", detail);
                if (protect_trace) {
                    log_status("SDK_PROTECT_HOLD", "delay_ms=2000,diagnostic-only=1,termination-still-required=1");
                    Sleep(2000); /* Allow the independent /proc mapping observer to sample this process. */
                }
                TerminateProcess(GetCurrentProcess(), 0x4953u);
                return;
            }
            {
                char detail[192];
                snprintf(detail, sizeof(detail),
                    "rva=0x3471510,port=55003,template-only=1,memory_type=0x%lx,"
                    "original_protect=0x%lx,write_protect=0x%lx,protection-restored=1",
                    (unsigned long)result.memory_type,
                    (unsigned long)result.protection,
                    (unsigned long)result.write_protection);
                log_status("SDK_LOCAL_ROUTE_READY", detail);
            }
        }
    }
    if (code_probe_requested()) {
        if (lstrlenW(code_log_path) + 1 <= MAX_PATH) {
            lstrcpyW(g_code_log_path, code_log_path);
        }
        if (
            g_code_log_path[0] != L'\0' &&
            verified_game_file()
        ) {
            g_code_probe_enabled = TRUE;
            log_code_status(
                "CODE_PROBE_READY",
                "windows=14,max-window=512,max-bytes=6144,payloads=disabled"
            );
        } else if (g_code_log_path[0] != L'\0') {
            log_code_status(
                "CODE_PROBE_SKIPPED",
                "unsupported-main-image"
            );
        }
    }
    if (
        dispatch_probe_requested() ||
        g_local_bridge_requested ||
        g_local_bridge_injection_requested ||
        g_local_bridge_type3_isolation_requested ||
        g_type3_profile_capture_requested ||
        g_world_bootstrap_probe_requested ||
        g_world_snapshot_capture_requested ||
        g_world_continuation_capture_requested ||
        g_world_replay_requested ||
        g_transport_startup_probe_requested
    ) {
        if (lstrlenW(dispatch_log_path) + 1 <= MAX_PATH) {
            lstrcpyW(g_dispatch_log_path, dispatch_log_path);
        }
        if (lstrlenW(plaintext_log_path) + 1 <= MAX_PATH) {
            lstrcpyW(g_plaintext_log_path, plaintext_log_path);
        }
        if (g_local_bridge_requested) {
            load_local_bridge_port();
        }
        if (
            g_tctd_certificate_probe_requested &&
            (
                !g_transport_startup_probe_requested ||
                (
                    !g_tctd_pc_loopback_requested &&
                    !g_tctd_validation_remote_requested &&
                    !g_tctd_completion_remote_requested &&
                    !g_tctd_branch_remote_requested &&
                    !g_tctd_chain_remote_requested &&
                    !g_tctd_cert_flow_remote_requested
                )
            )
        ) {
            log_dispatch_status(
                "TCTD_CERT_PROBE_ERROR",
                "requires-transport-startup-and-port-27015-scope"
            );
            g_tctd_certificate_probe_requested = FALSE;
            g_tctd_validation_probe_requested = FALSE;
            g_tctd_completion_probe_requested = FALSE;
            g_tctd_branch_probe_requested = FALSE;
            g_tctd_chain_probe_requested = FALSE;
            g_tctd_parser_code_requested = FALSE;
            g_tctd_cert_flow_requested = FALSE;
        }
        if (
            g_tctd_validation_probe_requested &&
            !g_code_probe_enabled
        ) {
            log_dispatch_status(
                "TCTD_VALIDATION_PROBE_ERROR",
                "requires-code-probe-and-supported-main-image"
            );
            g_tctd_validation_probe_requested = FALSE;
        }
        if (
            g_tctd_completion_probe_requested &&
            !g_code_probe_enabled
        ) {
            log_dispatch_status(
                "TCTD_COMPLETION_PROBE_ERROR",
                "requires-code-probe-and-supported-main-image"
            );
            g_tctd_completion_probe_requested = FALSE;
        }
        if (g_tctd_branch_probe_requested && !g_code_probe_enabled) {
            log_dispatch_status(
                "TCTD_BRANCH_PROBE_ERROR",
                "requires-code-probe-and-supported-main-image"
            );
            g_tctd_branch_probe_requested = FALSE;
        }
        if (g_tctd_chain_probe_requested && !g_code_probe_enabled) {
            log_dispatch_status(
                "TCTD_CHAIN_PROBE_ERROR",
                "requires-code-probe-and-supported-main-image"
            );
            g_tctd_chain_probe_requested = FALSE;
        }
        if (g_tctd_parser_code_requested && !g_code_probe_enabled) {
            log_dispatch_status(
                "TCTD_PARSER_CODE_ERROR",
                "requires-code-probe-and-supported-main-image"
            );
            g_tctd_parser_code_requested = FALSE;
        }
        if (g_tctd_cert_flow_requested && !g_code_probe_enabled) {
            log_dispatch_status(
                "TCTD_CERT_FLOW_ERROR",
                "requires-code-probe-and-supported-main-image"
            );
            g_tctd_cert_flow_requested = FALSE;
        }
        if (
            g_tctd_local_accept_requested &&
            (
                !g_transport_startup_probe_requested ||
                !g_tctd_pc_loopback_requested
            )
        ) {
            log_dispatch_status(
                "TCTD_LOCAL_ACCEPT_ERROR",
                "requires-transport-startup-and-tctd-loopback"
            );
            g_tctd_local_accept_requested = FALSE;
        }
        if (
            g_tctd_validator_code_requested &&
            (
                !g_transport_startup_probe_requested ||
                !g_tctd_pc_loopback_requested ||
                !g_code_probe_enabled
            )
        ) {
            log_dispatch_status(
                "TCTD_VALIDATOR_CODE_ERROR",
                "requires-code-probe-transport-startup-tctd-loopback-"
                "and-supported-main-image"
            );
            g_tctd_validator_code_requested = FALSE;
        }
        if (
            g_tctd_state_watch_requested &&
            (
                !g_transport_startup_probe_requested ||
                !g_tctd_pc_loopback_requested ||
                !g_code_probe_enabled
            )
        ) {
            log_dispatch_status(
                "TCTD_STATE_WATCH_ERROR",
                "requires-code-probe-transport-startup-tctd-loopback-"
                "and-supported-main-image"
            );
            g_tctd_state_watch_requested = FALSE;
        }
        if (
            g_tctd_owner_watch_requested &&
            (
                !g_transport_startup_probe_requested ||
                (
                    !g_tctd_pc_loopback_requested &&
                    !g_tctd_owner_remote_requested
                ) ||
                !g_code_probe_enabled
            )
        ) {
            log_dispatch_status(
                "TCTD_OWNER_WATCH_ERROR",
                "requires-code-probe-transport-startup-port-27015-scope-"
                "and-supported-main-image"
            );
            g_tctd_owner_watch_requested = FALSE;
        }
        if (
            g_transport_startup_probe_requested &&
            (
                g_local_bridge_injection_requested ||
                g_local_bridge_type3_isolation_requested ||
                g_world_bootstrap_probe_requested ||
                g_world_snapshot_capture_requested ||
                g_world_continuation_capture_requested ||
                g_world_replay_requested
            )
        ) {
            log_dispatch_status(
                "TRANSPORT_STARTUP_CONFIG_NOTICE",
                "diagnostic-mode-disables-injection-isolation-and-world-replay"
            );
            g_local_bridge_injection_requested = FALSE;
            g_local_bridge_type3_isolation_requested = FALSE;
            g_world_bootstrap_probe_requested = FALSE;
            g_world_snapshot_capture_requested = FALSE;
            g_world_continuation_capture_requested = FALSE;
            g_world_replay_requested = FALSE;
        }
        if (
            g_local_bridge_injection_requested &&
            (
                !g_local_bridge_requested ||
                g_bootstrap_type3_probe_requested
            )
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                !g_local_bridge_requested
                    ? "injection-requires-local-backend-bridge"
                    : "injection-conflicts-with-bootstrap-type3-probe"
            );
            g_local_bridge_injection_requested = FALSE;
        }
        if (
            g_local_bridge_type3_isolation_requested &&
            !g_local_bridge_injection_requested
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                "type3-isolation-requires-local-backend-inject"
            );
            g_local_bridge_type3_isolation_requested = FALSE;
        }
        if (
            g_type3_profile_capture_requested &&
            (
                !g_local_bridge_requested ||
                g_local_bridge_injection_requested ||
                g_bootstrap_type3_probe_requested
            )
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                !g_local_bridge_requested
                    ? "type3-capture-requires-local-backend-bridge"
                    : "type3-capture-requires-observe-only-bridge"
            );
            g_type3_profile_capture_requested = FALSE;
        }
        if (
            g_world_bootstrap_probe_requested &&
            (
                !g_local_bridge_requested ||
                !g_local_bridge_injection_requested
            )
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                "world-bootstrap-probe-requires-local-bridge-and-injection"
            );
            g_world_bootstrap_probe_requested = FALSE;
        }
        if (
            g_world_snapshot_capture_requested &&
            !g_world_bootstrap_probe_requested
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                "world-bootstrap-capture-requires-world-bootstrap-probe"
            );
            g_world_snapshot_capture_requested = FALSE;
        }
        if (
            g_world_continuation_capture_requested &&
            !g_world_snapshot_capture_requested
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                "world-continuation-capture-requires-world-capture"
            );
            g_world_continuation_capture_requested = FALSE;
        }
        if (
            g_world_replay_requested &&
            (
                !g_world_bootstrap_probe_requested ||
                g_world_snapshot_capture_requested
            )
        ) {
            log_dispatch_status(
                "LOCAL_BRIDGE_CONFIG_ERROR",
                !g_world_bootstrap_probe_requested
                    ? "world-replay-requires-world-bootstrap-probe"
                    : "world-replay-conflicts-with-world-capture"
            );
            g_world_replay_requested = FALSE;
        }
        if (
            g_dispatch_log_path[0] != L'\0' &&
            verified_game_file()
        ) {
            g_dispatch_probe_enabled = TRUE;
            g_dispatch_event_requested = dispatch_event_probe_requested();
            if (
                (
                    plaintext_probe_requested() ||
                    g_bootstrap_probe_requested
                ) &&
                g_plaintext_log_path[0] != L'\0'
            ) {
                g_plaintext_probe_requested = TRUE;
                g_schema_field_probe_requested =
                    schema_field_probe_requested();
                g_schema_miner_requested = schema_miner_requested();
                if (g_schema_miner_requested) {
                    g_schema_field_probe_requested = TRUE;
                    g_schema_field_type_filter = -1;
                } else if (g_schema_field_probe_requested) {
                    load_schema_field_type_filter();
                }
                log_plaintext_status(
                    "PLAINTEXT_PROBE_ARMED",
                    g_bootstrap_probe_requested
                        ? g_bootstrap_redacted_only
                            ? "immediate-install,bootstrap-metadata,"
                                "payloads=disabled"
                            : "immediate-install,"
                                "bootstrap-metadata-before-world,"
                                "world-gated-gameplay-payloads"
                        : "lazy-install,world-gated,outbound-only"
                );
                if (g_bootstrap_probe_requested) {
                    log_plaintext_status(
                        "BOOTSTRAP_PROBE_ARMED",
                        g_bootstrap_redacted_only
                            ? "payloads=redacted-all-phases,max-records=2048,"
                                "max-socket-events=4096,"
                                "max-inspect-bytes=16384"
                            : "payloads=redacted-before-world,"
                                "max-records=2048,max-socket-events=4096,"
                                "max-inspect-bytes=16384"
                    );
                }
                if (g_control_probe_requested) {
                    log_dispatch_status(
                        "CONTROL_PROBE_ARMED",
                        g_bootstrap_type3_probe_requested
                            ? "target-types=0x0003,payloads=disabled,"
                                "caller-unwind=enabled"
                            : "target-types=0x0002,0x0006,payloads=disabled,"
                        "caller-unwind=enabled"
                    );
                }
                if (g_bootstrap_type3_probe_requested) {
                    log_dispatch_status(
                        "BOOTSTRAP_TYPE3_PROBE_ARMED",
                        "target-type=0x0003,dr0=virtual-read-helper,"
                        "helper-rva=0x9a7c0,"
                        "rearm-after-login-request=12x25ms,"
                        "payloads=disabled,caller-unwind=enabled"
                    );
                }
                if (g_outbound_control_probe_requested) {
                    log_dispatch_status(
                        "OUTBOUND_CONTROL_PROBE_ARMED",
                        "target-types=0x0002,0x0005,payloads=disabled,"
                        "caller-unwind=enabled,redacted-only=enabled"
                    );
                }
                if (g_inbound_source_probe_requested) {
                    log_dispatch_status(
                        "INBOUND_SOURCE_PROBE_ARMED",
                        "max-reader-vtables=8,reader-vtable-slots=16,"
                        "max-vtable-xrefs=32,"
                        "transport-delivery-rva=0x84bd0,"
                        "source-append-rva=0x223d140,"
                        "injection-helper-rvas=0xb7e0/0x1e0a0/0xc6c0,"
                        "reader-advance-rva=0x9a851,vtable-offset=0x38,"
                        "per-thread=enabled,max-delivery-events=128,"
                        "max-delivery-chunks=32,"
                        "payloads=disabled,redacted-only=enabled"
                    );
                }
                if (g_local_bridge_requested) {
                    log_dispatch_status(
                        "LOCAL_BRIDGE_REQUESTED",
                        g_local_bridge_injection_requested
                            ? g_local_bridge_type3_isolation_requested
                                ? "loopback-only=yes,"
                                    "mode=type-0x0003-inject-once,"
                                    "reader=verified-id-1,"
                                    "retail-type3="
                                    "blocked-readers-1-through-2"
                                : "loopback-only=yes,"
                                    "mode=type-0x0003-inject-once,"
                                    "reader=verified-id-1,"
                                    "retail-path=enabled"
                            : g_type3_profile_capture_requested
                            ? "loopback-only=yes,"
                                "mode=receive-observe-only,"
                                "private-type3-capture=reader-1-once,"
                                "retail-path=enabled"
                            : "loopback-only=yes,mode=receive-observe-only,"
                                "injection=disabled"
                    );
                }
                if (g_transport_startup_probe_requested) {
                    log_dispatch_status(
                        "TRANSPORT_STARTUP_PROBE_ARMED",
                        "network=connect/getaddrinfo-a/getaddrinfo-w,"
                        "internal=reader-setup-a/reader-setup-b/"
                        "reader-registration/outbound-writer,"
                        "payloads=disabled,endpoints=classified-not-recorded"
                    );
                    if (g_tctd_pc_loopback_requested) {
                        log_dispatch_status(
                            "TCTD_PC_LOOPBACK_ARMED",
                            g_tctd_echo_requested
                            ? "hosts=tctd-pc:27015,tctd-pc-echo:51000,target=loopback,other-resolutions=unchanged"
                            :
                            "host=tctd-pc,service=27015,target=loopback,"
                            "all-other-resolutions=unchanged"
                        );
                    }
                    if (g_tctd_certificate_probe_requested) {
                        log_dispatch_status(
                            "TCTD_CERT_PROBE_ARMED",
                            (
                                g_tctd_validation_remote_requested ||
                                g_tctd_completion_remote_requested ||
                                g_tctd_branch_remote_requested ||
                                g_tctd_chain_remote_requested ||
                                g_tctd_cert_flow_remote_requested
                            )
                                ? "source=remote-port-27015-recv,"
                                    "selector=ec-p256-spki,"
                                    "hardware-read-watch=enabled,"
                                    "max-events=64,payloads=disabled"
                                : "source=loopback-port-27015-recv,"
                                    "selector=ec-p256-spki,"
                                    "hardware-read-watch=enabled,"
                                    "max-events=64,payloads=disabled"
                        );
                    }
                    if (g_tctd_validation_probe_requested) {
                        log_dispatch_status(
                            "TCTD_VALIDATION_PROBE_ARMED",
                            g_tctd_validation_remote_requested
                                ? "trigger=remote-port-27015-ec-p256-spki,"
                                    "arm=first-in-game-read-to-shared-return,"
                                    "code-windows=8,slot=dr0,"
                                    "return-checkpoints=5,max-events=128,"
                                    "payloads=disabled"
                                : "trigger=loopback-port-27015-ec-p256-spki,"
                                    "code-windows=8,slot=dr0,"
                                    "return-checkpoints=5,max-events=128,"
                                    "payloads=disabled"
                        );
                    }
                    if (g_tctd_local_accept_requested) {
                        log_dispatch_status(
                            "TCTD_LOCAL_ACCEPT_ARMED",
                            "trigger=loopback-port-27015-ec-p256-spki,"
                            "target-rva=0x206573b,"
                            "gate=certificate-verifier-return,"
                            "rearm=per-certificate,max-attempts=256,payloads=disabled"
                        );
                    }
                    if (g_tctd_validator_code_requested) {
                        log_dispatch_status(
                            "TCTD_VALIDATOR_CODE_ARMED",
                            "trigger=loopback-port-27015-ec-p256-spki,"
                            "range=runtime-function-containing-0xf12b1,"
                            "max-windows=8,mutation=disabled"
                        );
                    }
                    if (g_tctd_state_watch_requested) {
                        log_dispatch_status(
                            "TCTD_STATE_WATCH_ARMED",
                            "trigger=loopback-port-27015-ec-p256-spki,"
                            "decision-rva=0xbb4cd,then=one-byte-write-watch,"
                            "max-events=64,mutation=disabled"
                        );
                    }
                    if (g_tctd_owner_watch_requested) {
                        log_dispatch_status(
                            "TCTD_OWNER_WATCH_ARMED",
                            g_tctd_owner_remote_requested
                                ? "trigger=remote-port-27015-ec-p256-spki,"
                                    "decision-rva=0xbb4cd,decision-slot=dr0,"
                                    "owner-field-slot=dr1,state-slot=dr2,"
                                    "max-decisions=1024,max-writes=128,"
                                    "mutation=disabled"
                                : "trigger=loopback-port-27015-ec-p256-spki,"
                                    "decision-rva=0xbb4cd,decision-slot=dr0,"
                                    "owner-field-slot=dr1,state-slot=dr2,"
                                    "max-decisions=1024,max-writes=128,"
                                    "mutation=disabled"
                        );
                    }
                    if (g_tctd_completion_probe_requested) {
                        log_dispatch_status(
                            "TCTD_COMPLETION_PROBE_ARMED",
                            g_tctd_completion_remote_requested
                                ? "trigger=remote-port-27015-ec-p256-spki,"
                                    "entry=0xf0e60/dr0,setter-resume=0xf12b4/dr1,"
                                    "return=0xf1324/dr2,code-region=0xf0e60-"
                                    "0xf1337,mutation=disabled,"
                                    "payloads=disabled"
                                : "trigger=loopback-port-27015-ec-p256-spki,"
                                    "entry=0xf0e60/dr0,setter-resume=0xf12b4/dr1,"
                                    "return=0xf1324/dr2,code-region=0xf0e60-"
                                    "0xf1337,mutation=disabled,"
                                    "payloads=disabled"
                        );
                    }
                    if (g_tctd_branch_probe_requested) {
                        log_dispatch_status(
                            "TCTD_BRANCH_PROBE_ARMED",
                            g_tctd_branch_remote_requested
                                ? "trigger=remote-port-27015-ec-p256-spki,"
                                    "ready=0xf11af/dr0,status-ready=0xf11d0/dr1,"
                                    "tls-status=0xf11d8/dr2,final=0xf1251/dr3,"
                                    "max-events=256,mutation=disabled,"
                                    "payloads=disabled"
                                : "trigger=loopback-port-27015-ec-p256-spki,"
                                    "ready=0xf11af/dr0,status-ready=0xf11d0/dr1,"
                                    "tls-status=0xf11d8/dr2,final=0xf1251/dr3,"
                                    "max-events=256,mutation=disabled,"
                                    "payloads=disabled"
                        );
                    }
                    if (g_tctd_chain_probe_requested) {
                        log_dispatch_status(
                            "TCTD_CHAIN_PROBE_ARMED",
                            g_tctd_chain_remote_requested
                                ? "trigger=remote-port-27015-ec-p256-spki,"
                                    "key-copy=0x21fea19,slot=dr0,"
                                    "return-checkpoints=6,code-windows=6,"
                                    "mutation=disabled,payloads=disabled"
                                : "trigger=loopback-port-27015-ec-p256-spki,"
                                    "key-copy=0x21fea19,slot=dr0,"
                                    "return-checkpoints=6,code-windows=6,"
                                    "mutation=disabled,payloads=disabled"
                        );
                    }
                    if (g_tctd_parser_code_requested) {
                        log_dispatch_status(
                            "TCTD_PARSER_CODE_ARMED",
                            "trigger=loopback-port-27015-ec-p256-spki,"
                            "call-rva=0x20167d8,dynamic-vtable-slot=0x10,"
                            "max-windows=12,mutation=disabled,"
                            "payloads=disabled"
                        );
                    }
                    if (g_tctd_cert_flow_requested) {
                        log_dispatch_status(
                            "TCTD_CERT_FLOW_ARMED",
                            g_tctd_cert_flow_remote_requested
                                ? "trigger=remote-port-27015-ec-p256-spki,"
                                    "watch=copy-following-data,max-events=256,"
                                    "max-consumer-code-windows=12,"
                                    "mutation=disabled,payloads=disabled"
                                : "trigger=loopback-port-27015-ec-p256-spki,"
                                    "watch=copy-following-data,max-events=256,"
                                    "max-consumer-code-windows=12,"
                                    "mutation=disabled,payloads=disabled"
                        );
                    }
                }
            }
            log_dispatch_status(
                "DISPATCH_PROBE_ARMED",
                g_bootstrap_probe_requested
                    ? "immediate-install,bootstrap-metadata,"
                        "payloads=disabled-before-world"
                    : "lazy-install-after-port-55000,payloads=disabled"
            );
        } else if (g_dispatch_log_path[0] != L'\0') {
            log_dispatch_status(
                "DISPATCH_PROBE_SKIPPED",
                "unsupported-main-image"
            );
            if (
                (
                    plaintext_probe_requested() ||
                    g_bootstrap_probe_requested
                ) &&
                g_plaintext_log_path[0] != L'\0'
            ) {
                log_plaintext_status(
                    "PLAINTEXT_PROBE_SKIPPED",
                    "unsupported-main-image"
                );
            }
        }
    }

    ws2_module = GetModuleHandleW(L"ws2_32.dll");
    if (ws2_module == NULL) {
        log_status("STACK_PROBE_ERROR", "ws2-not-loaded");
        return;
    }
    peer_name.generic = GetProcAddress(ws2_module, "getpeername");
    g_getpeername = peer_name.getpeername_function;
    recv_target = find_internal_target(ws2_module, "WSARecv");
    send_target = find_internal_target(ws2_module, "WSASend");
    if (g_transport_startup_probe_requested) {
        connect_entry.generic = GetProcAddress(ws2_module, "connect");
        getaddrinfo_a_entry.generic = GetProcAddress(ws2_module, "getaddrinfo");
        getaddrinfo_w_entry.generic = GetProcAddress(
            ws2_module,
            "GetAddrInfoW"
        );
        connect_target = (BYTE *)connect_entry.generic;
        getaddrinfo_a_target = (BYTE *)getaddrinfo_a_entry.generic;
        getaddrinfo_w_target = (BYTE *)getaddrinfo_w_entry.generic;
        if (
            connect_target != NULL &&
            readable_code_window(
                connect_target,
                sizeof(g_wine_connect_signature)
            ) &&
            memcmp(
                connect_target,
                g_wine_connect_signature,
                sizeof(g_wine_connect_signature)
            ) == 0
        ) {
            connect_hook_size = sizeof(g_wine_connect_signature);
        } else if (
            connect_target != NULL &&
            readable_code_window(
                connect_target,
                sizeof(g_wine11_connect_signature)
            ) &&
            memcmp(
                connect_target,
                g_wine11_connect_signature,
                sizeof(g_wine11_connect_signature)
            ) == 0
        ) {
            connect_hook_size = sizeof(g_wine11_connect_signature);
        }
        if (
            getaddrinfo_a_target != NULL &&
            readable_code_window(
                getaddrinfo_a_target,
                sizeof(g_wine_getaddrinfo_signature)
            ) &&
            memcmp(
                getaddrinfo_a_target,
                g_wine_getaddrinfo_signature,
                sizeof(g_wine_getaddrinfo_signature)
            ) == 0
        ) {
            getaddrinfo_a_hook_size = sizeof(g_wine_getaddrinfo_signature);
        } else if (
            getaddrinfo_a_target != NULL &&
            readable_code_window(
                getaddrinfo_a_target,
                sizeof(g_wine11_getaddrinfo_a_signature)
            ) &&
            memcmp(
                getaddrinfo_a_target,
                g_wine11_getaddrinfo_a_signature,
                sizeof(g_wine11_getaddrinfo_a_signature)
            ) == 0
        ) {
            getaddrinfo_a_hook_size =
                sizeof(g_wine11_getaddrinfo_a_signature);
        }
        if (
            getaddrinfo_w_target != NULL &&
            readable_code_window(
                getaddrinfo_w_target,
                sizeof(g_wine_getaddrinfo_signature)
            ) &&
            memcmp(
                getaddrinfo_w_target,
                g_wine_getaddrinfo_signature,
                sizeof(g_wine_getaddrinfo_signature)
            ) == 0
        ) {
            getaddrinfo_w_hook_size = sizeof(g_wine_getaddrinfo_signature);
        } else if (
            getaddrinfo_w_target != NULL &&
            readable_code_window(
                getaddrinfo_w_target,
                sizeof(g_wine11_connect_signature)
            ) &&
            memcmp(
                getaddrinfo_w_target,
                g_wine11_connect_signature,
                sizeof(g_wine11_connect_signature)
            ) == 0
        ) {
            getaddrinfo_w_hook_size = sizeof(g_wine11_connect_signature);
        }
    }
    if (
        g_getpeername == NULL ||
        recv_target == NULL ||
        send_target == NULL ||
        recv_target == send_target
    ) {
        log_status("STACK_PROBE_ERROR", "winsock-signature-not-found");
        return;
    }
    if (
        g_transport_startup_probe_requested &&
        (
            connect_hook_size == 0u ||
            getaddrinfo_a_hook_size == 0u ||
            getaddrinfo_w_hook_size == 0u
        )
    ) {
        log_status(
            "TRANSPORT_STARTUP_PROBE_ERROR",
            "unsupported-winsock-connect-or-resolver-signature"
        );
        return;
    }
    if (
        !prepare_hook(&g_recv_hook, recv_target, ISAC_HOOK_SIZE) ||
        !prepare_hook(&g_send_hook, send_target, ISAC_HOOK_SIZE) ||
        (
            g_transport_startup_probe_requested &&
            (
                !prepare_hook(
                    &g_connect_hook,
                    connect_target,
                    connect_hook_size
                ) ||
                !prepare_hook(
                    &g_getaddrinfo_a_hook,
                    getaddrinfo_a_target,
                    getaddrinfo_a_hook_size
                ) ||
                !prepare_hook(
                    &g_getaddrinfo_w_hook,
                    getaddrinfo_w_target,
                    getaddrinfo_w_hook_size
                )
            )
        )
    ) {
        log_status("STACK_PROBE_ERROR", "trampoline-setup");
        isac_stack_probe_shutdown();
        return;
    }
    g_original_recv_base = (isac_recv_base_fn)g_recv_hook.trampoline;
    g_original_send_base = (isac_send_base_fn)g_send_hook.trampoline;
    if (g_transport_startup_probe_requested) {
        g_original_connect = (isac_connect_fn)g_connect_hook.trampoline;
        g_original_getaddrinfo_a =
            (isac_getaddrinfo_a_fn)g_getaddrinfo_a_hook.trampoline;
        g_original_getaddrinfo_w =
            (isac_getaddrinfo_w_fn)g_getaddrinfo_w_hook.trampoline;
    }
    winsock_hook_count = g_transport_startup_probe_requested ? 5u : 2u;

    suspended_count = suspend_other_threads(suspended, &suspended_complete);
    if (!suspended_complete) {
        resume_threads(suspended, suspended_count);
        log_status("STACK_PROBE_ERROR", "thread-suspension");
        isac_stack_probe_shutdown();
        return;
    }
    redirect_suspended_threads(
        suspended,
        suspended_count,
        winsock_hooks,
        winsock_hook_count,
        TRUE
    );
    if (
        !patch_hook(&g_recv_hook, (const void *)hook_recv_base, NULL) ||
        !patch_hook(&g_send_hook, (const void *)hook_send_base, NULL) ||
        (
            g_transport_startup_probe_requested &&
            (
                !patch_hook(
                    &g_connect_hook,
                    (const void *)hook_transport_connect,
                    NULL
                ) ||
                !patch_hook(
                    &g_getaddrinfo_a_hook,
                    (const void *)hook_transport_getaddrinfo_a,
                    NULL
                ) ||
                !patch_hook(
                    &g_getaddrinfo_w_hook,
                    (const void *)hook_transport_getaddrinfo_w,
                    NULL
                )
            )
        )
    ) {
        unpatch_hook(&g_recv_hook);
        unpatch_hook(&g_send_hook);
        unpatch_hook(&g_connect_hook);
        unpatch_hook(&g_getaddrinfo_a_hook);
        unpatch_hook(&g_getaddrinfo_w_hook);
        redirect_suspended_threads(
            suspended,
            suspended_count,
            winsock_hooks,
            winsock_hook_count,
            FALSE
        );
        resume_threads(suspended, suspended_count);
        log_status("STACK_PROBE_ERROR", "target-patch");
        isac_stack_probe_shutdown();
        return;
    }
    resume_threads(suspended, suspended_count);
    if (g_bootstrap_probe_requested && g_dispatch_probe_enabled) {
        ensure_dispatch_hooks();
    }
    if (g_local_bridge_enabled && g_dispatch_install_state == 2) {
        start_local_bridge();
    }
    if (g_tctd_certificate_probe_enabled) {
        log_status(
            "TCTD_CERT_PROBE_READY",
            (
                g_tctd_validation_remote_requested ||
                g_tctd_completion_remote_requested ||
                g_tctd_branch_remote_requested ||
                g_tctd_chain_remote_requested ||
                g_tctd_cert_flow_remote_requested
            )
                ? "source=remote-port-27015-recv,selector=ec-p256-spki,"
                    "max-read-events=64,payloads=disabled"
                : "source=loopback-port-27015-recv,"
                    "selector=ec-p256-spki,max-read-events=64,"
                    "payloads=disabled"
        );
    }
    if (g_tctd_validation_probe_enabled) {
        log_status(
            "TCTD_VALIDATION_PROBE_READY",
            g_tctd_validation_remote_requested
                ? "trigger=remote-port-27015-ec-p256-spki,"
                    "arm=first-in-game-read-to-shared-return,"
                    "code-windows=8,slot=dr0,"
                    "mode=data-then-staged-execute,"
                    "return-checkpoints=5,max-events=128,"
                    "register-scalars=enabled,payloads=disabled"
                : "trigger=loopback-port-27015-ec-p256-spki,"
                    "code-windows=8,slot=dr0,"
                    "mode=data-then-staged-execute,"
                    "return-checkpoints=5,max-events=128,"
                    "register-scalars=enabled,payloads=disabled"
        );
    }
    if (g_tctd_local_accept_enabled) {
        log_status(
            "TCTD_LOCAL_ACCEPT_READY",
            "trigger=loopback-port-27015-ec-p256-spki,"
            "target-rva=0x206573b,gate=certificate-verifier-return,"
            "rearm=per-certificate,max-attempts=256,payloads=disabled"
        );
    }
    if (g_tctd_validator_code_enabled) {
        log_status(
            "TCTD_VALIDATOR_CODE_READY",
            "trigger=loopback-port-27015-ec-p256-spki,"
            "range=runtime-function-containing-0xf12b1,"
            "max-windows=8,max-window=512,mutation=disabled"
        );
    }
    if (g_tctd_state_watch_enabled) {
        log_status(
            "TCTD_STATE_WATCH_READY",
            "trigger=loopback-port-27015-ec-p256-spki,"
            "decision-rva=0xbb4cd,then=one-byte-write-watch,"
            "max-events=64,mutation=disabled"
        );
    }
    if (g_tctd_owner_watch_enabled) {
        log_status(
            "TCTD_OWNER_WATCH_READY",
            g_tctd_owner_remote_requested
                ? "trigger=remote-port-27015-ec-p256-spki,"
                    "decision-rva=0xbb4cd,decision-slot=dr0,"
                    "owner-field-slot=dr1,state-slot=dr2,"
                    "max-decisions=1024,max-writes=128,mutation=disabled"
                : "trigger=loopback-port-27015-ec-p256-spki,"
                    "decision-rva=0xbb4cd,decision-slot=dr0,"
                    "owner-field-slot=dr1,state-slot=dr2,"
                    "max-decisions=1024,max-writes=128,mutation=disabled"
        );
    }
    if (g_tctd_completion_probe_enabled) {
        log_status(
            "TCTD_COMPLETION_PROBE_READY",
            g_tctd_completion_remote_requested
                ? "trigger=remote-port-27015-ec-p256-spki,"
                    "entry=0xf0e60/dr0,setter-resume=0xf12b4/dr1,"
                    "return=0xf1324/dr2,code-region=0xf0e60-0xf1337,"
                    "max-events=64,mutation=disabled,payloads=disabled"
                : "trigger=loopback-port-27015-ec-p256-spki,"
                    "entry=0xf0e60/dr0,setter-resume=0xf12b4/dr1,"
                    "return=0xf1324/dr2,code-region=0xf0e60-0xf1337,"
                    "max-events=64,mutation=disabled,payloads=disabled"
        );
    }
    if (g_tctd_branch_probe_enabled) {
        log_status(
            "TCTD_BRANCH_PROBE_READY",
            g_tctd_branch_remote_requested
                ? "trigger=remote-port-27015-ec-p256-spki,"
                    "ready=0xf11af/dr0,status-ready=0xf11d0/dr1,"
                    "tls-status=0xf11d8/dr2,final=0xf1251/dr3,"
                    "max-events=256,mutation=disabled,payloads=disabled"
                : "trigger=loopback-port-27015-ec-p256-spki,"
                    "ready=0xf11af/dr0,status-ready=0xf11d0/dr1,"
                    "tls-status=0xf11d8/dr2,final=0xf1251/dr3,"
                    "max-events=256,mutation=disabled,payloads=disabled"
        );
    }
    if (g_tctd_chain_probe_enabled) {
        log_status(
            "TCTD_CHAIN_PROBE_READY",
            g_tctd_chain_remote_requested
                ? "trigger=remote-port-27015-ec-p256-spki,"
                    "key-copy=0x21fea19,slot=dr0,mode=data-then-staged-execute,"
                    "return-checkpoints=6,code-windows=6,max-events=32,"
                    "register-scalars=enabled,mutation=disabled,"
                    "payloads=disabled"
                : "trigger=loopback-port-27015-ec-p256-spki,"
                    "key-copy=0x21fea19,slot=dr0,mode=data-then-staged-execute,"
                    "return-checkpoints=6,code-windows=6,max-events=32,"
                    "register-scalars=enabled,mutation=disabled,"
                    "payloads=disabled"
        );
    }
    if (g_tctd_parser_code_enabled) {
        log_status(
            "TCTD_PARSER_CODE_READY",
            "trigger=loopback-port-27015-ec-p256-spki,"
            "call-rva=0x20167d8,dynamic-vtable-slot=0x10,"
            "max-windows=12,mutation=disabled,payloads=disabled"
        );
    }
    if (g_tctd_cert_flow_enabled) {
        log_status(
            "TCTD_CERT_FLOW_READY",
            g_tctd_cert_flow_remote_requested
                ? "trigger=remote-port-27015-ec-p256-spki,"
                    "watch=copy-following-data,max-events=256,"
                    "max-consumer-code-windows=12,mutation=disabled,"
                    "payloads=disabled"
                : "trigger=loopback-port-27015-ec-p256-spki,"
                    "watch=copy-following-data,max-events=256,"
                    "max-consumer-code-windows=12,mutation=disabled,"
                    "payloads=disabled"
        );
    }
    log_status(
        "STACK_PROBE_READY",
        g_transport_startup_probe_requested
            ? g_tctd_pc_loopback_requested
                ? g_tctd_certificate_probe_requested
                    ? "port=55000,max_unique=256,transport-startup=enabled,"
                        "payloads=disabled,endpoints=classified,"
                        "tctd-pc-loopback=enabled,tctd-cert-probe=enabled"
                    : "port=55000,max_unique=256,transport-startup=enabled,"
                        "payloads=disabled,endpoints=classified,"
                        "tctd-pc-loopback=enabled,tctd-cert-probe=disabled"
                : "port=55000,max_unique=256,transport-startup=enabled,"
                    "payloads=disabled,endpoints=classified,"
                    "tctd-pc-loopback=disabled"
            : "port=55000,max_unique=256,payloads=disabled"
    );
}

void isac_stack_probe_shutdown(void) {
    HANDLE suspended[ISAC_MAX_SUSPENDED_THREADS];
    const isac_inline_hook *winsock_hooks[5] = {
        &g_recv_hook,
        &g_send_hook,
        &g_connect_hook,
        &g_getaddrinfo_a_hook,
        &g_getaddrinfo_w_hook
    };
    size_t suspended_count = 0;
    size_t index;
    BOOL suspended_complete = FALSE;
    BOOL dispatch_breakpoints_cleared = TRUE;

    world_snapshot_shutdown();
    stop_local_bridge();

    if (
        g_recv_hook.installed ||
        g_send_hook.installed ||
        g_connect_hook.installed ||
        g_getaddrinfo_a_hook.installed ||
        g_getaddrinfo_w_hook.installed ||
        g_dispatch_exception_handler != NULL
    ) {
        suspended_count = suspend_other_threads(
            suspended,
            &suspended_complete
        );
        if (suspended_complete) {
            redirect_suspended_threads(
                suspended,
                suspended_count,
                winsock_hooks,
                5,
                FALSE
            );
            unpatch_hook(&g_recv_hook);
            unpatch_hook(&g_send_hook);
            unpatch_hook(&g_connect_hook);
            unpatch_hook(&g_getaddrinfo_a_hook);
            unpatch_hook(&g_getaddrinfo_w_hook);
            if (g_dispatch_exception_handler != NULL) {
                for (index = 0; index < suspended_count; ++index) {
                    if (!set_dispatch_breakpoints(suspended[index], FALSE)) {
                        dispatch_breakpoints_cleared = FALSE;
                    }
                }
                if (!set_dispatch_breakpoints(GetCurrentThread(), FALSE)) {
                    dispatch_breakpoints_cleared = FALSE;
                }
            }
        } else {
            log_status("STACK_PROBE_ERROR", "shutdown-thread-suspension");
            dispatch_breakpoints_cleared = FALSE;
        }
        resume_threads(suspended, suspended_count);
    }
    if (
        g_dispatch_exception_handler != NULL &&
        dispatch_breakpoints_cleared
    ) {
        RemoveVectoredExceptionHandler(g_dispatch_exception_handler);
        g_dispatch_exception_handler = NULL;
    }
    release_hook_storage(&g_recv_hook);
    release_hook_storage(&g_send_hook);
    release_hook_storage(&g_connect_hook);
    release_hook_storage(&g_getaddrinfo_a_hook);
    release_hook_storage(&g_getaddrinfo_w_hook);
    if (
        g_recv_hook.installed ||
        g_send_hook.installed ||
        g_connect_hook.installed ||
        g_getaddrinfo_a_hook.installed ||
        g_getaddrinfo_w_hook.installed ||
        g_dispatch_exception_handler != NULL
    ) {
        return;
    }
    g_original_recv_base = NULL;
    if (handoff_fault_file != INVALID_HANDLE_VALUE) {
        CloseHandle(handoff_fault_file);
        handoff_fault_file = INVALID_HANDLE_VALUE;
    }
    g_original_send_base = NULL;
    g_original_connect = NULL;
    g_original_getaddrinfo_a = NULL;
    g_original_getaddrinfo_w = NULL;
    g_dispatch_event_enabled = FALSE;
    if (g_dispatch_event_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dispatch_event_file);
        g_dispatch_event_file = INVALID_HANDLE_VALUE;
    }
}
