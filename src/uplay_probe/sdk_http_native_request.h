#ifndef ISAC_SDK_HTTP_NATIVE_REQUEST_H
#define ISAC_SDK_HTTP_NATIVE_REQUEST_H

#include "sdk_http_adapter.h"
#include <stdint.h>

/* Verified-build request-side ABI only. No automatic address resolver,
 * installation, HTTP sender, failed-result factory or service destructor.
 * These helpers are not linked into the live probe. Caller supplies independently
 * verified, live function/vtable addresses; they are capabilities, not discoveries.
 * No constructor fault/exception recovery is implemented: native allocation and
 * C++ unwinding must be audited before this can be enabled in the retail process.
 */
#if defined(__GNUC__) && defined(__x86_64__)
#define ISAC_SDK_CALL __attribute__((ms_abi))
#elif defined(_MSC_VER) && defined(_M_X64)
#define ISAC_SDK_CALL
#else
#error SDK request ABI requires an x86-64 compiler with Windows ABI support
#endif

typedef union { uint64_t align; unsigned char bytes[0x58]; } isac_sdk_string;
typedef union { uint64_t align; unsigned char bytes[0x2c8]; } isac_sdk_url;

typedef struct {
    void *(ISAC_SDK_CALL *destroy)(void *request, unsigned int flags);
    unsigned int (ISAC_SDK_CALL *method)(const void *request);
    void *(ISAC_SDK_CALL *clone)(const void *request);
} isac_sdk_request_vtable;

typedef struct {
    uintptr_t address;
    unsigned int method_id; /* Verified IDs: GET=0, POST=1, DELETE=4. */
    isac_sdk_request_vtable entries;
} isac_sdk_request_class;

typedef struct {
    void *(ISAC_SDK_CALL *string_from_utf8)(isac_sdk_string *, const char *);
    void (ISAC_SDK_CALL *string_destroy)(isac_sdk_string *);
    void *(ISAC_SDK_CALL *url_parse)(isac_sdk_url *, const isac_sdk_string *);
    void *(ISAC_SDK_CALL *url_assign)(isac_sdk_url *, const isac_sdk_url *);
    isac_sdk_string *(ISAC_SDK_CALL *url_format)(const isac_sdk_url *, isac_sdk_string *);
    void (ISAC_SDK_CALL *url_destroy)(isac_sdk_url *);
    /* Must fail on unreadable ranges, without faulting or partial-success.
     * Does not make concurrent destruction safe: caller owns/pins all inputs. */
    int (*read)(void *context, uintptr_t address, void *output, size_t length);
    void *read_context;
    isac_sdk_request_class classes[3];
} isac_sdk_request_api;

/* Output is unchanged on failure. Reads only bounded narrow string storage
 * through read(); uses the observed vbtable displacement and SSO convention.
 * This is not a generic MSVC string-layout implementation. */
int isac_sdk_string_copy_utf8(const isac_sdk_request_api *api,
    const isac_sdk_string *string, char *output, size_t capacity, size_t *length);

/* These can be used by the corresponding adapter callbacks after the remaining
 * bindings are verified. Unknown vtable addresses, changed entries or mismatched
 * method IDs are rejected before invoking unapproved virtual targets.
 * Normal-return paths destroy every SDK temporary they construct. */
int isac_sdk_request_describe(const isac_sdk_request_api *api, const void *request,
    char *scratch, size_t capacity, isac_http_request_view *view);
void *isac_sdk_request_clone(const isac_sdk_request_api *api, const void *request);
int isac_sdk_request_destroy(const isac_sdk_request_api *api, void *owned_request);
/* owned_request must be an independent clone, never a borrowed live request.
 * Rejects nonlocal/unsupported input, parses and round-trips into fresh SDK
 * values, then invokes native URL assignment. No memcpy of owning objects. */
int isac_sdk_request_replace_url(const isac_sdk_request_api *api,
    void *owned_request, const char *url, size_t length);

#endif
