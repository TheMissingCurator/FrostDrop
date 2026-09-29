/* Reuse the proven retail-only VEH/thread lifecycle. */
#define ISAC_RETAIL_HANDSHAKE 1
#define T5Result HandshakeResult
#define T5State HandshakeState
#define T5Regs HandshakeRegs
#define T5_SITE_COUNT HANDSHAKE_SITE_COUNT
#define t5_reset handshake_reset
#define t5_handle(s,k,r,b,read,emit) handshake_handle(s,k,r,b,read,emit,handshake_now())
#include "retail_type5_win.c"
