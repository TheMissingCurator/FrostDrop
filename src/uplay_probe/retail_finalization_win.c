/* Profile create/list plus a credential-filtered world submit marker. */
#define ISAC_RETAIL_PROFILE 1
#define ISAC_RETAIL_FINALIZATION 1
#define T5Result ProfileResult
#define T5State ProfileState
#define T5Regs ProfileRegs
#define T5_SITE_COUNT PROFILE_SITE_COUNT
#define t5_reset profile_reset
#define t5_handle profile_handle
#include "retail_type5_win.c"
