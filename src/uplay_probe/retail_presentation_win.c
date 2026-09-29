/* Retail presentation observer: same read-only tutorial stream lifecycle. */
#define ISAC_RETAIL_PRESENTATION 1
#define ISAC_RETAIL_TUTORIAL 1
#define T5Result TutorialResult
#define T5State TutorialState
#define T5Regs TutorialRegs
#define T5_SITE_COUNT 4
#define t5_reset tutorial_reset
#define t5_handle(s,k,r,b,read,emit) tutorial_observe(s,k,r,b,read,emit)
#include "retail_type5_win.c"
