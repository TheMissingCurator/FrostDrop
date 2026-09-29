#define ISAC_RETAIL_PRESENTATION 1
#include "../src/uplay_probe/retail_tutorial.h"
#include <assert.h>
#include <stdio.h>

static TutorialResult observed[2];
static unsigned count;
static int read_local(uintptr_t address,void *out,size_t size) {
 if(!address) return 0;
 memcpy(out,(const void *)address,size);
 return 1;
}
static void collect(const TutorialResult *result) {
 if(count<2) observed[count]=*result;
 ++count;
}
int main(void) {
 TutorialSession session={0}; TutorialState state; TutorialRegs regs={0};
 uintptr_t base=0x100000, caller=base+0x1234;
 tutorial_reset(&state);
 regs.rsp=(uintptr_t)&caller;
 tutorial_handle(&session,&state,2,&regs,base,read_local,collect);
 assert(count==0);
 session.selected=1;
 tutorial_handle(&session,&state,2,&regs,base,read_local,collect);
 tutorial_handle(&session,&state,3,&regs,base,read_local,collect);
 assert(count==2 && observed[0].kind==7 && observed[1].kind==8);
 assert(observed[0].aux==0x1234 && observed[1].aux==0x1234);
 assert(observed[0].length==0 && observed[1].length==0);
 assert(tutorial_key_edges(&(unsigned){0},1,1)==1);
 puts("presentation node events remain payload-free and stream-gated");
 return 0;
}
