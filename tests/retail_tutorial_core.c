#include "../src/uplay_probe/retail_tutorial.h"
#include "retail_tutorial_fixture.h"
#include <stdio.h>
static TutorialSession session;
static TutorialState state;
static TutorialResult events[32];
static unsigned count;
static int fixture_read(uintptr_t p,void *out,size_t n) {
 uintptr_t begin=(uintptr_t)tutorial_arena;
 if(p<begin || p+n<p || p+n>begin+sizeof(tutorial_arena)) return 0;
 memcpy(out,(const void *)p,n); return 1;
}
static void fixture_emit(const TutorialResult *r) { assert(count<32); events[count++]=*r; }
static void reset(void) { tutorial_fixture_data(); memset(&session,0,sizeof(session)); tutorial_reset(&state); count=0; }
static void call(unsigned kind,unsigned first,unsigned second) {
 TutorialRegs r={0}; r.rcx=r.rdi=(uintptr_t)(tutorial_arena+first); r.rdx=r.rbx=(uintptr_t)(tutorial_arena+second); r.rax=1;
 tutorial_handle(&session,&state,(int)kind,&r,0,fixture_read,fixture_emit);
}
int main(void) {
 unsigned prev=0;
 assert(tutorial_key_edges(&prev,2047,1)==2047); assert(tutorial_key_edges(&prev,2047,1)==0);
 assert(tutorial_key_edges(&prev,0,1)==0); assert(tutorial_key_edges(&prev,8,1)==8);
 assert(tutorial_key_edges(&prev,0,0)==0); assert(tutorial_key_edges(&prev,1,0)==0);
 assert(tutorial_key_edges(&prev,1,1)==0); assert(tutorial_key_edges(&prev,0,1)==0);
 assert(tutorial_key_edges(&prev,1,1)==1);
 reset(); call(1,0x4000,0x5000); assert(count==1 && events[0].kind==5 && !events[0].length);
 assert(session.waiting && !session.selected);
 call(0,0x1000,0x2800); assert(count==2 && events[1].kind==1 && events[1].length==19 && events[1].aux==1);
 call(2,0xa000,0xa800); assert(events[2].kind==3 && events[2].length==17);
 call(3,0xb000,0xb800); assert(events[3].kind==4 && events[3].length==16);
 tutorial_fixture_gameplay(); call(1,0x4000,0x5000); assert(count==5 && events[4].kind==2);
 /* Pre-world readers remain excluded. */
 reset(); call(0,0x1000,0x2800); call(1,0x4000,0x5000); call(0,0x1000,0x2800); assert(count==1 && !session.selected);
 /* Fragmented five-byte setup followed by fragmented 19-byte sync. */
 reset(); call(1,0x4000,0x5000);
 memmove(tutorial_arena+0x3015,tutorial_arena+0x3010,19); memset(tutorial_arena+0x3010,0x7f,5);
 tutorial_fixture_u(0x300c,7,4); call(0,0x1000,0x2800); assert(count==1);
 memmove(tutorial_arena+0x3010,tutorial_arena+0x3017,17); tutorial_fixture_u(0x300c,17,4);
 call(0,0x1000,0x2800); assert(count==2 && events[1].length==19 && events[1].bytes[0]==0x24 && events[1].bytes[1]==2);
 /* Sensitive type-2 outbound after selection is not saved. */
 tutorial_fixture_gameplay(); tutorial_arena[0x8004]=2; call(1,0x4000,0x5000);
 assert(count==2 && session.filtered==1); assert(!state.result.bytes[0]);
 /* Selected source replacement stops, rather than mixing streams. */
 tutorial_fixture_u(0x1000+0x68,(uintptr_t)(tutorial_arena+0x2100),8);
 tutorial_fixture_u(0x2100,0x34863d8,8); call(0,0x1000,0x2800); assert(session.failed && events[2].kind==6);
 /* Large chained spans are split without losing bytes. */
 reset(); call(1,0x4000,0x5000); call(0,0x1000,0x2800);
 tutorial_fixture_u(0x2800,(uintptr_t)(tutorial_arena+0x10000),8);
 tutorial_fixture_u(0x1000c,20000,4); memset(tutorial_arena+0x10010,0x33,20000);
 tutorial_fixture_u(0x103f8,0,8); call(0,0x1000,0x2800);
 assert(!session.failed && count==4 && events[2].length==16384 && events[3].length==3616);
 /* Unreadable, oversized and cycles are errors after selection. */
 tutorial_fixture_u(0x1000c,1048577,4); call(0,0x1000,0x2800); assert(session.failed);
 puts("tutorial core: selection, fragmentation, filtering, markers, bounds passed"); return 0;
}
