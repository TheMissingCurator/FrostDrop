#include <assert.h>
#include <stdint.h>
#include <string.h>
static unsigned char tutorial_arena[131072];
static void tutorial_fixture_u(unsigned offset,uint64_t value,unsigned n) { memcpy(tutorial_arena+offset,&value,n); }
static void tutorial_fixture_data(void) {
 unsigned char *b=tutorial_arena+0x8000; unsigned i;
 memset(tutorial_arena,0,sizeof(tutorial_arena));
 tutorial_fixture_u(0x1000+0x68,(uintptr_t)(tutorial_arena+0x2000),8);
 tutorial_fixture_u(0x2000,0x34863d8,8);
 tutorial_fixture_u(0x2800,(uintptr_t)(tutorial_arena+0x3000),8);
 tutorial_fixture_u(0x3000+0xc,19,4);
 tutorial_arena[0x3010]=0x24; tutorial_arena[0x3011]=2;
 for(i=0;i<16;++i) tutorial_arena[0x3012+i]=(unsigned char)(i+1);
 tutorial_fixture_u(0x5000+0x4090,(uintptr_t)b,8);
 tutorial_fixture_u(0x5000+0x4098,519,4);
 b[0]=3; b[1]=0; b[2]=0x83; b[3]=4; b[4]=0x82; b[5]=8; b[6]=0;
 memset(b+7,0xa5,512); /* Synthetic bearer; must never be persisted. */
 memcpy(tutorial_arena+0xa000,tutorial_arena+0x3012,17);
 tutorial_fixture_u(0xa800+0x10,2,2);
 tutorial_fixture_u(0xb000+4,0,4);
 memset(tutorial_arena+0xb008,0x5a,16);
 tutorial_fixture_u(0xb800+0x10,6,2);
}
static void tutorial_fixture_gameplay(void) {
 unsigned char b[]={3,0,3,4,3,42};
 memcpy(tutorial_arena+0x8000,b,sizeof(b)); tutorial_fixture_u(0x5000+0x4098,sizeof(b),4);
}
