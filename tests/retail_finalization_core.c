#include <assert.h>
#include <stdio.h>
#include <string.h>
#define ISAC_RETAIL_FINALIZATION 1
#include "../src/uplay_probe/retail_profile.h"

static unsigned char arena[32768];
static ProfileState state;
static ProfileResult saved;
static unsigned emitted;

static int read_fixture(uintptr_t p,void *out,size_t n) {
 uintptr_t first=(uintptr_t)arena,last=first+sizeof(arena);
 if(p<first || p>last || n>last-p) return 0;
 memcpy(out,(void *)p,n); return 1;
}
static void collect(const ProfileResult *r) { saved=*r; ++emitted; }
static void capture(const unsigned char *envelope,unsigned n) {
 ProfileRegs regs={0};
 memset(arena,0,sizeof(arena)); memcpy(arena+0x2000,envelope,n);
 regs.rdx=(uintptr_t)arena;
 { uintptr_t pointer=(uintptr_t)(arena+0x2000); memcpy(arena+0x4090,&pointer,8); }
 memcpy(arena+0x4098,&n,4);
 profile_handle(&state,3,&regs,0,read_fixture,collect);
}
int main(void) {
 unsigned char good[154]={3,0,0x96,1,0xa8,2,0x0c};
 unsigned i;
 for(i=0;i<16;++i) good[7+i]=(unsigned char)(i+1);
 profile_reset(&state);
 capture(good,sizeof(good));
 assert(emitted==1 && saved.kind==3 && saved.complete && saved.length==16);
 for(i=0;i<16;++i) assert(saved.bytes[i]==(unsigned char)(i+1));
 for(i=16;i<sizeof(good);++i) assert(!state.result.bytes[i]);
 good[6]=0; capture(good,sizeof(good)); assert(emitted==1); good[6]=0x0c;
 good[1]=1; capture(good,sizeof(good)); assert(emitted==1); good[1]=0;
 good[3]=0x97; capture(good,sizeof(good)); assert(emitted==1);
 puts("finalization core: filtered character-only marker passed");
 return 0;
}
