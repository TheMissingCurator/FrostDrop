#include <assert.h>
#include <stdio.h>
#include "../src/uplay_probe/retail_profile.h"
#include "retail_profile_fixture.h"
static ProfileState state;
static ProfileResult result;
static unsigned emitted;
static int read_fixture(uintptr_t p,void *out,size_t size) {
 uintptr_t begin=(uintptr_t)arena,end=begin+sizeof(arena);
 if(p<begin || p>end || size>end-p) return 0;
 memcpy(out,(void *)p,size); return 1;
}
static void save(const ProfileResult *r) { result=*r; ++emitted; }
static void run(int kind,unsigned offset) {
 ProfileRegs r={0};
 r.rcx=r.rdi=(uintptr_t)(arena+offset); r.rbx=(uintptr_t)(arena+0x3000);
 fixture_u(0x3010,kind==1?6:kind==2?2:8,2);
 profile_handle(&state,kind,&r,0,read_fixture,save);
}
int main(void) {
 unsigned char expected[]={0x81,1,0,1};
 fixture_profile_data(); profile_reset(&state);
 run(0,0); assert(result.complete && result.length==4 && !memcmp(result.bytes,expected,4));
 run(1,0x100); assert(result.complete && result.length==19 && result.bytes[2]==0 && result.bytes[3]==0x31);
 run(2,0x200); assert(result.complete && result.count==1 && result.length>60);
 run(3,0x1000); assert(result.complete && result.length<64);
 fixture_u(0x218,9,4); run(2,0x200); assert(!result.complete);
 fixture_u(0x218,1,4); fixture_u(0x8f0,10001,4); run(2,0x200); assert(!result.complete);
 fixture_u(0x8f0,3,4); fixture_u(0x220,1,8); run(2,0x200); assert(!result.complete);
 fixture_profile_data(); fixture_u(0x680,0,8); run(2,0x200); assert(!result.complete);
 run(0,0x3fff); assert(!result.complete);
 assert(emitted==9);
 puts("profile core: bounded typed fields and failures passed"); return 0;
}
