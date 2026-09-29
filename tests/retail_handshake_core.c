#include <assert.h>
#include <stdio.h>
#include "../src/uplay_probe/retail_handshake.h"
#include "retail_handshake_fixture.h"
static HandshakeState state;
static HandshakeResult results[20];
static unsigned emitted;
static int read_fixture(uintptr_t p,void *out,size_t size) {
 uintptr_t begin=(uintptr_t)arena,end=begin+sizeof(arena);
 if(p<begin || p>end || size>end-p) return 0;
 memcpy(out,(void *)p,size); return 1;
}
static void save(const HandshakeResult *r) { assert(emitted<20); results[emitted++]=*r; }
static void run(int kind,unsigned offset,int valid) {
 HandshakeRegs r={0};
 r.rcx=r.rdi=(uintptr_t)(arena+offset); r.rbx=(uintptr_t)(arena+0x6000); r.rax=valid;
 fixture_u(0x6010,kind==0?3:kind==1?6:2,2);
 handshake_handle(&state,kind,&r,0,read_fixture,save,100000);
}
int main(void) {
 unsigned i,j; unsigned char digest[32],buffer[1024];
 fixture_handshake_data(); handshake_reset(&state);
 run(0,0x100,1); run(1,0x1800,1); run(2,0x3000,1); run(3,0x5000,1);
 assert(emitted==4);
 for(i=0;i<4;++i) assert(results[i].complete && state.slot[i]==(int)i);
 assert(results[0].count==3 && results[0].tokens[0].length==240 && results[0].tokens[2].length==272);
 assert(results[1].request_id==129 && results[1].flag==1 && results[1].uint32_c==42 && results[1].proxy_id==7);
 assert(results[1].tokens[0].length==208 && results[1].tokens[0].remaining==900);
 assert(!memcmp(results[1].tokens[0].sha256,results[2].tokens[1].sha256,32));
 assert(!memcmp(results[0].tokens[0].sha256,results[2].tokens[0].sha256,32));
 assert(!memcmp(results[0].tokens[2].sha256,results[2].tokens[2].sha256,32));
 assert(results[3].flag==1 && !results[3].prefix_zero);
 for(i=0;i<sizeof(state.scratch);++i) assert(!state.scratch[i]);
 run(0,0x100,0); run(3,0x5000,0); assert(emitted==4);
 fixture_u(0x1804,0,1); run(1,0x1800,1); assert(results[4].complete && !results[4].count);
 fixture_token(0x3000,1025,'X'); run(2,0x3000,1); assert(!results[5].complete);
 fixture_handshake_data(); fixture_u(0x3408,1,8); run(2,0x3000,1); assert(!results[6].complete);
 fixture_handshake_data(); fixture_u(0x3010,0,8); run(2,0x7fff,1); assert(!results[7].complete);
 fixture_handshake_data(); fixture_u(0x3c78,1,1); fixture_token(0x3c80,3,'G'); run(2,0x3000,1);
 assert(results[8].complete && results[8].count==4 && results[8].tokens[3].length==3);
 fixture_u(0x3c78,2,1); run(2,0x3000,1); assert(!results[9].complete);
 memset(buffer,'a',sizeof(buffer));
 for(i=0;i<6;++i) {
  unsigned lengths[]={0,3,55,56,64,1024};
  hs_sha256(i==1?(const unsigned char *)"abc":buffer,lengths[i],digest);
  for(j=0;j<32;++j) printf("%02x",digest[j]);
  puts("");
 }
 return 0;
}
