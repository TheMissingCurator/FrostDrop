/* Four bounded decoded-object observations. Never persist bearer bytes. */
#ifndef ISAC_RETAIL_HANDSHAKE_H
#define ISAC_RETAIL_HANDSHAKE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define HANDSHAKE_SITE_COUNT 4
typedef struct { uint64_t rsp,rbp,rax,rbx,rcx,rdx,rsi,rdi,r13,r14; } HandshakeRegs;
typedef int (*HandshakeRead)(uintptr_t,void *,size_t);
typedef struct { unsigned length; uint64_t deadline,remaining; unsigned char sha256[32]; } HandshakeToken;
typedef struct {
 unsigned kind,complete,request_id,flag,uint32_c,proxy_id,count,extra;
 HandshakeToken tokens[4];
 unsigned string_lengths[3]; unsigned char string_hashes[3][32];
 unsigned char prefix_hash[32]; unsigned prefix_zero;
} HandshakeResult;
typedef struct { int slot[4],active; HandshakeResult result; unsigned char scratch[1024]; } HandshakeState;
typedef void (*HandshakeEmit)(const HandshakeResult *);

static uint32_t hs_rotr(uint32_t x,unsigned n) { return (x>>n)|(x<<(32-n)); }
static void hs_sha256(const unsigned char *bytes,unsigned length,unsigned char digest[32]) {
 static const uint32_t k[64]={
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
 uint32_t h[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
 unsigned total=((length+9+63)/64)*64,pos,i,j; uint64_t bits=(uint64_t)length*8;
 for(pos=0;pos<total;pos+=64) {
  unsigned char block[64]; uint32_t w[64],a,b,c,d,e,f,g,z;
  for(i=0;i<64;++i) {
   unsigned n=pos+i;
   block[i]=n<length?bytes[n]:n==length?128:n>=total-8?(unsigned char)(bits>>(8*(total-1-n))):0;
  }
  for(i=0;i<16;++i) w[i]=((uint32_t)block[4*i]<<24)|((uint32_t)block[4*i+1]<<16)|((uint32_t)block[4*i+2]<<8)|block[4*i+3];
  for(i=16;i<64;++i) w[i]=w[i-16]+(hs_rotr(w[i-15],7)^hs_rotr(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(hs_rotr(w[i-2],17)^hs_rotr(w[i-2],19)^(w[i-2]>>10));
  a=h[0];b=h[1];c=h[2];d=h[3];e=h[4];f=h[5];g=h[6];z=h[7];
  for(i=0;i<64;++i) {
   uint32_t t1=z+(hs_rotr(e,6)^hs_rotr(e,11)^hs_rotr(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
   uint32_t t2=(hs_rotr(a,2)^hs_rotr(a,13)^hs_rotr(a,22))+((a&b)^(a&c)^(b&c));
   z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
  }
  h[0]+=a;h[1]+=b;h[2]+=c;h[3]+=d;h[4]+=e;h[5]+=f;h[6]+=g;h[7]+=z;
 }
 for(i=0;i<8;++i) for(j=0;j<4;++j) digest[4*i+j]=(unsigned char)(h[i]>>(24-8*j));
}
static uint64_t hs_uint(HandshakeResult *o,HandshakeRead read,uintptr_t p,unsigned n) {
 uint64_t v=0;
 if(!p || n>8 || p+n<p || !read(p,&v,n)) o->complete=0;
 return v;
}
static void hs_token(HandshakeState *s,HandshakeRead read,uintptr_t base,uintptr_t p,unsigned index,uint64_t now) {
 HandshakeResult *o=&s->result; HandshakeToken *t=&o->tokens[index]; uintptr_t data; uint64_t n;
 /* Verified MG bounded byte container: vtable, pointer+408, count+410,
  * capacity+414, absolute epoch-seconds deadline+420. No virtual calls. */
 if(hs_uint(o,read,p,8)!=base+0x2914dd8) { o->complete=0; return; }
 data=(uintptr_t)hs_uint(o,read,p+0x408,8); n=hs_uint(o,read,p+0x410,4);
 t->deadline=hs_uint(o,read,p+0x420,8);
 if(n>sizeof(s->scratch) || n>hs_uint(o,read,p+0x414,4) || (n && (!data || data+n<data || !read(data,s->scratch,(size_t)n)))) o->complete=0;
 if(o->complete) {
  t->length=(unsigned)n; t->remaining=t->deadline>now?t->deadline-now:0;
  hs_sha256(s->scratch,(unsigned)n,t->sha256);
 }
 /* Volatile clear: raw bearer bytes must not remain in queued results/state. */
 { volatile unsigned char *wipe=s->scratch; unsigned i; for(i=0;i<sizeof(s->scratch);++i) wipe[i]=0; }
}
static void hs_string(HandshakeState *s,HandshakeRead read,uintptr_t base,uintptr_t p,unsigned index) {
 HandshakeResult *o=&s->result; uintptr_t data; unsigned n;
 if(hs_uint(o,read,p,8)!=base+0x2910bb8) { o->complete=0; return; }
 data=(uintptr_t)hs_uint(o,read,p+0x48,8);
 for(n=0;n<64;++n) {
  if(!data || data+n<data || !read(data+n,s->scratch+n,1)) { o->complete=0; break; }
  if(!s->scratch[n]) { o->string_lengths[index]=n; hs_sha256(s->scratch,n,o->string_hashes[index]); break; }
 }
 if(n==64) o->complete=0;
 memset(s->scratch,0,sizeof(s->scratch));
}
static void handshake_reset(HandshakeState *s) {
 unsigned i; memset(s,0,sizeof(*s)); for(i=0;i<4;++i) s->slot[i]=(int)i;
}
static void handshake_handle(HandshakeState *s,int kind,const HandshakeRegs *r,uintptr_t base,
                             HandshakeRead read,HandshakeEmit emit,uint64_t now) {
 HandshakeResult *o=&s->result; uintptr_t p=kind==2?r->rcx:r->rdi; unsigned i;
 memset(o,0,sizeof(*o)); o->kind=(unsigned)kind; o->complete=1;
 if(kind<0 || kind>=4) return;
 if(kind!=2) {
  uint64_t tag=hs_uint(o,read,r->rbx+0x10,2);
  if(!o->complete || tag!=(uint64_t)(kind==0?3:kind==1?6:2) || (kind!=1 && (r->rax&255)!=1)) return;
 }
 if(kind==0) {
  o->flag=(unsigned)hs_uint(o,read,p,1); o->count=3;
  hs_token(s,read,base,p+8,0,now); hs_token(s,read,base,p+0x430,1,now); hs_token(s,read,base,p+0x8f0,2,now);
 } else if(kind==1) {
  o->request_id=(unsigned)hs_uint(o,read,p,4); o->flag=(unsigned)hs_uint(o,read,p+4,1);
  if(o->flag>1) o->complete=0;
  if(o->flag) {
   o->uint32_c=(unsigned)hs_uint(o,read,p+0xc,4); o->count=1;
   hs_string(s,read,base,p+0x10,0); hs_token(s,read,base,p+0x68,0,now);
   hs_string(s,read,base,p+0x4e8,1); hs_string(s,read,base,p+0x490,2);
   o->proxy_id=(unsigned)hs_uint(o,read,p+0x540,4);
  } else o->uint32_c=(unsigned)hs_uint(o,read,p+8,4); /* failure queue_pos */
 } else if(kind==2) {
  o->count=3;
  for(i=0;i<3;++i) hs_token(s,read,base,p+0x428*i,i,now);
  o->extra=(unsigned)hs_uint(o,read,p+0xc78,1);
  if(o->extra>1) o->complete=0;
  if(o->extra==1) { o->count=4; hs_token(s,read,base,p+0xc80,3,now); }
 } else {
  /* Reader 0x22556c0: raw 16-byte field, then boolean at +10. Hash only. */
  if(!p || p+16<p || !read(p,s->scratch,16)) o->complete=0;
  else { o->prefix_zero=1; for(i=0;i<16;++i) if(s->scratch[i]) o->prefix_zero=0;
   hs_sha256(s->scratch,16,o->prefix_hash); memset(s->scratch,0,16); }
  o->flag=(unsigned)hs_uint(o,read,p+0x10,1); if(o->flag>1) o->complete=0;
 }
 emit(o);
}
#endif
