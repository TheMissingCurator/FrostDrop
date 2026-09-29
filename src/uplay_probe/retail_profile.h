/* Read-only, bounded decoded-object capture. No game function calls.
 * Bodies are reconstructed from parsed fields, NOT original wire packets. */
#ifndef ISAC_RETAIL_PROFILE_H
#define ISAC_RETAIL_PROFILE_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define PROFILE_SITE_COUNT 4
#define PROFILE_BYTES 98304
typedef struct { uint64_t rsp,rbp,rax,rbx,rcx,rdx,rsi,rdi,r13,r14; } ProfileRegs;
typedef int (*ProfileRead)(uintptr_t,void *,size_t);
typedef struct {
 unsigned kind, complete, length, count;
 unsigned char bytes[PROFILE_BYTES];
} ProfileResult;
typedef struct { int slot[4], active; ProfileResult result; } ProfileState;
typedef void (*ProfileEmit)(const ProfileResult *);
static uint64_t profile_uint(ProfileResult *o,ProfileRead read,uintptr_t p,unsigned n) {
 uint64_t v=0;
 if (!p || n>8 || p+n<p || !read(p,&v,n)) o->complete=0;
 return v;
}
static void profile_var(ProfileResult *o,uint64_t v) {
 do {
  if (o->length==PROFILE_BYTES) { o->complete=0; return; }
  o->bytes[o->length++]=(unsigned char)((v & 127) | (v>127?128:0)); v>>=7;
 } while (v);
}
static void profile_copy(ProfileResult *o,ProfileRead read,uintptr_t p,unsigned n) {
 if (!o->complete) return;
 if (n>PROFILE_BYTES-o->length || (n && (!p || p+n<p || !read(p,o->bytes+o->length,n)))) {
  o->complete=0; return;
 }
 o->length+=n;
}
static void profile_scalar(ProfileResult *o,ProfileRead read,uintptr_t p,unsigned n) {
 profile_var(o,profile_uint(o,read,p,n));
}
static void profile_string(ProfileResult *o,ProfileRead read,uintptr_t base,uintptr_t p) {
 uintptr_t data; unsigned n; unsigned char ch;
 if (profile_uint(o,read,p,8)!=base+0x2910bb8) { o->complete=0; return; }
 data=(uintptr_t)profile_uint(o,read,p+0x48,8);
 for(n=0;n<64;++n) {
  if (!data || !read(data+n,&ch,1)) { o->complete=0; return; }
  if (!ch) { profile_var(o,n); profile_copy(o,read,data,n); return; }
 }
 o->complete=0;
}
static void profile_entry(ProfileResult *o,ProfileRead read,uintptr_t base,uintptr_t p) {
 unsigned i,n; uintptr_t data;
 profile_copy(o,read,p,16);
 profile_scalar(o,read,p+0x10,4); profile_scalar(o,read,p+0x14,1);
 profile_scalar(o,read,p+0x18,8); profile_scalar(o,read,p+0x20,8);
 profile_string(o,read,base,p+0x80); profile_string(o,read,base,p+0x28);
 for(i=0;i<4;++i) profile_scalar(o,read,p+0xd8+i,1);
 profile_scalar(o,read,p+0x300,1);
 if (profile_uint(o,read,p+0xe0,8)!=base+0x2917838) { o->complete=0; return; }
 n=(unsigned)profile_uint(o,read,p+0x2f0,4);
 data=(uintptr_t)profile_uint(o,read,p+0x2e8,8);
 if(n>10000) { o->complete=0; return; }
 profile_var(o,n); profile_copy(o,read,data,n);
}
static void profile_reset(ProfileState *s) {
 unsigned i; memset(s,0,sizeof(*s)); for(i=0;i<4;++i) s->slot[i]=(int)i;
}
#if defined(ISAC_RETAIL_FINALIZATION)
static int profile_read_var(const unsigned char *bytes,unsigned end,unsigned *at,unsigned *value) {
 unsigned i; uint64_t result=0;
 for(i=0;i<5 && *at<end;++i) {
  unsigned byte=bytes[(*at)++]; result|=(uint64_t)(byte&127)<<(7*i);
  if(!(byte&128)) {
   if(result>0xffffffffULL) return 0;
   *value=(unsigned)result; return 1;
  }
 }
 return 0;
}
/* The generic outbound writer also sees credentials. Inspect a bounded copy,
 * emit ONLY the 16-byte character ID of one world-channel type-0x000c shape,
 * and wipe the temporary envelope before returning from the VEH. */
static void profile_agent_submit(ProfileResult *o,const ProfileRegs *r,ProfileRead read,ProfileEmit emit) {
 uint64_t p,n; unsigned at,declared,length,type,end,i,found=0; unsigned char identifier[16]={0};
 o->kind=3; o->complete=1; o->count=147; o->length=0;
 p=profile_uint(o,read,r->rdx+0x4090,8);
 n=profile_uint(o,read,r->rdx+0x4098,4);
 if(!o->complete || n<5 || n>4096 || !p || p+n<p) return;
 if(!read((uintptr_t)p,o->bytes,(size_t)n)) goto reject;
 at=2;
 if(o->bytes[0]!=3 || o->bytes[1]!=0 ||
    !profile_read_var(o->bytes,(unsigned)n,&at,&declared) || declared!=n-at) goto reject;
 while(at<(unsigned)n) {
  if(!profile_read_var(o->bytes,(unsigned)n,&at,&length) || (length&1) ||
     (length>>1)>n-at) goto reject;
  end=at+(length>>1);
  if(!profile_read_var(o->bytes,end,&at,&type)) goto reject;
  if(type==0 || type==2) goto reject;
  if(type==0x000c && end-at==147) {
   if(found) goto reject;
   memcpy(identifier,o->bytes+at,16);
   ++found;
  }
  at=end;
 }
 if(!found) goto reject;
 { volatile unsigned char *clear=o->bytes; for(i=0;i<(unsigned)n;++i) clear[i]=0; }
 memcpy(o->bytes,identifier,16); o->length=16; emit(o);
 memset(identifier,0,sizeof(identifier)); return;
reject:
 { volatile unsigned char *clear=o->bytes; for(i=0;i<(unsigned)n;++i) clear[i]=0; }
 memset(identifier,0,sizeof(identifier));
}
#endif
static void profile_handle(ProfileState *s,int kind,const ProfileRegs *r,uintptr_t base,
                           ProfileRead read,ProfileEmit emit) {
 ProfileResult *o=&s->result; uintptr_t p=kind==0?r->rcx:r->rdi,items; unsigned i;
 memset(o,0,sizeof(*o)); o->kind=(unsigned)kind; o->complete=1;
 if (kind<0 || kind>=4) return;
#if defined(ISAC_RETAIL_FINALIZATION)
 if(kind==3) { profile_agent_submit(o,r,read,emit); return; }
#endif
 if (kind && profile_uint(o,read,r->rbx+0x10,2)!=(uint64_t)(kind==1?6:kind==2?2:8)) return;
 profile_scalar(o,read,p,4); /* request ID */
 if(kind==0) {
  profile_scalar(o,read,p+5,1); profile_scalar(o,read,p+4,1);
 } else if(kind==1) {
  unsigned status=(unsigned)profile_uint(o,read,p+4,4);
  profile_var(o,status); if(!status) profile_copy(o,read,p+8,16);
 } else if(kind==2) {
  profile_scalar(o,read,p+4,1); profile_scalar(o,read,p+0x128,1);
  profile_scalar(o,read,p+0x129,1); profile_scalar(o,read,p+8,4);
  profile_string(o,read,base,p+0x130);
  if(profile_uint(o,read,p+0x10,8)!=base+0x2917998) o->complete=0;
  o->count=(unsigned)profile_uint(o,read,p+0x18,4);
  items=(uintptr_t)profile_uint(o,read,p+0x20,8);
  if(o->count>8 || (o->count && !items)) o->complete=0;
  profile_var(o,o->count);
  for(i=0;o->complete && i<o->count;++i)
   profile_entry(o,read,base,(uintptr_t)profile_uint(o,read,items+8*i,8));
 } else {
  /* Handoff metadata only: ID, status, two strings and optional-section flags.
   * Deliberately omit live session token blobs; this is NOT a type-8 body. */
  profile_scalar(o,read,p+4,4);
  profile_string(o,read,base,p+8); profile_string(o,read,base,p+0x60);
  profile_scalar(o,read,p+0xb8,1); profile_scalar(o,read,p+0x920,1);
 }
 emit(o);
}
#endif
