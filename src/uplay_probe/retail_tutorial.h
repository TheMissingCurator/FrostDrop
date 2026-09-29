/* Private observational tutorial stream. Never call or modify game objects. */
#ifndef ISAC_RETAIL_TUTORIAL_H
#define ISAC_RETAIL_TUTORIAL_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define TUTORIAL_BYTES 16384
#define TUTORIAL_READERS 64
typedef struct { uint64_t rsp,rbp,rax,rbx,rcx,rdx,rsi,rdi,r13,r14; } TutorialRegs;
typedef int (*TutorialRead)(uintptr_t,void *,size_t);
typedef struct { unsigned kind,stream,length,aux; unsigned char bytes[TUTORIAL_BYTES]; } TutorialResult;
typedef void (*TutorialEmit)(const TutorialResult *);
typedef struct { int slot[4],active; TutorialResult result; } TutorialState;
typedef struct { uintptr_t reader,source; unsigned length,rejected; unsigned char prefix[24]; } TutorialReader;
typedef struct {
 uintptr_t writer; unsigned waiting,selected,count,failed,filtered,parsed,confirmed;
#if defined(ISAC_RETAIL_PRESENTATION)
 unsigned presentation_count[2];
#endif
 unsigned char sync_reply[17],parsed_reply[17];
 TutorialReader readers[TUTORIAL_READERS];
} TutorialSession;
/* Errors: 1 unreadable, 2 bounds, 3 readers, 4 source replacement,
 * 5 a second world request, 6 malformed selected envelope, 7 synchronization,
 * 8 selected stream disagrees with parsed connect reply. */
static void tutorial_reset(TutorialState *s) {
 unsigned i; memset(s,0,sizeof(*s)); for(i=0;i<4;++i) s->slot[i]=(int)i;
}
#if !defined(ISAC_RETAIL_VAULT_STATE)
static int tut_read(TutorialRead read,uintptr_t p,void *out,size_t n) {
 return p && p+n>=p && read(p,out,n);
}
static int tut_uint(TutorialRead read,uintptr_t p,uint64_t *v,unsigned n) {
 *v=0; return n<=8 && tut_read(read,p,v,n);
}
static void tut_error(TutorialSession *session,TutorialState *s,TutorialEmit emit,unsigned reason) {
 session->failed=1; s->result.kind=6; s->result.stream=session->selected;
 s->result.length=0; s->result.aux=reason; emit(&s->result);
}
static int tut_var(const unsigned char *b,unsigned n,unsigned *p,uint64_t *v,unsigned bits) {
 unsigned i; *v=0;
 for(i=0;i<(bits+6)/7 && *p<n;++i) {
  unsigned c=b[(*p)++]; *v|=(uint64_t)(c&127)<<(7*i);
  if(!(c&128)) return bits==64 || *v<((uint64_t)1<<bits);
 }
 return 0;
}
/* A complete application envelope only. Mark all connect/login types sensitive. */
static int tut_envelope(const unsigned char *b,unsigned n,unsigned *world,unsigned *sensitive) {
 unsigned p=2,end,frames=0; uint64_t size,type; *world=*sensitive=0;
 if(n<4 || b[0]!=3 || !tut_var(b,n,&p,&size,32) || size!=n-p) return 0;
 while(p<n) {
  if(!tut_var(b,n,&p,&size,32) || (size&1) || (size>>1)>n-p) return 0;
  end=p+(unsigned)(size>>1);
  if(!tut_var(b,end,&p,&type,16)) return 0;
  if(type==0 || type==2) *sensitive=1;
  if(type==0 && b[1]==0 && end-p>=512 && end-p<=2048 && frames==0 && end==n) *world=1;
  ++frames; p=end;
 }
 return frames!=0;
}
static void tutorial_handle(TutorialSession *session,TutorialState *s,int kind,const TutorialRegs *r,
                           uintptr_t base,TutorialRead read,TutorialEmit emit) {
 TutorialResult *o=&s->result; uint64_t p,n,v,next,source; unsigned i,pos,size,world,sensitive;
 if(session->failed) return;
 o->length=0; o->stream=session->selected; o->aux=0;
 if(kind==1) {
  if(!tut_uint(read,r->rdx+0x4090,&p,8) || !tut_uint(read,r->rdx+0x4098,&n,4)) {
   if(session->writer==r->rcx) tut_error(session,s,emit,1);
   goto wipe;
  }
  if(!n || n>TUTORIAL_BYTES) {
   if(session->writer==r->rcx) tut_error(session,s,emit,2);
   goto wipe;
  }
  if(!tut_read(read,(uintptr_t)p,o->bytes,(size_t)n)) {
   if(session->writer==r->rcx) tut_error(session,s,emit,1);
   goto wipe;
  }
  if(!tut_envelope(o->bytes,(unsigned)n,&world,&sensitive)) {
   if(session->writer==r->rcx) tut_error(session,s,emit,6);
  } else if(world) {
   if(session->writer) { tut_error(session,s,emit,5); goto wipe; }
   session->writer=r->rcx; session->waiting=1;
   /* Instance credentials never enter the queue or file. */
   o->kind=5; o->length=0; o->aux=(unsigned)n; emit(o);
  } else if(session->selected && session->writer==r->rcx && o->bytes[1]==0) {
   if(sensitive) ++session->filtered;
   else { o->kind=2; o->length=(unsigned)n; emit(o); }
  }
  /* Remove any temporary login/instance bearer window, including failures. */
wipe:
  { volatile unsigned char *wipe=o->bytes; for(i=0;i<TUTORIAL_BYTES;++i) wipe[i]=0; }
  return;
 }
 if(kind==2 || kind==3) {
#if defined(ISAC_RETAIL_PRESENTATION)
  unsigned event=kind-2; uint64_t caller=0;
  /* These are script-node evaluation entries, not proof of presentation.
   * Only the bounded caller RVA is retained; no node data or audio ID. */
  if(!session->selected || ++session->presentation_count[event]>8192) return;
  if(tut_uint(read,r->rsp,&caller,8) && caller>=base+0x1000 && caller<base+0x2901000)
   o->aux=(unsigned)(caller-base);
  o->kind=7+event; o->length=0; emit(o);
#else
  if((r->rax&255)!=1 || !tut_uint(read,r->rbx+0x10,&v,2) || v!=(uint64_t)(kind==2?2:6)) return;
  if(kind==2) {
   o->kind=3; o->length=17;
   if(!tut_read(read,r->rdi,o->bytes,17) || o->bytes[16]>1) { tut_error(session,s,emit,1); return; }
   session->parsed=1; memcpy(session->parsed_reply,o->bytes,17);
   if(session->selected) {
    if(memcmp(session->sync_reply,o->bytes,17)) { tut_error(session,s,emit,8); return; }
    session->confirmed=1;
   }
   emit(o);
  } else {
   o->kind=4; o->length=0;
   if(!tut_uint(read,r->rdi+4,&v,4)) return;
   o->aux=(unsigned)v;
   if(!v) { o->length=16; if(!tut_read(read,r->rdi+8,o->bytes,16)) { tut_error(session,s,emit,1); return; } }
   emit(o);
  }
#endif
  return;
 }
 if(kind!=0 || !r->rcx || r->rcx<8) return;
 /* Secondary reader's source +68 == primary reader's +70. */
 if(!tut_uint(read,r->rcx+0x68,&source,8) || !tut_uint(read,(uintptr_t)source,&v,8) || v!=base+0x34863d8) {
  if(session->selected && session->readers[session->selected-1].reader==r->rcx) tut_error(session,s,emit,1);
  return;
 }
 for(i=0;i<session->count;++i) if(session->readers[i].reader==r->rcx) break;
 if(i==session->count) {
  if(i==TUTORIAL_READERS) { tut_error(session,s,emit,3); return; }
  ++session->count; session->readers[i].reader=r->rcx; session->readers[i].source=(uintptr_t)source;
  /* Exclude all readers seen before the credential-bearing world request. */
  session->readers[i].rejected=!session->waiting || session->selected;
 }
 if(session->readers[i].source!=(uintptr_t)source) {
  if(session->selected==i+1) tut_error(session,s,emit,4);
  return;
 }
 if(session->readers[i].rejected) return;
 if(!tut_uint(read,r->rdx,&p,8)) { tut_error(session,s,emit,1); return; }
 for(pos=0;p && pos<1024;++pos,p=next) {
  if(!tut_uint(read,(uintptr_t)p+0xc,&n,4) || !tut_uint(read,(uintptr_t)p+0x3f8,&next,8)) { tut_error(session,s,emit,1); return; }
  if(n>1048576 || next==p) { tut_error(session,s,emit,2); return; }
  for(size=0;size<n;) {
   unsigned take=(unsigned)n-size; uintptr_t address=(uintptr_t)p+0x10+size;
   if(!session->selected) {
    TutorialReader *candidate=&session->readers[i]; unsigned start=0;
    /* Keep only a tiny sync prefix in memory; never dump unrelated readers. */
    take=1;
    if(candidate->length==24 || !tut_read(read,address,candidate->prefix+candidate->length,1)) { tut_error(session,s,emit,7); return; }
    ++candidate->length; ++size;
    if(candidate->length>=19 && candidate->prefix[0]==0x24 && candidate->prefix[1]==2 && candidate->prefix[18]<=1) start=1;
    else if(candidate->length==24 && candidate->prefix[5]==0x24 && candidate->prefix[6]==2 && candidate->prefix[23]<=1) start=6;
    if(start) {
     memcpy(session->sync_reply,candidate->prefix+start+1,17);
     if(session->parsed && memcmp(session->parsed_reply,session->sync_reply,17)) { tut_error(session,s,emit,8); return; }
     session->confirmed=session->parsed;
     session->selected=i+1; session->waiting=0; o->kind=1; o->stream=i+1; o->length=19; o->aux=1;
     memcpy(o->bytes,candidate->prefix+start-1,19); memset(candidate->prefix,0,24); emit(o);
    } else if(candidate->length==24) { candidate->rejected=1; return; }
    continue;
   }
   if(session->selected!=i+1) { session->readers[i].rejected=1; return; }
   if(take>TUTORIAL_BYTES) take=TUTORIAL_BYTES;
   if(!tut_read(read,address,o->bytes,take)) { tut_error(session,s,emit,1); return; }
   o->kind=1; o->stream=i+1; o->length=take; o->aux=0; emit(o); size+=take;
  }
 }
 if(p) tut_error(session,s,emit,2);
}
#endif
/* Rising edges; loss of foreground focus requires release before re-arming. */
static unsigned tutorial_key_edges(unsigned *previous,unsigned down,int foreground) {
 unsigned edges=foreground?(down & ~*previous):0; *previous=down; return edges&2047;
}
#endif
