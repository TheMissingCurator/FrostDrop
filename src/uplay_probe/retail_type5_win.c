/* Retail-only VEH observer. No local bridge, SDK adapter or code patches. */
#include "stack_probe.h"
#include <tlhelp32.h>
#include <stdint.h>
#include <stdio.h>
#if defined(ISAC_RETAIL_TUTORIAL)
#include "retail_tutorial.h"
#define RESULT_LIMIT 256
#elif defined(ISAC_RETAIL_HANDSHAKE)
#include "retail_handshake.h"
#define RESULT_LIMIT 64
#elif defined(ISAC_RETAIL_PROFILE)
#include "retail_profile.h"
#define RESULT_LIMIT 64
#else
#include "retail_type5.h"
#define RESULT_LIMIT 192
#endif
#if defined(ISAC_RETAIL_TUTORIAL)
#define THREAD_LIMIT 512
#else
#define THREAD_LIMIT 256
#endif
typedef struct { unsigned rva; const char *bytes; unsigned size; } Site;
#define SITE(r,s) {r,s,sizeof(s)-1}
#if defined(ISAC_RETAIL_TUTORIAL)
#if defined(ISAC_RETAIL_VAULT_STATE)
static const Site sites[] = {
 SITE(0xf14000,"\x48\x63\x02\x8b\x44\x81\x4c\xc3"),
 SITE(0x19be5e4,"\x48\x85\xc0\x74\x13\x48\x8d\x54\x24\x38")
};
static const Site auxiliary[] = {
 SITE(0x286d5f0,"\x48\x83\xec\x28\x48\x8d\x0d\x8d\x05\xf6\x01")
};
#else
static const Site sites[] = {
 SITE(0x84bd0,"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18"),
 SITE(0xd6bbf,"\xff\x50\x08\x48\x8d\x4c\x24\x20\xe8\x04\x15\x16\x02"),
#if defined(ISAC_RETAIL_PRESENTATION)
 SITE(0x6316d0,"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x18\x48\x89\x7c\x24\x20\x55"),
 SITE(0x15c00a0,"\x48\x89\x5c\x24\x10\x56\x48\x81\xec\x90\x00\x00\x00")
#else
 SITE(0x2255717,"\x48\x8b\x5c\x24\x30\x84\xc0\x0f\x95\xc0"),
 SITE(0x2257db8,"\x48\x8b\x74\x24\x30\x48\x8b\x5c\x24\x38\xb0\x01")
#endif
};
static const Site auxiliary[] = {
 SITE(0x84c10,"\x48\x8b\x4e\x68\x44\x8b\x43\x0c\x48\x8d\x53\x10"),
#if defined(ISAC_RETAIL_PRESENTATION)
 SITE(0x624290,"\x48\x83\xec\x28\xb9\x30\x00\x00\x00"),
 SITE(0x1595400,"\x48\x83\xec\x28\xb9\x38\x00\x00\x00")
#else
 SITE(0x22556ca,"\x66\x83\x7a\x10\x02"), SITE(0x2257d3a,"\x66\x83\x7a\x10\x06")
#endif
};
#endif
#elif defined(ISAC_RETAIL_HANDSHAKE)
static const Site sites[] = {
 SITE(0x22552b3,"\x48\x8b\x5c\x24\x30\x84\xc0\x0f\x95\xc0"),
 SITE(0x22593ae,"\x48\x8b\x74\x24\x30\x48\x8b\x5c\x24\x38\xb0\x01"),
 SITE(0x225adf0,"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20"),
 SITE(0x2255717,"\x48\x8b\x5c\x24\x30\x84\xc0\x0f\x95\xc0")
};
static const Site auxiliary[] = {
 SITE(0x22551ba,"\x66\x83\x7a\x10\x03"), SITE(0x22592da,"\x66\x83\x7a\x10\x06"),
 SITE(0x22556ca,"\x66\x83\x7a\x10\x02"), SITE(0x225ae00,"\x33\xd2\x48\x8b\xcb"),
 SITE(0x68c30,"\x48\x8b\x81\x08\x04\x00\x00\xc3"), SITE(0x6b730,"\x8b\x81\x10\x04\x00\x00\xc3"),
 SITE(0x12920,"\x48\x8b\x41\x48\xc3"), SITE(0x12ae0,"\xb8\x10\x00\x00\x00\xc3")
};
static uint64_t handshake_now(void) {
 FILETIME ft; ULARGE_INTEGER value;
 GetSystemTimeAsFileTime(&ft); value.LowPart=ft.dwLowDateTime; value.HighPart=ft.dwHighDateTime;
 return value.QuadPart/10000000ULL-11644473600ULL;
}
#elif defined(ISAC_RETAIL_PROFILE)
static const Site sites[] = {
 SITE(0x225cb10,"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20"),
 SITE(0x2257db8,"\x48\x8b\x74\x24\x30\x48\x8b\x5c\x24\x38\xb0\x01\x48\x83\xc4\x20\x5f\xc3"),
 SITE(0x2258222,"\xb0\x01\x48\x83\xc4\x38\x5f\x5b\xc3"),
#if defined(ISAC_RETAIL_FINALIZATION)
 SITE(0xd6bbf,"\xff\x50\x08\x48\x8d\x4c\x24\x20\xe8\x04\x15\x16\x02")
#else
 SITE(0x22583a1,"\x48\x8b\x74\x24\x30\x48\x8b\x5c\x24\x38\xb0\x01\x48\x83\xc4\x20\x5f\xc3")
#endif
};
static const Site auxiliary[] = {
 SITE(0x2257f97,"\x66\x83\x7a\x10\x02"), SITE(0x2257d3a,"\x66\x83\x7a\x10\x06"),
 SITE(0x225824a,"\x66\x83\x7a\x10\x08"), SITE(0x225cb20,"\xba\x05\x00\x00\x00"),
 SITE(0x12920,"\x48\x8b\x41\x48\xc3"), SITE(0x5b950,"\x8b\x41\x08\xc3"),
 SITE(0x68bf0,"\x48\x8b\x81\x08\x02\x00\x00\xc3")
};
#else
static const Site sites[] = {
 SITE(0x8b60b,"\xe8\x20\xce\x1c\x02"), SITE(0x8b610,"\x84\xc0\x75\x07\x32\xdb\xe9\x3a\x01\x00\x00"),
 SITE(0x8b755,"\x48\x8d\x4c\x24\x78\xe8\x51\xa0\xfa\xff"), SITE(0x21830,"\x8b\x54\x24\x48\x3b\xd3\x73\xe6"),
 SITE(0x654c6,"\x8b\x45\x77\x83\xf8\x18\x77\xe8"), SITE(0x6556e,"\x8b\x55\x67\x83\xfa\x40"),
 SITE(0x65623,"\x48\x8d\x55\xb7\x49\x8b\xce\xe8\x11\xdb\xfe\xff"), SITE(0x8b6d1,"\xe8\xea\x20\xf9\xff\x48\x8b\x8d"),
 SITE(0x8b6d6,"\x48\x8b\x8d\x00\x03\x00\x00\x48"), SITE(0x5fe48,"\x84\xc0\x74\x04\x32\xdb\xeb\x28")
};
static const Site auxiliary[] = {
 SITE(0x12920,"\x48\x8b\x41\x48\xc3"), SITE(0x69160,"\x48\x8b\x41\x30\xc3"),
 SITE(0x12860,"\x48\x8b\x41\x18\xc3"), SITE(0x5b9d0,"\x8b\x41\x08\xc3"),
 SITE(0x8b590,"\x48\x8b\xc4\x55\x53\x48\x8d\xa8\x18\xfd\xff\xff\x48\x81\xec\xd8\x03\x00\x00"),
 SITE(0x2258430,"\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20"),
 SITE(0x225843a,"\x66\x83\x7a\x10\x05\x48\x8b\xda"),
 SITE(0x2258461,"\x41\xb8\x40\x00\x00\x00\x48\x8b\xd7\x48\x8b\xcb\xe8\x7e\x93\xdc\xfd"),
 SITE(0x217f0,"\x48\x89\x5c\x24\x08\x48\x89\x74\x24\x10\x57\x48\x83\xec\x20"),
 SITE(0x65480,"\x40\x55\x56\x41\x56\x41\x57\x48\x8d\x6c\x24\xc1\x48\x81\xec\xa8\x00\x00\x00"),
 SITE(0x655d5,"\x8b\x55\x67\x81\xfa\x00\x02\x00\x00"),
 SITE(0x5fb10,"\x4c\x89\x4c\x24\x20\x4c\x89\x44\x24\x18\x55\x53\x56\x57\x41\x54\x41\x55\x41\x56\x48\x8d\xac\x24\x20\xfe\xff\xff\x48\x81\xec\xe0\x02\x00\x00"),
 SITE(0x14c20,"\x48\x83\xec\x28\x48\x8b\x01\xff\x50\x10\x33\xc9\x38\x08\x0f\x94\xc0\x48\x83\xc4\x28\xc3")
};
#endif
static uintptr_t base;
static volatile LONG stopped, reserved, hits, begun;
#if !defined(ISAC_RETAIL_PROFILE) && !defined(ISAC_RETAIL_HANDSHAKE) && !defined(ISAC_RETAIL_TUTORIAL)
static volatile LONG advertisements, gates;
#endif
static volatile LONG debug_context_refreshes;
static ULONGLONG deadline;
typedef struct { DWORD id; volatile LONG ready; T5State state; HANDLE handle; } Thread;
static Thread threads[THREAD_LIMIT];
static unsigned thread_count;
typedef struct { volatile LONG ready; DWORD thread; ULONGLONG tick; T5Result result; } Result;
static Result results[RESULT_LIMIT];
static volatile unsigned consumed;
static unsigned conflicts, failed, armed, resume_failed, pending;
static HANDLE output = INVALID_HANDLE_VALUE;
#if defined(ISAC_RETAIL_TUTORIAL)
static HANDLE tutorial_payload=INVALID_HANDLE_VALUE;
#if !defined(ISAC_RETAIL_VAULT_STATE)
static TutorialSession tutorial_session;
static volatile LONG tutorial_lock, tutorial_gaps;
#else
static volatile LONG tutorial_gaps;
#endif
static unsigned tutorial_keys, tutorial_markers, tutorial_records;
static uint64_t tutorial_bytes;
#endif
#if !defined(ISAC_RETAIL_PROFILE) && !defined(ISAC_RETAIL_HANDSHAKE) && !defined(ISAC_RETAIL_TUTORIAL)
static uintptr_t owners[RESULT_LIMIT];
static unsigned owner_count;
#endif
static int read_memory(uintptr_t address, void *out, size_t size) {
 SIZE_T done=0;
 return address && address+size>=address && ReadProcessMemory(GetCurrentProcess(),(const void *)address,out,size,&done) && done==size;
}
static uintptr_t site_address(int kind) {
#ifdef ISAC_RETAIL_OBSERVER_TEST
 extern uintptr_t fixture_addresses[T5_SITE_COUNT];
 return fixture_addresses[kind];
#else
 return base+sites[kind].rva;
#endif
}
static int attest(void) {
#ifdef ISAC_RETAIL_OBSERVER_TEST
 (void)sites; (void)auxiliary; base=0; return 1;
#else
 unsigned i; unsigned char bytes[64]; IMAGE_DOS_HEADER dos; IMAGE_NT_HEADERS64 nt;
 base=(uintptr_t)GetModuleHandleW(NULL);
 if (!read_memory(base,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<0 || dos.e_lfanew>4096 ||
     !read_memory(base+dos.e_lfanew,&nt,sizeof(nt)) || nt.Signature!=IMAGE_NT_SIGNATURE ||
     nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 || nt.FileHeader.TimeDateStamp!=0x693b11ff ||
     nt.OptionalHeader.SizeOfImage!=0x7311000 || nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC) return 0;
 for (i=0;i<sizeof(sites)/sizeof(*sites);++i)
  if (!read_memory(base+sites[i].rva,bytes,sites[i].size) || memcmp(bytes,sites[i].bytes,sites[i].size)) return 0;
 for (i=0;i<sizeof(auxiliary)/sizeof(*auxiliary);++i)
  if (!read_memory(base+auxiliary[i].rva,bytes,auxiliary[i].size) || memcmp(bytes,auxiliary[i].bytes,auxiliary[i].size)) return 0;
 return 1;
#endif
}
static void emit(const T5Result *result) {
 LONG index;
#if !defined(ISAC_RETAIL_PROFILE) && !defined(ISAC_RETAIL_HANDSHAKE) && !defined(ISAC_RETAIL_TUTORIAL)
 if ((result->kind==1 ? InterlockedIncrement(&gates)>128 : InterlockedIncrement(&advertisements)>64)) {
  InterlockedExchange(&stopped,1); return;
 }
#endif
#if defined(ISAC_RETAIL_TUTORIAL)
 /* Producer is serialized by tutorial_lock; only the worker consumes. */
 index=InterlockedCompareExchange(&reserved,0,0);
 if((unsigned)index-consumed>=RESULT_LIMIT || index>=500000 || result->length>TUTORIAL_BYTES) {
  InterlockedIncrement(&tutorial_gaps); InterlockedExchange(&stopped,1); return;
 }
 InterlockedIncrement(&reserved); index%=RESULT_LIMIT;
 results[index].thread=GetCurrentThreadId(); results[index].tick=GetTickCount64();
 memcpy(&results[index].result,result,offsetof(TutorialResult,bytes)+result->length);
 InterlockedExchange(&results[index].ready,1);
#else
 index=InterlockedIncrement(&reserved)-1;
 if (index>=RESULT_LIMIT) { InterlockedExchange(&stopped,1); return; }
 results[index].thread=GetCurrentThreadId(); results[index].tick=GetTickCount64();
 results[index].result=*result; InterlockedExchange(&results[index].ready,1);
#endif
}
#if defined(ISAC_RETAIL_TUTORIAL) && !defined(ISAC_RETAIL_VAULT_STATE)
static void tutorial_observe(TutorialState *s,int kind,const TutorialRegs *r,uintptr_t b,TutorialRead read,TutorialEmit callback) {
 if(InterlockedCompareExchange(&tutorial_lock,1,0)) {
  InterlockedIncrement(&tutorial_gaps); InterlockedExchange(&stopped,1); return;
 }
 tutorial_handle(&tutorial_session,s,kind,r,b,read,callback);
 if(tutorial_session.failed) InterlockedExchange(&stopped,1);
 InterlockedExchange(&tutorial_lock,0);
}
#endif
static Thread *current_thread(void) {
 unsigned i; DWORD id=GetCurrentThreadId();
 /* Handles are retained until cleanup, preventing ID reuse. Entries publish
  * before peer resume. No locks, allocation or file IO in the VEH. */
 for (i=0;i<THREAD_LIMIT;++i)
  if (InterlockedCompareExchange(&threads[i].ready,0,0) && threads[i].id==id) return &threads[i];
 return NULL;
}
static int matches(Thread *t,CONTEXT *c) {
#if defined(ISAC_RETAIL_VAULT_STATE)
 return (c->Dr7 & 0xffff00ffULL)==0x5 && c->Dr0==site_address(t->state.slot[0]) &&
  c->Dr1==site_address(t->state.slot[1]) && !c->Dr2 && !c->Dr3;
#else
 return (c->Dr7 & 0xffff00ffULL)==0x55 && c->Dr0==site_address(t->state.slot[0]) &&
  c->Dr1==site_address(t->state.slot[1]) && c->Dr2==site_address(t->state.slot[2]) && c->Dr3==site_address(t->state.slot[3]);
#endif
}
static void set_slots(Thread *t,CONTEXT *c) {
#if defined(ISAC_RETAIL_VAULT_STATE)
 c->Dr0=site_address(t->state.slot[0]); c->Dr1=site_address(t->state.slot[1]);
 c->Dr2=c->Dr3=0; c->Dr7=(c->Dr7 & ~0xffff00ffULL)|0x5;
#else
 c->Dr0=site_address(t->state.slot[0]); c->Dr1=site_address(t->state.slot[1]);
 c->Dr2=site_address(t->state.slot[2]); c->Dr3=site_address(t->state.slot[3]);
 c->Dr7=(c->Dr7 & ~0xffff00ffULL)|0x55;
#endif
}
static void clear_slots(CONTEXT *c) {
 c->Dr0=c->Dr1=c->Dr2=c->Dr3=0; c->Dr7 &= ~0xffff00ffULL; c->Dr6 &= ~15ULL;
}
static LONG CALLBACK handler(EXCEPTION_POINTERS *exception) {
 CONTEXT *c=exception->ContextRecord, refreshed; CONTEXT *debug=c; Thread *t; int slot; T5Regs r;
 if (exception->ExceptionRecord->ExceptionCode!=EXCEPTION_SINGLE_STEP ||
     (c->Dr6 & 0xe000) || (c->EFlags & 0x100)) return EXCEPTION_CONTINUE_SEARCH;
 t=current_thread(); if (!t) return EXCEPTION_CONTINUE_SEARCH;
 /* Proton can deliver the first peer-armed trap with an empty cached debug
  * context. A real retained thread handle forces a server read; the current
  * thread pseudo-handle can return the same stale cache. Never infer ownership
  * from RIP alone, and leave the exception untouched unless readback verifies
  * all four slots, their modes and the actual triggering status bit. */
 if (!(c->Dr0 | c->Dr1 | c->Dr2 | c->Dr3 | c->Dr6 | c->Dr7)) {
  for (slot=0;slot<T5_SITE_COUNT;++slot) if (c->Rip==site_address(t->state.slot[slot])) break;
  if (slot==T5_SITE_COUNT || !t->handle) return EXCEPTION_CONTINUE_SEARCH;
  memset(&refreshed,0,sizeof(refreshed)); refreshed.ContextFlags=CONTEXT_DEBUG_REGISTERS;
  if (!GetThreadContext(t->handle,&refreshed)) return EXCEPTION_CONTINUE_SEARCH;
  debug=&refreshed;
 }
 if ((debug->Dr6 & 0xe000) || !(debug->Dr6 & 15) || !matches(t,debug)) return EXCEPTION_CONTINUE_SEARCH;
 for (slot=0;slot<T5_SITE_COUNT;++slot) if ((debug->Dr6 & (1u<<slot)) && c->Rip==site_address(t->state.slot[slot])) break;
 if (slot==T5_SITE_COUNT) return EXCEPTION_CONTINUE_SEARCH;
 if (debug!=c) {
  c->Dr0=debug->Dr0; c->Dr1=debug->Dr1; c->Dr2=debug->Dr2; c->Dr3=debug->Dr3;
  c->Dr6=debug->Dr6; c->Dr7=debug->Dr7; c->ContextFlags|=CONTEXT_DEBUG_REGISTERS;
  InterlockedIncrement(&debug_context_refreshes);
 }
#if defined(ISAC_RETAIL_TUTORIAL)
 if (InterlockedIncrement(&hits)>
#if defined(ISAC_RETAIL_VAULT_STATE)
     10000000
#else
     1000000
#endif
     || GetTickCount64()>=deadline) InterlockedExchange(&stopped,1);
#else
 if (InterlockedIncrement(&hits)>12000 || GetTickCount64()>=deadline) InterlockedExchange(&stopped,1);
#endif
 if (InterlockedCompareExchange(&stopped,0,0)) clear_slots(c);
 else {
  r=(T5Regs){c->Rsp,c->Rbp,c->Rax,c->Rbx,c->Rcx,c->Rdx,c->Rsi,c->Rdi,c->R13,c->R14};
  t5_handle(&t->state,t->state.slot[slot],&r,base,read_memory,emit);
  set_slots(t,c); c->Dr6 &= ~15ULL;
 }
 c->EFlags |= 0x10000; /* RF: execute observed instruction; no IP/GPR/TF edits. */
 return EXCEPTION_CONTINUE_EXECUTION;
}
static int write_text(const char *text) {
 DWORD size=(DWORD)strlen(text),written=0;
 if (!WriteFile(output,text,size,&written,NULL) || written!=size) {
#if defined(ISAC_RETAIL_TUTORIAL)
  InterlockedIncrement(&tutorial_gaps);
#endif
  InterlockedExchange(&stopped,1); return 0;
 }
 return 1;
}
#if defined(ISAC_RETAIL_TUTORIAL)
static int tutorial_write(const void *bytes,DWORD size) {
 DWORD written=0;
 if(!WriteFile(tutorial_payload,bytes,size,&written,NULL) || written!=size) {
  InterlockedIncrement(&tutorial_gaps); InterlockedExchange(&stopped,1); return 0;
 }
 return 1;
}
static void drain(void) {
 while(consumed<(unsigned)InterlockedCompareExchange(&reserved,0,0)) {
  unsigned index=consumed%RESULT_LIMIT; Result *q=&results[index];
  uint64_t times[2]; uint32_t fields[4]; char text[320];
  if(!InterlockedCompareExchange(&q->ready,0,0)) break;
  if(tutorial_bytes+32+q->result.length>67108864) {
   InterlockedIncrement(&tutorial_gaps); InterlockedExchange(&stopped,1);
   break;
  }
  times[0]=consumed+1; times[1]=q->tick;
  fields[0]=q->result.kind; fields[1]=q->result.stream; fields[2]=q->result.length; fields[3]=q->result.aux;
  if(!tutorial_write(times,sizeof(times)) || !tutorial_write(fields,sizeof(fields)) ||
     (fields[2] && !tutorial_write(q->result.bytes,fields[2]))) break;
  tutorial_bytes+=32+fields[2]; ++tutorial_records;
  if(fields[0]>=3 || fields[3]) {
#if defined(ISAC_RETAIL_VAULT_STATE)
   if(fields[0]>=10 && fields[0]<=14) {
    uint32_t caller=0;
    if(fields[2]==4) memcpy(&caller,q->result.bytes,4);
    snprintf(text,sizeof(text),"{\"event\":\"vault_state\",\"kind\":%u,\"sequence\":%u,\"tick_ms\":%llu,\"owner\":%u,\"value\":%u,\"caller_rva\":%u}\n",
     fields[0],consumed+1,(unsigned long long)q->tick,fields[1],fields[3],caller);
    write_text(text);
   } else
#endif
   {
   snprintf(text,sizeof(text),"{\"event\":\"observation\",\"kind\":%u,\"sequence\":%u,\"tick_ms\":%llu,\"stream\":%u,\"bytes\":%u,\"aux\":%u}\n",
    fields[0],consumed+1,(unsigned long long)q->tick,fields[1],fields[2],fields[3]); write_text(text);
   }
  }
  InterlockedExchange(&q->ready,0); ++consumed;
 }
 if(!FlushFileBuffers(tutorial_payload) || !FlushFileBuffers(output)) {
  InterlockedIncrement(&tutorial_gaps); InterlockedExchange(&stopped,1);
 }
}
static void tutorial_poll_keys(void) {
 static const int keys[]={VK_NUMPAD1,VK_NUMPAD2,VK_NUMPAD3,VK_NUMPAD4,VK_NUMPAD5,
  VK_NUMPAD6,VK_NUMPAD7,VK_NUMPAD8,VK_NUMPAD9,VK_NUMPAD0,VK_DECIMAL};
 static const unsigned marker_keys[]={1,2,3,4,5,6,7,8,9,0,10};
 static const char *labels[]={"world_loaded","objective_started","objective_completed",
  "ai_spawned","safe_house_entered","merchant_accessed","coordinator_voice_onset",
  "vault_attempt","combat_started","notable_enemy_action","combat_ended"};
 unsigned i,down=0,edges; DWORD pid=0; char text[256];
 HWND window=GetForegroundWindow(); if(window) GetWindowThreadProcessId(window,&pid);
 for(i=0;i<11;++i) if(GetAsyncKeyState(keys[i])&0x8000) down|=1u<<i;
 edges=tutorial_key_edges(&tutorial_keys,down,pid==GetCurrentProcessId());
 for(i=0;i<11;++i) if(edges&(1u<<i)) {
  snprintf(text,sizeof(text),"{\"event\":\"marker\",\"index\":%u,\"key\":%u,\"label\":\"%s\",\"tick_ms\":%llu}\n",
   ++tutorial_markers,marker_keys[i],labels[i],(unsigned long long)GetTickCount64()); write_text(text);
#if defined(ISAC_RETAIL_VAULT_STATE)
  if(marker_keys[i]==8) vault_poll(base,read_memory,emit,1);
#endif
 }
 if(edges && !FlushFileBuffers(output)) { InterlockedIncrement(&tutorial_gaps); InterlockedExchange(&stopped,1); }
}
#elif defined(ISAC_RETAIL_HANDSHAKE)
static void write_hash(const unsigned char *value) {
 static const char digits[]="0123456789abcdef"; char text[65]; unsigned i;
 for(i=0;i<32;++i) { text[2*i]=digits[value[i]>>4]; text[2*i+1]=digits[value[i]&15]; }
 text[64]=0; write_text(text);
}
static void drain(void) {
 static const char *names[]={"auth_reply","join_reply","instance_connect","game_connect_reply"};
 while(consumed<RESULT_LIMIT && InterlockedCompareExchange(&results[consumed].ready,0,0)) {
  const HandshakeResult *r=&results[consumed].result; char text[512]; unsigned i;
  snprintf(text,sizeof(text),"{\"event\":\"%s\",\"encoding\":\"handshake-metadata-v1\",\"sequence\":%u,\"thread\":%u,\"tick_ms\":%llu,\"complete\":%s,\"request_id\":%u,\"flag\":%u,\"uint32_c\":%u,\"proxy_id\":%u,\"extra\":%u,\"tokens\":[",
   names[r->kind],consumed+1,(unsigned)results[consumed].thread,(unsigned long long)results[consumed].tick,
   r->complete?"true":"false",r->request_id,r->flag,r->uint32_c,r->proxy_id,r->extra);
  write_text(text);
  for(i=0;i<r->count;++i) {
   snprintf(text,sizeof(text),"%s{\"slot\":%u,\"length\":%u,\"deadline_epoch_seconds\":%llu,\"remaining_seconds_estimate\":%llu,\"sha256\":\"",
    i?",":"",i+1,r->tokens[i].length,(unsigned long long)r->tokens[i].deadline,(unsigned long long)r->tokens[i].remaining);
   write_text(text); write_hash(r->tokens[i].sha256); write_text("\"}");
  }
  write_text("],\"strings\":[");
  for(i=0;i<3;++i) {
   snprintf(text,sizeof(text),"%s{\"slot\":%u,\"length\":%u,\"sha256\":\"",i?",":"",i+1,r->string_lengths[i]);
   write_text(text); write_hash(r->string_hashes[i]); write_text("\"}");
  }
  snprintf(text,sizeof(text),"],\"prefix_zero\":%s,\"prefix_sha256\":\"",r->prefix_zero?"true":"false");
  write_text(text); write_hash(r->prefix_hash); write_text("\"}\n");
  if(!FlushFileBuffers(output)) InterlockedExchange(&stopped,1);
  ++consumed;
 }
}
#elif defined(ISAC_RETAIL_PROFILE)
static void drain(void) {
#if defined(ISAC_RETAIL_FINALIZATION)
 static const char *names[]={"create_request","create_reply","profile_list","agent_submit"};
#else
 static const char *names[]={"create_request","create_reply","profile_list","token_handoff"};
#endif
 static const char digits[]="0123456789abcdef";
 while(consumed<RESULT_LIMIT && InterlockedCompareExchange(&results[consumed].ready,0,0)) {
  const ProfileResult *r=&results[consumed].result;
  char text[320], hex[1025]; unsigned pos,i,n;
  snprintf(text,sizeof(text),"{\"event\":\"%s\",\"sequence\":%u,\"thread\":%u,\"tick_ms\":%llu,\"complete\":%s,\"count\":%u,\"encoding\":\"%s\",\"data_hex\":\"",
    names[r->kind],consumed+1,(unsigned)results[consumed].thread,(unsigned long long)results[consumed].tick,
    r->complete?"true":"false",r->count,
    r->kind==3?
#if defined(ISAC_RETAIL_FINALIZATION)
    "character-id-only-v1":
#else
    "handoff-metadata-v1":
#endif
    "reconstructed-body-v1");
  write_text(text);
  for(pos=0;pos<r->length;pos+=n) {
   n=r->length-pos; if(n>512) n=512;
   for(i=0;i<n;++i) { hex[2*i]=digits[r->bytes[pos+i]>>4]; hex[2*i+1]=digits[r->bytes[pos+i]&15]; }
   hex[2*n]=0; write_text(hex);
  }
  write_text("\"}\n"); ++consumed;
 }
}
#else
static void write_bytes(const T5Bytes *b) {
 char hex[1027]; const char *digits="0123456789abcdef"; int i;
 if (b->length<0 || b->length>511) { write_text("null"); return; }
 hex[0]='"';
 for (i=0;i<b->length;++i) { hex[1+i*2]=digits[b->bytes[i]>>4]; hex[2+i*2]=digits[b->bytes[i]&15]; }
 hex[1+b->length*2]='"'; hex[2+b->length*2]=0; write_text(hex);
}
static unsigned owner_id(uintptr_t owner) {
 unsigned i;
 for (i=0;i<owner_count;++i) if (owners[i]==owner) return i+1;
 if (owner_count==RESULT_LIMIT) return 0;
 owners[owner_count++]=owner; return owner_count;
}
static void drain(void) {
 while (consumed<RESULT_LIMIT && InterlockedCompareExchange(&results[consumed].ready,0,0)) {
  T5Result *r=&results[consumed].result; char text[768]; unsigned i;
  if (r->kind==1) {
   snprintf(text,sizeof(text),"{\"event\":\"gate\",\"owner\":%u,\"gate_empty\":%d,\"registry_count\":%d,\"name_hex\":",owner_id(r->owner),r->gate_empty,r->before);
   write_text(text); write_bytes(&r->name); write_text("}\n");
  } else {
   snprintf(text,sizeof(text),"{\"event\":\"type5\",\"version\":1,\"root_type\":5,\"owner\":%u,"
    "\"complete_fields\":%s,\"parse_success\":%s,\"consumer_accepted\":%s,\"name_declared_length\":%d,"
    "\"wire_attribute_count\":%d,\"parsed_attribute_count\":%d,\"registry_before\":%d,\"registry_after\":%d,"
    "\"record_written\":%s,\"copy_equal\":%d,\"name_hex\":",owner_id(r->owner),r->complete?"true":"false",
    r->parsed?"true":"false",r->accepted?"true":"false",r->declared,r->wire_count,r->parsed_count,
    r->before,r->after,r->written?"true":"false",r->copy_equal);
   write_text(text); write_bytes(&r->name); write_text(",\"record_name_hex\":"); write_bytes(&r->record_name); write_text(",\"attributes\":[");
   for (i=0;i<r->pairs;++i) {
    snprintf(text,sizeof(text),"%s{\"index\":%u,\"key_hex\":",i?",":"",r->pair[i].index);
    write_text(text); write_bytes(&r->pair[i].key); write_text(",\"value_hex\":"); write_bytes(&r->pair[i].value); write_text("}");
   }
   write_text("]}\n");
  }
  ++consumed;
 }
}
#endif
static int arm_thread(HANDLE h,DWORD id) {
 CONTEXT before,after; Thread *t=&threads[thread_count]; int success=0;
 t->id=id; t->handle=h; t5_reset(&t->state);
 memset(&before,0,sizeof(before)); before.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if (SuspendThread(h)==(DWORD)-1) return 0;
 /* No allocation, logging, locks or IO while a peer is stopped. */
 if (!GetThreadContext(h,&before)) goto resume;
 if ((before.Dr7 & 255) || before.Dr0 || before.Dr1 || before.Dr2 || before.Dr3) { ++conflicts; goto resume; }
 after=before; set_slots(t,&after); InterlockedExchange(&t->ready,1);
 if (!SetThreadContext(h,&after) || !GetThreadContext(h,&after) || !matches(t,&after)) {
  if (SetThreadContext(h,&before)) InterlockedExchange(&t->ready,0);
  else { success=1; InterlockedExchange(&stopped,1); } /* Retain handler ownership if rollback failed. */
  goto resume;
 }
 success=1;
resume:
 if (ResumeThread(h)==(DWORD)-1) { ++resume_failed; InterlockedExchange(&stopped,1); }
 return success;
}
static void sweep(void) {
 HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0); THREADENTRY32 entry; unsigned i;
 DWORD self=GetCurrentThreadId(),pid=GetCurrentProcessId();
 if (snapshot==INVALID_HANDLE_VALUE) { ++failed; return; }
 memset(&entry,0,sizeof(entry)); entry.dwSize=sizeof(entry);
 if (Thread32First(snapshot,&entry)) do {
  if (entry.th32OwnerProcessID!=pid || entry.th32ThreadID==self) continue;
  for (i=0;i<thread_count;++i) if (threads[i].id==entry.th32ThreadID) break;
  if (i<thread_count) continue;
  if (thread_count==THREAD_LIMIT) {
#if defined(ISAC_RETAIL_TUTORIAL)
   InterlockedIncrement(&tutorial_gaps);
#endif
   InterlockedExchange(&stopped,1); break;
  }
  {
   HANDLE h=OpenThread(THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION|SYNCHRONIZE,FALSE,entry.th32ThreadID);
   if (h) {
    if (arm_thread(h,entry.th32ThreadID)) { threads[thread_count++].handle=h; ++armed; }
    else { ++failed; CloseHandle(h); }
   } else ++failed;
  }
 } while (Thread32Next(snapshot,&entry));
 CloseHandle(snapshot);
}
static void disarm(void) {
 unsigned i;
 for (i=0;i<thread_count;++i) {
  HANDLE h=threads[i].handle; CONTEXT c; int safe=0;
  memset(&c,0,sizeof(c)); c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
  if (WaitForSingleObject(h,0)==WAIT_OBJECT_0) safe=1;
  else if (SuspendThread(h)!=(DWORD)-1) {
   if (GetThreadContext(h,&c)) {
    if (matches(&threads[i],&c)) { clear_slots(&c); safe=SetThreadContext(h,&c); }
    else if (!(c.Dr7 & 255) && !c.Dr0 && !c.Dr1 && !c.Dr2 && !c.Dr3) safe=1;
   }
   pending+=!!threads[i].state.active;
   if (ResumeThread(h)==(DWORD)-1) ++resume_failed;
  }
  if (safe) { InterlockedExchange(&threads[i].ready,0); CloseHandle(h); }
  else ++failed; /* Retain handle and handler for any still-owned trap. */
 }
}
static DWORD WINAPI worker(void *unused) {
 ULONGLONG next_report=0,until=GetTickCount64()+30000; char text[384]; (void)unused;
 write_text("{\"event\":\"starting\",\"attestation_timeout_ms\":30000}\n");
 while (!attest() && GetTickCount64()<until && !stopped) Sleep(100);
 if (!attest()) { write_text("{\"event\":\"refused\",\"reason\":\"runtime-signatures\"}\n"); goto done; }
 if (!AddVectoredExceptionHandler(1,handler)) { write_text("{\"event\":\"refused\",\"reason\":\"veh\"}\n"); goto done; }
#if defined(ISAC_RETAIL_TUTORIAL)
 deadline=GetTickCount64()+1200000;
 snprintf(text,sizeof(text),"{\"event\":\"tutorial_ready\",\"tick_ms\":%llu,\"duration_ms\":1200000,\"marker_poll_ms\":100}\n",(unsigned long long)GetTickCount64()); write_text(text);
#elif defined(ISAC_RETAIL_HANDSHAKE)
 deadline=GetTickCount64()+300000;
#elif defined(ISAC_RETAIL_PROFILE)
 deadline=GetTickCount64()+1200000;
#else
 deadline=GetTickCount64()+180000;
#endif
#if defined(ISAC_RETAIL_VAULT_STATE)
 write_text("{\"event\":\"ready\",\"slots\":2,\"coverage\":\"sampled-threads\",\"interval_ms\":100,\"state\":\"CoverVaultIsAllowed\"}\n");
#else
 write_text("{\"event\":\"ready\",\"slots\":4,\"coverage\":\"sampled-threads\",\"interval_ms\":100}\n");
#endif
 while (!InterlockedCompareExchange(&stopped,0,0) && GetTickCount64()<deadline) {
  sweep(); drain();
#if defined(ISAC_RETAIL_TUTORIAL)
 #if defined(ISAC_RETAIL_VAULT_STATE)
  vault_poll(base,read_memory,emit,0);
 #endif
  tutorial_poll_keys();
#endif
  if (GetTickCount64()>=next_report) {
   snprintf(text,sizeof(text),"{\"event\":\"coverage\",\"armed\":%u,\"conflicts\":%u,\"failures\":%u,\"resume_failures\":%u,\"hits\":%ld,\"records\":%u}\n",armed,conflicts,failed,resume_failed,hits,consumed);
   write_text(text); next_report=GetTickCount64()+5000;
  }
  Sleep(100);
 }
 InterlockedExchange(&stopped,1); disarm(); drain();
#if defined(ISAC_RETAIL_TUTORIAL)
#if defined(ISAC_RETAIL_VAULT_STATE)
 snprintf(text,sizeof(text),"{\"event\":\"vault_end\",\"index\":%u,\"index_valid\":%s,\"owners\":%u,\"local_owner_seen\":%s,\"markers\":%u,\"gaps\":%ld}\n",
  vault_raw_index,vault_index_reported?"true":"false",vault_owner_count,
  vault_local_owner?"true":"false",tutorial_markers,tutorial_gaps); write_text(text);
#else
 snprintf(text,sizeof(text),"{\"event\":\"tutorial_end\",\"selected_stream\":%u,\"connect_reply_correlated\":%s,\"filtered_envelopes\":%u,\"records\":%u,\"payload_bytes\":%llu,\"markers\":%u,\"gaps\":%ld,\"core_failed\":%u}\n",
  tutorial_session.selected,tutorial_session.confirmed?"true":"false",tutorial_session.filtered,tutorial_records,(unsigned long long)tutorial_bytes,tutorial_markers,tutorial_gaps,tutorial_session.failed); write_text(text);
#endif
#endif
 snprintf(text,sizeof(text),"{\"event\":\"end\",\"hits\":%ld,\"records\":%u,\"pending\":%u,\"resume_failures\":%u,\"debug_context_refreshes\":%ld}\n",hits,consumed,pending,resume_failed,debug_context_refreshes); write_text(text);
done:
#if defined(ISAC_RETAIL_TUTORIAL)
 if(tutorial_payload!=INVALID_HANDLE_VALUE) { FlushFileBuffers(tutorial_payload); CloseHandle(tutorial_payload); tutorial_payload=INVALID_HANDLE_VALUE; }
#endif
 CloseHandle(output); output=INVALID_HANDLE_VALUE;
 /* Keep the pinned module/VEH alive if thread cleanup failed. */
 return 0;
}
void isac_stack_probe_initialize(const WCHAR *a,const WCHAR *b,const WCHAR *c,const WCHAR *d) {
 WCHAR flag[8],directory[MAX_PATH],path[MAX_PATH]; DWORD size; HANDLE thread; HMODULE pinned;
 (void)a;(void)b;(void)c;(void)d;
#if defined(ISAC_RETAIL_TUTORIAL)
#if defined(ISAC_RETAIL_VAULT_STATE)
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_VAULT_STATE",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#elif defined(ISAC_RETAIL_PRESENTATION)
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_PRESENTATION",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#else
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_TUTORIAL",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#endif
#elif defined(ISAC_RETAIL_HANDSHAKE)
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_HANDSHAKE",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#elif defined(ISAC_RETAIL_PROFILE)
#if defined(ISAC_RETAIL_FINALIZATION)
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_FINALIZATION",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#else
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_PROFILE",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#endif
#else
 if (GetEnvironmentVariableW(L"ISAC_RETAIL_TYPE5",flag,8)!=1 || flag[0]!=L'1' || InterlockedCompareExchange(&begun,1,0)) return;
#endif
 size=GetEnvironmentVariableW(L"ISAC_RETAIL_CAPTURE_DIR",directory,MAX_PATH);
 if (!size || size>=MAX_PATH-40 || GetFileAttributesW(directory)==INVALID_FILE_ATTRIBUTES) return;
#if defined(ISAC_RETAIL_TUTORIAL)
#if defined(ISAC_RETAIL_VAULT_STATE)
 swprintf(path,MAX_PATH,L"%ls\\vault-state-%lu.jsonl",directory,GetCurrentProcessId());
#elif defined(ISAC_RETAIL_PRESENTATION)
 swprintf(path,MAX_PATH,L"%ls\\presentation-%lu.jsonl",directory,GetCurrentProcessId());
#else
 swprintf(path,MAX_PATH,L"%ls\\tutorial-%lu.jsonl",directory,GetCurrentProcessId());
#endif
#elif defined(ISAC_RETAIL_HANDSHAKE)
 swprintf(path,MAX_PATH,L"%ls\\handshake-%lu.jsonl",directory,GetCurrentProcessId());
#elif defined(ISAC_RETAIL_PROFILE)
#if defined(ISAC_RETAIL_FINALIZATION)
 swprintf(path,MAX_PATH,L"%ls\\finalization-%lu.jsonl",directory,GetCurrentProcessId());
#else
 swprintf(path,MAX_PATH,L"%ls\\profile-%lu.jsonl",directory,GetCurrentProcessId());
#endif
#else
 swprintf(path,MAX_PATH,L"%ls\\type5-%lu.jsonl",directory,GetCurrentProcessId());
#endif
 output=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if (output==INVALID_HANDLE_VALUE) return;
#if defined(ISAC_RETAIL_TUTORIAL)
#if defined(ISAC_RETAIL_VAULT_STATE)
 swprintf(path,MAX_PATH,L"%ls\\vault-state-%lu.bin",directory,GetCurrentProcessId());
#elif defined(ISAC_RETAIL_PRESENTATION)
 swprintf(path,MAX_PATH,L"%ls\\presentation-%lu.bin",directory,GetCurrentProcessId());
#else
 swprintf(path,MAX_PATH,L"%ls\\tutorial-%lu.bin",directory,GetCurrentProcessId());
#endif
 tutorial_payload=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(tutorial_payload==INVALID_HANDLE_VALUE) { CloseHandle(output); output=INVALID_HANDLE_VALUE; return; }
 if(!tutorial_write("ISACTUT1\x01\0\0\0\x10\0\0\0",16)) goto tutorial_failed;
#endif
 if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
      (LPCWSTR)(uintptr_t)isac_stack_probe_initialize,&pinned)) {
#if defined(ISAC_RETAIL_TUTORIAL)
  goto tutorial_failed;
#else
  CloseHandle(output); output=INVALID_HANDLE_VALUE; return;
#endif
 }
 thread=CreateThread(NULL,0,worker,NULL,0,NULL);
 if (thread) CloseHandle(thread);
 else { write_text("{\"event\":\"refused\",\"reason\":\"worker\"}\n"); CloseHandle(output); output=INVALID_HANDLE_VALUE; }
#if defined(ISAC_RETAIL_TUTORIAL)
 if(thread) return;
tutorial_failed:
 if(tutorial_payload!=INVALID_HANDLE_VALUE) { CloseHandle(tutorial_payload); tutorial_payload=INVALID_HANDLE_VALUE; }
 if(output!=INVALID_HANDLE_VALUE) { CloseHandle(output); output=INVALID_HANDLE_VALUE; }
#endif
}
void isac_stack_probe_shutdown(void) { InterlockedExchange(&stopped,1); }
