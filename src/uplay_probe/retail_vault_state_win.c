/* Read-only retail action-state value observer. No game state is changed. */
#include "stack_probe.h"
#define ISAC_RETAIL_TUTORIAL 1
#define ISAC_RETAIL_VAULT_STATE 1
#include "retail_tutorial.h"
#define T5Result TutorialResult
#define T5State TutorialState
#define T5Regs TutorialRegs
#define T5_SITE_COUNT 2
#define t5_reset tutorial_reset
#define t5_handle vault_observe

typedef struct { uintptr_t address; unsigned id, last, seen, caller; } VaultOwner;
static VaultOwner vault_owners[32];
static unsigned vault_owner_count, vault_index=0xffffffffu, vault_index_reported;
static unsigned vault_raw_index=0xffffffffu, vault_raw_seen;
static uintptr_t vault_local_owner;
static volatile LONG vault_lock;

static unsigned vault_owner_id(uintptr_t address) {
 unsigned i;
 for(i=0;i<vault_owner_count;++i) if(vault_owners[i].address==address) return i+1;
 if(!address || vault_owner_count==32) return 0;
 i=vault_owner_count++;
 vault_owners[i].address=address; vault_owners[i].id=i+1;
 vault_owners[i].seen=0;
 return i+1;
}
static int vault_value(uintptr_t owner,unsigned index,TutorialRead read,unsigned *value) {
 uintptr_t address;
 if(!owner || index>511 || owner>UINTPTR_MAX-0x4c-4*index) return 0;
 address=owner+0x4c+4*index;
 return read(address,value,4);
}
static void vault_record(TutorialState *s,TutorialEmit emit,unsigned kind,
                         unsigned owner,unsigned value,unsigned caller) {
 TutorialResult *o=&s->result;
 o->kind=kind; o->stream=owner; o->aux=value; o->length=4;
 memcpy(o->bytes,&caller,4); emit(o);
}
static void vault_observe(TutorialState *s,int kind,const TutorialRegs *r,
                          uintptr_t base,TutorialRead read,TutorialEmit emit) {
 unsigned index,value,id,caller=0; uintptr_t return_address=0;
 if(InterlockedCompareExchange(&vault_lock,1,0)) return;
 index=vault_index;
 if(kind==1) {
  /* At 0x19be5e4 RAX is the action-state owner resolved through the
   * client-local singleton, before the script node calls the array getter. */
  id=vault_owner_id(r->rax);
  if(id && vault_local_owner!=r->rax) {
   vault_local_owner=r->rax;
   vault_record(s,emit,12,id,0,0);
  }
 } else if(kind==0 && index<=511 && r->rdx && read(r->rdx,&value,4)) {
  id=vault_owner_id(r->rcx);
  if(id) {
   VaultOwner *owner=&vault_owners[id-1];
   if(read(r->rsp,&return_address,8) && return_address>=base+0x1000 &&
      return_address<base+0x2901000) caller=(unsigned)(return_address-base);
   owner->caller=caller;
   if(value==index && vault_value(r->rcx,index,read,&value)) {
    if(!owner->seen || owner->last!=value) {
     owner->last=value; owner->seen=1;
     vault_record(s,emit,11,id,value,caller);
    }
   }
  }
 }
 InterlockedExchange(&vault_lock,0);
}
static void vault_poll(uintptr_t base,TutorialRead read,TutorialEmit emit,int marker) {
 TutorialState state; unsigned i,index,value,id;
 if(InterlockedCompareExchange(&vault_lock,1,0)) return;
 tutorial_reset(&state);
 if(read(base+0x47cdb90,&index,4) &&
    (!vault_raw_seen || index!=vault_raw_index)) {
  vault_raw_seen=1;
  vault_raw_index=index;
  vault_record(&state,emit,10,0,index,0);
  vault_index=index<=511?index:0xffffffffu;
  vault_index_reported=index<=511;
 }
 if(vault_index_reported && vault_index<=511) {
  for(i=0;i<vault_owner_count;++i) {
   VaultOwner *owner=&vault_owners[i];
   id=owner->id;
   if(!marker && owner->address!=vault_local_owner) continue;
   if(!vault_value(owner->address,vault_index,read,&value)) continue;
   if(marker || !owner->seen || owner->last!=value) {
    owner->last=value; owner->seen=1;
    vault_record(&state,emit,marker?13:14,id,value,owner->caller);
   }
  }
 }
 InterlockedExchange(&vault_lock,0);
}
#include "retail_type5_win.c"
