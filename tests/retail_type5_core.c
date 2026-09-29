#include <assert.h>
#include <stdio.h>
#include "../src/uplay_probe/retail_type5.h"
static struct {
 unsigned char stack[2048], owner[2048], reader[64], record[1024];
 uint64_t temp_table[16], record_table[16], key_table[16], count_table[16];
 unsigned char name[64], key[64], value[512], copied[64];
} mem;
static T5State state;
static T5Regs regs;
static T5Result last;
static unsigned emissions;
static uintptr_t stack;
static const uintptr_t base=0x140000000ULL;
static int read_mem(uintptr_t p,void *out,size_t n) {
 uintptr_t lo=(uintptr_t)&mem, hi=lo+sizeof(mem);
 if (p<lo || p>hi || n>hi-p) return 0;
 memcpy(out,(const void *)p,n); return 1;
}
static void put(uintptr_t p,uint64_t v,size_t n) { memcpy((void *)p,&v,n); }
static void string(uintptr_t p,uint64_t *table,unsigned offset,unsigned char *data) {
 put(p,(uintptr_t)table,8); put(p+offset,(uintptr_t)data,8);
}
static void emit_result(const T5Result *r) { last=*r; ++emissions; }
static void hit(int site) {
 T5Regs before=regs;
 t5_handle(&state,site,&regs,base,read_mem,emit_result);
 assert(!memcmp(&before,&regs,sizeof(regs)));
}
static void setup(void) {
 memset(&mem,0,sizeof(mem)); memset(&regs,0,sizeof(regs)); t5_reset(&state); emissions=0;
 stack=(uintptr_t)mem.stack+0x200;
 mem.temp_table[2]=base+0x12920; mem.record_table[2]=base+0x69160;
 mem.key_table[2]=base+0x12860; mem.count_table[14]=base+0x5b9d0;
 put((uintptr_t)mem.owner+0xb8,(uintptr_t)mem.count_table,8);
 put((uintptr_t)mem.reader+0x10,5,2);
 string((uintptr_t)mem.record+0x358,mem.record_table,0x30,mem.copied);
 regs.rsp=stack; regs.rbp=stack+0x100; regs.rcx=stack+0x20;
 regs.rdx=(uintptr_t)mem.reader; regs.r14=(uintptr_t)mem.owner;
 hit(T5_READ); assert(state.active);
}
static void start(const char *name,int length,int count) {
 setup(); memcpy(mem.name,name,(size_t)length);
 regs.rsp=stack-0x60; regs.rdi=(uintptr_t)mem.reader; regs.rsi=stack+0x20; regs.rbx=64;
 put(regs.rsp+0x48,(unsigned)length,4); hit(T5_NAME);
 string(stack+0x20,mem.temp_table,0x48,mem.name);
 put(stack+0x78,(uintptr_t)mem.count_table,8); put(stack+0x80,(unsigned)count,4);
 regs.rsp=stack-0x100; regs.rbp=stack-0x97; regs.rsi=(uintptr_t)mem.reader; regs.r14=stack+0x78;
 put(regs.rbp+0x77,(unsigned)count,4); hit(T5_COUNT);
}
static void pair(unsigned index,const char *key,int kn,const char *value,int vn) {
 memcpy(mem.key,key,(size_t)kn); memcpy(mem.value,value,(size_t)vn);
 regs.rdi=index; put(regs.rbp+0x67,(unsigned)kn,4); hit(T5_KEY);
 string(regs.rbp-0x49,mem.key_table,0x18,mem.key);
 string(regs.rbp-0x21,mem.record_table,0x30,mem.value);
 put(regs.rbp+0x67,(unsigned)vn,4); hit(T5_PAIR);
}
static void finish(int parsed,int accepted,int copy) {
 regs.rsp=stack; regs.rbp=stack+0x100; regs.r14=(uintptr_t)mem.owner;
 regs.rax=parsed; hit(T5_PARSED);
 if (copy) {
  regs.rcx=(uintptr_t)mem.record+0x358; regs.rdx=(uintptr_t)mem.name;
  put(regs.rbp+0x300,(uintptr_t)mem.record,8); hit(T5_COPY);
  memcpy(mem.copied,mem.name,64); hit(T5_WRITTEN);
 }
 regs.rbx=accepted; put((uintptr_t)mem.owner+0xc0,accepted?1:0,4); hit(T5_DONE);
 assert(emissions==1 && state.slot[0]==T5_READ && state.slot[1]==T5_NAME && state.slot[2]==T5_COPY);
}
int main(void) {
 start("service",7,0); finish(1,1,1);
 assert(last.complete && last.written && last.copy_equal==1 && last.pairs==0 && last.after==1);
 start("wire\0tail",9,2); pair(0,"type",4,"auth",4); pair(1,"type",4,"other\0value",11);
 put(stack+0x80,1,4); finish(1,1,1);
 assert(last.complete && last.pairs==2 && last.parsed_count==1 && last.name.length==9 && last.copy_equal==1);
 assert(last.pair[1].value.length==11 && !memcmp(last.pair[1].value.bytes,"other\0value",11));
 start("service",7,2); pair(0,"type",4,"auth",4); finish(1,1,0); assert(!last.complete && last.copy_equal==-1);
 start("service",7,0); mem.temp_table[2]=base+0x12940; finish(1,1,0); assert(!last.complete && last.name.length==-1);
 start("service",7,25); finish(0,0,0); assert(!last.complete && !last.accepted);
 start("service",7,0); state.result.declared=64; finish(1,1,0); assert(!last.complete && last.name.length==-1);
 setup(); regs.rax=0; hit(T5_PARSED); regs.rbx=0; hit(T5_DONE);
 assert(emissions==1 && !last.complete && state.slot[0]==T5_READ);
 setup(); regs.rsp=stack-0x68; regs.rdi=(uintptr_t)mem.reader; regs.rsi=stack+0x20; regs.rbx=64;
 hit(T5_NAME); assert(state.slot[1]==T5_NAME && state.result.declared==-1);
 start("service",7,0); regs.rsp=stack; regs.r14=(uintptr_t)mem.owner; regs.rax=1; hit(T5_PARSED);
 regs.rcx=(uintptr_t)mem.record+0x358; regs.rdx=(uintptr_t)mem.name; regs.rbp=stack+0x100;
 put(regs.rbp+0x300,(uintptr_t)mem.record+8,8); hit(T5_COPY); assert(!state.copy_pending);
 puts("type5 core: 9 bounded field, pairing, failure and exact-byte scenarios passed");
 return 0;
}
