#define ISAC_RETAIL_OBSERVER_TEST 1
#include "../src/uplay_probe/retail_type5_win.c"
unsigned char owner[0x700], reader[0x40], record[0x400];
uintptr_t temporary_table[16], record_table[16], key_table[16], collection_table[20];
char service_name[]="fixture-service-name", empty_name[]="", type_key[]="type", auth_value[]="auth";
#define DECLARE(name) extern void fixture_##name(void)
DECLARE(consumer_read); DECLARE(parser_done); DECLARE(consumer_done); DECLARE(name_length);
DECLARE(attribute_count); DECLARE(key_length); DECLARE(attribute_pair); DECLARE(producer_copy);
DECLARE(producer_written); DECLARE(name_gate); DECLARE(run);
uintptr_t fixture_addresses[T5_SITE_COUNT];
static void pointer(unsigned char *p,uintptr_t value) { memcpy(p,&value,8); }
static volatile LONG foreign_seen;
static HANDLE conflict_ready, conflict_release;
static DWORD WINAPI conflict_thread(void *unused) {
 CONTEXT c; (void)unused;
 memset(&c,0,sizeof(c)); c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if (!GetThreadContext(GetCurrentThread(),&c)) return 12;
 c.Dr0=(uintptr_t)fixture_name_gate; c.Dr7=(c.Dr7 & ~0xffff00ffULL)|1;
 if (!SetThreadContext(GetCurrentThread(),&c)) return 13;
 SetEvent(conflict_ready); WaitForSingleObject(conflict_release,10000);
 if (!GetThreadContext(GetCurrentThread(),&c) || c.Dr0!=(uintptr_t)fixture_name_gate || (c.Dr7 & 255)!=1) return 14;
 c.Dr0=0; c.Dr7 &= ~0xffff00ffULL;
 if (!SetThreadContext(GetCurrentThread(),&c)) return 15;
 return 0;
}
static LONG CALLBACK foreign_handler(EXCEPTION_POINTERS *e) {
 if (e->ExceptionRecord->ExceptionCode==0xe1234567) { InterlockedIncrement(&foreign_seen); return EXCEPTION_CONTINUE_EXECUTION; }
 return EXCEPTION_CONTINUE_SEARCH;
}
static int rejection_guards(void) {
 CONTEXT c,before; EXCEPTION_RECORD record; EXCEPTION_POINTERS e={&record,&c}; unsigned i;
 LONG previous_hits=hits; Thread *t=current_thread();
 if (!t) return 0;
 for (i=0;i<6;++i) {
  memset(&c,0,sizeof(c)); memset(&record,0,sizeof(record));
  record.ExceptionCode=EXCEPTION_SINGLE_STEP;
  set_slots(t,&c); c.Dr6=1; c.Rip=site_address(t->state.slot[0]);
  switch(i) {
   case 0: record.ExceptionCode=0xe1234567; break;
   case 1: c.EFlags=0x100; break;
   case 2: c.Dr6|=0x4000; break;
   case 3: c.Dr0++; break;
   case 4: c.Dr6=2; break; /* Wrong triggering slot for this instruction. */
   case 5: clear_slots(&c); c.Rip=1; break;
  }
  before=c;
  if (handler(&e)!=EXCEPTION_CONTINUE_SEARCH || memcmp(&c,&before,sizeof(c)) || hits!=previous_hits) return 0;
 }
 return 1;
}
static DWORD WINAPI late_thread(void *unused) {
 ULONGLONG until=GetTickCount64()+5000; (void)unused;
 while (!current_thread() && GetTickCount64()<until) Sleep(10);
 if (!current_thread()) return 5;
 fixture_run(); return 0;
}
int main(int argc,char **argv) {
 HANDLE run,late,conflict; DWORD result; uintptr_t copied; ULONGLONG until; PVOID foreign;
 CONTEXT context;
 if (argc!=2) return 2;
 fixture_addresses[0]=(uintptr_t)fixture_consumer_read; fixture_addresses[1]=(uintptr_t)fixture_parser_done;
 fixture_addresses[2]=(uintptr_t)fixture_consumer_done; fixture_addresses[3]=(uintptr_t)fixture_name_length;
 fixture_addresses[4]=(uintptr_t)fixture_attribute_count; fixture_addresses[5]=(uintptr_t)fixture_key_length;
 fixture_addresses[6]=(uintptr_t)fixture_attribute_pair; fixture_addresses[7]=(uintptr_t)fixture_producer_copy;
 fixture_addresses[8]=(uintptr_t)fixture_producer_written; fixture_addresses[9]=(uintptr_t)fixture_name_gate;
 temporary_table[2]=0x12920; record_table[2]=0x69160; key_table[2]=0x12860; collection_table[14]=0x5b9d0;
 pointer(owner+0xb8,(uintptr_t)collection_table); pointer(record+0x358,(uintptr_t)record_table);
 pointer(record+0x388,(uintptr_t)empty_name); reader[0x10]=5;
 output=CreateFileA(argv[1],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if (output==INVALID_HANDLE_VALUE) return 3;
 conflict_ready=CreateEventW(NULL,TRUE,FALSE,NULL); conflict_release=CreateEventW(NULL,TRUE,FALSE,NULL);
 conflict=CreateThread(NULL,0,conflict_thread,NULL,0,NULL);
 if (!conflict || WaitForSingleObject(conflict_ready,5000)!=WAIT_OBJECT_0) return 16;
 run=CreateThread(NULL,0,worker,NULL,0,NULL); if (!run) return 4;
 until=GetTickCount64()+5000;
 while (!current_thread() && GetTickCount64()<until) Sleep(10);
 if (!current_thread()) return 5;
 foreign=AddVectoredExceptionHandler(0,foreign_handler);
 if (!rejection_guards()) return 18;
 RaiseException(0xe1234567,0,0,NULL);
 if (foreign_seen!=1) return 6;
 fixture_run();
 memcpy(&copied,record+0x388,8);
 if (copied!=(uintptr_t)service_name || owner[0xc0]!=1) return 7;
 late=CreateThread(NULL,0,late_thread,NULL,0,NULL);
 if (!late || WaitForSingleObject(late,6000)!=WAIT_OBJECT_0 || !GetExitCodeThread(late,&result) || result) return 8;
 CloseHandle(late);
 isac_stack_probe_shutdown();
 if (WaitForSingleObject(run,5000)!=WAIT_OBJECT_0) return 9;
 CloseHandle(run); RemoveVectoredExceptionHandler(foreign);
 SetEvent(conflict_release);
 if (WaitForSingleObject(conflict,5000)!=WAIT_OBJECT_0 || !GetExitCodeThread(conflict,&result) || result || !conflicts) return 17;
 CloseHandle(conflict); CloseHandle(conflict_ready); CloseHandle(conflict_release);
 memset(&context,0,sizeof(context)); context.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if (!GetThreadContext(GetCurrentThread(),&context) || (context.Dr7 & 255)) return 10;
 if (consumed!=4 || resume_failed || results[0].result.copy_equal!=1 || !results[0].result.complete ||
     results[1].result.gate_empty || results[2].result.copy_equal!=1) return 11;
 puts("type5 VEH: main/late-thread fields, copy, gate, foreign slots/exception and disarm passed");
 return 0;
}
