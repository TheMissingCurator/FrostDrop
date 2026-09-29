#define ISAC_RETAIL_OBSERVER_TEST 1
#include "../src/uplay_probe/retail_profile_win.c"
#include "retail_profile_fixture.h"
extern void fixture_profile_run(void *,void *,unsigned);
extern void fixture_profile_0(void),fixture_profile_1(void),fixture_profile_2(void),fixture_profile_3(void);
uintptr_t fixture_addresses[PROFILE_SITE_COUNT];
static DWORD WINAPI late(void *unused) {
 ULONGLONG until=GetTickCount64()+5000; (void)unused;
 while(!current_thread() && GetTickCount64()<until) Sleep(10);
 if(!current_thread()) return 1;
 fixture_u(0x3010,2,2); fixture_profile_run(arena+0x200,arena+0x3000,2);
 return 0;
}
int main(int argc,char **argv) {
 HANDLE thread,other; ULONGLONG until; DWORD code; unsigned i;
 unsigned offsets[]={0,0x100,0x200,0x1000}; CONTEXT c;
 if(argc!=2) return 2;
 fixture_profile_data();
 fixture_addresses[0]=(uintptr_t)fixture_profile_0; fixture_addresses[1]=(uintptr_t)fixture_profile_1;
 fixture_addresses[2]=(uintptr_t)fixture_profile_2; fixture_addresses[3]=(uintptr_t)fixture_profile_3;
 output=CreateFileA(argv[1],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(output==INVALID_HANDLE_VALUE) return 3;
 thread=CreateThread(NULL,0,worker,NULL,0,NULL); if(!thread) return 4;
 until=GetTickCount64()+5000;
 while(!current_thread() && GetTickCount64()<until) Sleep(10);
 if(!current_thread()) return 5;
 for(i=0;i<4;++i) {
  fixture_u(0x3010,i==1?6:i==2?2:8,2);
  fixture_profile_run(arena+offsets[i],arena+0x3000,i);
 }
 other=CreateThread(NULL,0,late,NULL,0,NULL);
 if(!other || WaitForSingleObject(other,6000)!=WAIT_OBJECT_0 || !GetExitCodeThread(other,&code) || code) return 6;
 CloseHandle(other); isac_stack_probe_shutdown();
 if(WaitForSingleObject(thread,5000)!=WAIT_OBJECT_0) return 7;
 CloseHandle(thread);
 memset(&c,0,sizeof(c)); c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if(!GetThreadContext(GetCurrentThread(),&c) || (c.Dr7&255) || consumed!=5 || resume_failed) return 8;
 for(i=0;i<5;++i) if(!results[i].result.complete) return 9;
 puts("profile VEH: four paths, late thread, disarm passed"); return 0;
}
