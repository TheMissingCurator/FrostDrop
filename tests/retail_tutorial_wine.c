#include <windows.h>
static unsigned fixture_down;
static SHORT fixture_key_state(int key) {
 unsigned bit;
 if(key>=VK_NUMPAD1 && key<=VK_NUMPAD9) bit=(unsigned)(key-VK_NUMPAD1);
 else if(key==VK_NUMPAD0) bit=9;
 else if(key==VK_DECIMAL) bit=10;
 else return 0;
 return (fixture_down&(1u<<bit))?(SHORT)0x8000:0;
}
static HWND fixture_foreground(void) { return (HWND)(uintptr_t)1; }
static DWORD fixture_window_pid(HWND w,DWORD *pid) { (void)w; *pid=GetCurrentProcessId(); return 1; }
#define GetAsyncKeyState fixture_key_state
#define GetForegroundWindow fixture_foreground
#define GetWindowThreadProcessId fixture_window_pid
#define ISAC_RETAIL_OBSERVER_TEST 1
#include "../src/uplay_probe/retail_tutorial_win.c"
#include "retail_tutorial_fixture.h"
extern void fixture_handshake_run(void *,void *,unsigned);
extern void fixture_handshake_0(void),fixture_handshake_1(void),fixture_handshake_2(void),fixture_handshake_3(void);
uintptr_t fixture_addresses[4];
static DWORD WINAPI late(void *unused) {
 ULONGLONG until=GetTickCount64()+5000; (void)unused;
 while(!current_thread() && GetTickCount64()<until) Sleep(10);
 if(!current_thread()) return 1;
 fixture_handshake_run(tutorial_arena+0x4000,tutorial_arena+0x5000,1); return 0;
}
int main(int argc,char **argv) {
 HANDLE thread,other; ULONGLONG until; DWORD code; unsigned i; CONTEXT c;
 if(argc!=3) return 2;
 tutorial_fixture_data();
 fixture_addresses[0]=(uintptr_t)fixture_handshake_0; fixture_addresses[1]=(uintptr_t)fixture_handshake_1;
 fixture_addresses[2]=(uintptr_t)fixture_handshake_2; fixture_addresses[3]=(uintptr_t)fixture_handshake_3;
 output=CreateFileA(argv[1],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 tutorial_payload=CreateFileA(argv[2],GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(output==INVALID_HANDLE_VALUE || tutorial_payload==INVALID_HANDLE_VALUE) return 3;
 if(!tutorial_write("ISACTUT1\x01\0\0\0\x10\0\0\0",16)) return 4;
 thread=CreateThread(NULL,0,worker,NULL,0,NULL); if(!thread) return 5;
 until=GetTickCount64()+5000;
 while(!current_thread() && GetTickCount64()<until) Sleep(10);
 if(!current_thread()) return 6;
 fixture_handshake_run(tutorial_arena+0x4000,tutorial_arena+0x5000,1);
 fixture_handshake_run(tutorial_arena+0x1000,tutorial_arena+0x2800,0);
 fixture_handshake_run(tutorial_arena+0xa000,tutorial_arena+0xa800,2);
 fixture_handshake_run(tutorial_arena+0xb000,tutorial_arena+0xb800,3);
 tutorial_fixture_gameplay();
 for(i=0;i<600;++i) {
  while((unsigned)InterlockedCompareExchange(&reserved,0,0)-consumed>96 && !stopped) Sleep(10);
  fixture_handshake_run(tutorial_arena+0x4000,tutorial_arena+0x5000,1);
 }
 other=CreateThread(NULL,0,late,NULL,0,NULL);
 if(!other || WaitForSingleObject(other,6000)!=WAIT_OBJECT_0 || !GetExitCodeThread(other,&code) || code) return 7;
 CloseHandle(other);
 /* Exercise all eleven real marker polling branches without desktop key injection. */
 for(i=0;i<11;++i) {
  fixture_down=1u<<i; tutorial_poll_keys(); tutorial_poll_keys();
  fixture_down=0; tutorial_poll_keys();
 }
 isac_stack_probe_shutdown();
 if(WaitForSingleObject(thread,5000)!=WAIT_OBJECT_0) return 8;
 CloseHandle(thread);
 memset(&c,0,sizeof(c)); c.ContextFlags=CONTEXT_DEBUG_REGISTERS;
 if(!GetThreadContext(GetCurrentThread(),&c) || (c.Dr7&255) || tutorial_records!=605 || resume_failed || tutorial_gaps || tutorial_markers!=11) return 9;
 puts("tutorial VEH: ring reuse, eleven marker edges, late thread, disarm passed"); return 0;
}
