#include <stdint.h>
#include <string.h>
static unsigned char arena[16384];
static void fixture_u(unsigned offset,uint64_t value,unsigned size) { memcpy(arena+offset,&value,size); }
static void fixture_string(unsigned offset,const char *value) {
 fixture_u(offset,0x2910bb8,8); fixture_u(offset+0x48,(uintptr_t)(arena+offset+8),8);
 strcpy((char *)arena+offset+8,value);
}
static void fixture_profile_data(void) {
 memset(arena,0,sizeof(arena));
 fixture_u(0,129,4); fixture_u(4,1,1); /* create request */
 fixture_u(0x100,129,4); memset(arena+0x108,0x31,16); /* create reply */
 fixture_u(0x200,129,4); fixture_u(0x204,1,1); fixture_u(0x208,7,4);
 fixture_u(0x210,0x2917998,8); fixture_u(0x218,1,4);
 fixture_u(0x220,(uintptr_t)(arena+0x500),8);
 fixture_u(0x500,(uintptr_t)(arena+0x600),8);
 fixture_string(0x330,"fixture-list");
 memset(arena+0x600,0x31,16); fixture_u(0x610,30,4); fixture_u(0x614,1,1);
 fixture_u(0x618,12345,8); fixture_u(0x620,67890,8);
 fixture_string(0x680,"fixture-one"); fixture_string(0x628,"fixture-two");
 fixture_u(0x6d8,1,1); fixture_u(0x900,1,1);
 fixture_u(0x6e0,0x2917838,8); fixture_u(0x8e8,(uintptr_t)(arena+0xa00),8);
 fixture_u(0x8f0,3,4); memcpy(arena+0xa00,"xyz",3);
 fixture_u(0x1000,129,4); fixture_string(0x1008,"fixture-endpoint"); fixture_string(0x1060,"fixture-service");
 fixture_u(0x10b8,1,1); fixture_u(0x1920,1,1);
}
