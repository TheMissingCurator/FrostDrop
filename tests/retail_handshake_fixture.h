#include <stdint.h>
#include <string.h>
static unsigned char arena[32768];
static void fixture_u(unsigned offset,uint64_t value,unsigned size) { memcpy(arena+offset,&value,size); }
static void fixture_token(unsigned p,unsigned n,unsigned char fill) {
 fixture_u(p,0x2914dd8,8); fixture_u(p+0x408,(uintptr_t)(arena+p+8),8);
 fixture_u(p+0x410,n,4); fixture_u(p+0x414,1024,4); fixture_u(p+0x420,100900,8);
 memset(arena+p+8,fill,n<=1024?n:0);
}
static void fixture_string(unsigned p,const char *value) {
 fixture_u(p,0x2910bb8,8); fixture_u(p+0x48,(uintptr_t)(arena+p+8),8);
 strcpy((char *)arena+p+8,value);
}
static void fixture_handshake_data(void) {
 memset(arena,0,sizeof(arena));
 fixture_token(0x108,240,'A'); fixture_token(0x530,240,'B'); fixture_token(0x9f0,272,'C');
 fixture_u(0x1800,129,4); fixture_u(0x1804,1,1); fixture_u(0x180c,42,4);
 fixture_string(0x1810,"fixture-instance"); fixture_token(0x1868,208,'J');
 fixture_string(0x1ce8,"fixture-location"); fixture_string(0x1c90,"default_start_zone"); fixture_u(0x1d40,7,4);
 fixture_token(0x3000,240,'A'); fixture_token(0x3428,208,'J'); fixture_token(0x3850,272,'C');
 memset(arena+0x5000,0x17,16); fixture_u(0x5010,1,1);
}
