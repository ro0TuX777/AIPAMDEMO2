/* Bait for the C rules. One construct per rule, nothing incidental. */
#include <string.h>
char buf[64];
char cfg_key = 0x2E;                        /* static-payload-key */
void a(char *in, int n){ memcpy(buf, in, n); }   /* unchecked-memcpy */
void b(char *in){ strcpy(buf, in); }             /* unbounded-string-copy */
