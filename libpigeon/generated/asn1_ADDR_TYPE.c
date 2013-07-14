/* Generated from /home/admin/libpigeon/robin.asn1 */
/* Do not edit */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <robin_asn1.h>
#include <toolbox.h>
#include <toolbox_asn1_err.h>
#include <toolbox_asn1_der.h>

#define BACK if (e) return e; p -= l; len -= l; ret += l

int
enc_ADDR_TYPE(unsigned char *p, size_t len, const ADDR_TYPE *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
e = enc_int32(p, len, (const int32_t *)data, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ADDR_TYPE(const unsigned char *p, size_t len, ADDR_TYPE *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = dec_int32(p, len, (int32_t *)data, &l);
FORW;
if (size) *size = ret;
return 0;
fail:
free_ADDR_TYPE(data);
return e;
}

void
free_ADDR_TYPE(ADDR_TYPE *data)
{
}

size_t
len_ADDR_TYPE(const ADDR_TYPE *data)
{
size_t ret = 0;
ret += len_int32((const int32_t *)data);
return ret;
}

int
copy_ADDR_TYPE(const ADDR_TYPE *from, ADDR_TYPE *to)
{
*(to) = *(from);
return 0;
}

