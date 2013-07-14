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
enc_RobinFilename(unsigned char *p, size_t len, const RobinFilename *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
e = enc_bytes(p, len, data, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_RobinFilename(const unsigned char *p, size_t len, RobinFilename *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = dec_bytes(p, len, data, &l);
FORW;
if (size) *size = ret;
return 0;
fail:
free_RobinFilename(data);
return e;
}

void
free_RobinFilename(RobinFilename *data)
{
free_bytes(data);
}

size_t
len_RobinFilename(const RobinFilename *data)
{
size_t ret = 0;
ret += len_bytes(data);
return ret;
}

int
copy_RobinFilename(const RobinFilename *from, RobinFilename *to)
{
if (copy_bytes(from, to)) return ENOMEM;
return 0;
}

