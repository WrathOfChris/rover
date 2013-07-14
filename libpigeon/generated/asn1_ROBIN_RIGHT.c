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
enc_ROBIN_RIGHT(unsigned char *p, size_t len, const ROBIN_RIGHT *data, size_t *size)
{
size_t ret = 0;
size_t l;
int i, e;

i = 0;
{
unsigned char c = 0;
if (data->local8) c |= 1<<0;
if (data->local7) c |= 1<<1;
if (data->local6) c |= 1<<2;
if (data->local5) c |= 1<<3;
if (data->local4) c |= 1<<4;
if (data->local3) c |= 1<<5;
if (data->local2) c |= 1<<6;
if (data->local1) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
if (data->peruse) c |= 1<<4;
if (data->pstop) c |= 1<<5;
if (data->ponly) c |= 1<<6;
if (data->pdir) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
if (data->pfile) c |= 1<<0;
if (data->notify) c |= 1<<1;
if (data->lock) c |= 1<<2;
if (data->admin) c |= 1<<3;
if (data->wacl) c |= 1<<4;
if (data->racl) c |= 1<<5;
if (data->execute) c |= 1<<6;
if (data->wattr) c |= 1<<7;
*p-- = c; len--; ret++;
c = 0;
if (data->rattr) c |= 1<<0;
if (data->remove) c |= 1<<1;
if (data->insert) c |= 1<<2;
if (data->lookup) c |= 1<<3;
if (data->delete) c |= 1<<4;
if (data->append) c |= 1<<5;
if (data->write) c |= 1<<6;
if (data->read) c |= 1<<7;
*p-- = c;
*p-- = 0;
len -= 2;
ret += 2;
}

e = tb_der_put_len_and_tag(p, len, ret, ASN1_C_UNIV, PRIM,UT_BitString, &l);
BACK;
*size = ret;
return 0;
}

#define FORW if(e) goto fail; p += l; len -= l; ret += l

int
dec_ROBIN_RIGHT(const unsigned char *p, size_t len, ROBIN_RIGHT *data, size_t *size)
{
size_t ret = 0, reallen;
size_t l;
int e;

memset(data, 0, sizeof(*data));
reallen = 0;
e = tb_der_match_tag_and_len(p, len, ASN1_C_UNIV, PRIM, UT_BitString, &reallen, &l);
FORW;
if (len < reallen)
	return TBASN1_OVERRUN;
p++;
len--;
reallen--;
ret++;
data->read = (*p >> 7) & 1;
data->write = (*p >> 6) & 1;
data->append = (*p >> 5) & 1;
data->delete = (*p >> 4) & 1;
data->lookup = (*p >> 3) & 1;
data->insert = (*p >> 2) & 1;
data->remove = (*p >> 1) & 1;
data->rattr = (*p >> 0) & 1;
p++; len--; reallen--; ret++;
data->wattr = (*p >> 7) & 1;
data->execute = (*p >> 6) & 1;
data->racl = (*p >> 5) & 1;
data->wacl = (*p >> 4) & 1;
data->admin = (*p >> 3) & 1;
data->lock = (*p >> 2) & 1;
data->notify = (*p >> 1) & 1;
data->pfile = (*p >> 0) & 1;
p++; len--; reallen--; ret++;
data->pdir = (*p >> 7) & 1;
data->ponly = (*p >> 6) & 1;
data->pstop = (*p >> 5) & 1;
data->peruse = (*p >> 4) & 1;
p++; len--; reallen--; ret++;
data->local1 = (*p >> 7) & 1;
data->local2 = (*p >> 6) & 1;
data->local3 = (*p >> 5) & 1;
data->local4 = (*p >> 4) & 1;
data->local5 = (*p >> 3) & 1;
data->local6 = (*p >> 2) & 1;
data->local7 = (*p >> 1) & 1;
data->local8 = (*p >> 0) & 1;
p += reallen; len -= reallen; ret += reallen;
if (size) *size = ret;
return 0;
fail:
free_ROBIN_RIGHT(data);
return e;
}

void
free_ROBIN_RIGHT(ROBIN_RIGHT *data)
{
}

size_t
len_ROBIN_RIGHT(const ROBIN_RIGHT *data)
{
size_t ret = 0;
ret += 7;
return ret;
}

int
copy_ROBIN_RIGHT(const ROBIN_RIGHT *from, ROBIN_RIGHT *to)
{
*(to) = *(from);
return 0;
}

unsigned ROBIN_RIGHT2int(ROBIN_RIGHT f)
{
unsigned r = 0;
if (f.read) r |= (1U << 0);
if (f.write) r |= (1U << 1);
if (f.append) r |= (1U << 2);
if (f.delete) r |= (1U << 3);
if (f.lookup) r |= (1U << 4);
if (f.insert) r |= (1U << 5);
if (f.remove) r |= (1U << 6);
if (f.rattr) r |= (1U << 7);
if (f.wattr) r |= (1U << 8);
if (f.execute) r |= (1U << 9);
if (f.racl) r |= (1U << 10);
if (f.wacl) r |= (1U << 11);
if (f.admin) r |= (1U << 12);
if (f.lock) r |= (1U << 13);
if (f.notify) r |= (1U << 14);
if (f.pfile) r |= (1U << 15);
if (f.pdir) r |= (1U << 16);
if (f.ponly) r |= (1U << 17);
if (f.pstop) r |= (1U << 18);
if (f.peruse) r |= (1U << 19);
if (f.local1) r |= (1U << 24);
if (f.local2) r |= (1U << 25);
if (f.local3) r |= (1U << 26);
if (f.local4) r |= (1U << 27);
if (f.local5) r |= (1U << 28);
if (f.local6) r |= (1U << 29);
if (f.local7) r |= (1U << 30);
if (f.local8) r |= (1U << 31);
return r;
}

ROBIN_RIGHT int2ROBIN_RIGHT(unsigned n)
{
	ROBIN_RIGHT flags;

	flags.read = (n >> 0) & 1;
	flags.write = (n >> 1) & 1;
	flags.append = (n >> 2) & 1;
	flags.delete = (n >> 3) & 1;
	flags.lookup = (n >> 4) & 1;
	flags.insert = (n >> 5) & 1;
	flags.remove = (n >> 6) & 1;
	flags.rattr = (n >> 7) & 1;
	flags.wattr = (n >> 8) & 1;
	flags.execute = (n >> 9) & 1;
	flags.racl = (n >> 10) & 1;
	flags.wacl = (n >> 11) & 1;
	flags.admin = (n >> 12) & 1;
	flags.lock = (n >> 13) & 1;
	flags.notify = (n >> 14) & 1;
	flags.pfile = (n >> 15) & 1;
	flags.pdir = (n >> 16) & 1;
	flags.ponly = (n >> 17) & 1;
	flags.pstop = (n >> 18) & 1;
	flags.peruse = (n >> 19) & 1;
	flags.local1 = (n >> 24) & 1;
	flags.local2 = (n >> 25) & 1;
	flags.local3 = (n >> 26) & 1;
	flags.local4 = (n >> 27) & 1;
	flags.local5 = (n >> 28) & 1;
	flags.local6 = (n >> 29) & 1;
	flags.local7 = (n >> 30) & 1;
	flags.local8 = (n >> 31) & 1;
	return flags;
}

static tbunits ROBIN_RIGHT_units[] = {
	{"local8",	1U << 31},
	{"local7",	1U << 30},
	{"local6",	1U << 29},
	{"local5",	1U << 28},
	{"local4",	1U << 27},
	{"local3",	1U << 26},
	{"local2",	1U << 25},
	{"local1",	1U << 24},
	{"peruse",	1U << 19},
	{"pstop",	1U << 18},
	{"ponly",	1U << 17},
	{"pdir",	1U << 16},
	{"pfile",	1U << 15},
	{"notify",	1U << 14},
	{"lock",	1U << 13},
	{"admin",	1U << 12},
	{"wacl",	1U << 11},
	{"racl",	1U << 10},
	{"execute",	1U << 9},
	{"wattr",	1U << 8},
	{"rattr",	1U << 7},
	{"remove",	1U << 6},
	{"insert",	1U << 5},
	{"lookup",	1U << 4},
	{"delete",	1U << 3},
	{"append",	1U << 2},
	{"write",	1U << 1},
	{"read",	1U << 0},
	{NULL,	0}
};

const tbunits * asn1_ROBIN_RIGHT_units(void){
return ROBIN_RIGHT_units;
}

