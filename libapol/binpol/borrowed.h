/* Copyright (C) 2004 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */
 
/* 
 * Directly borrowed from checkpolicy
 */

#ifndef _APOLICY_BINPOL_BORROWED_H_
#define _APOLICY_BINPOL_BORROWED_H_

#include <byteswap.h>
#include <endian.h>
#include <sys/types.h>


#define SELINUX_MAGIC 0xf97cff8c 

#define OBJECT_R_VAL 1

#define printk printf
#define kmalloc(size) malloc(size)
#define kfree(ptr) free(ptr)


#if __BYTE_ORDER == __LITTLE_ENDIAN
#define cpu_to_le32(x) (x)
#define le32_to_cpu(x) (x)
#define cpu_to_le64(x) (x)
#define le64_to_cpu(x) (x)
#else
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#define cpu_to_le64(x) bswap_64(x)
#define le64_to_cpu(x) bswap_64(x)
#endif

/* needed for constraints (which apol currently ignores */
#ifndef CEXPR_NOT
	#define CEXPR_NOT	1 /* not expr */
#endif
#ifndef CEXPR_AND
	#define CEXPR_AND	2 /* expr and expr */

#endif
#ifndef CEXPR_OR
	#define CEXPR_OR	3 /* expr or expr */
#endif
#ifndef CEXPR_ATTR
	#define CEXPR_ATTR	4 /* attr op attr */
#endif
#ifndef CEXPR_NAMES
	#define CEXPR_NAMES	5 /* attr op names */	
#endif

#define POLICYDB_VERSION_IPV6	17
#define POLICYDB_VERSION_BOOL 	16
#define POLICYDB_VERSION_BASE 	15

#define POLICYDB_CONFIG_MLS    1

#ifdef CONFIG_SECURITY_SELINUX_MLS
#define SYM_NUM     8
#else
#define SYM_NUM     6
#endif


/* avtab.h */
typedef struct avtab_key {
	__u32 source_type;	/* source type */
	__u32 target_type;	/* target type */
	__u32 target_class;     /* target object class */
} avtab_key_t;

typedef struct avtab_datum {
#define AVTAB_ALLOWED     1
#define AVTAB_AUDITALLOW  2
#define AVTAB_AUDITDENY   4
#define AVTAB_AV         (AVTAB_ALLOWED | AVTAB_AUDITALLOW | AVTAB_AUDITDENY)
#define AVTAB_TRANSITION 16
#define AVTAB_MEMBER     32
#define AVTAB_CHANGE     64
#define AVTAB_TYPE       (AVTAB_TRANSITION | AVTAB_MEMBER | AVTAB_CHANGE)
#define AVTAB_ENABLED    0x80000000 /* reserved for used in cond_avtab */
	__u32 specified;	/* what fields are specified */
        __u32 data[3];          /* access vectors or types */
#define avtab_allowed(x) (x)->data[0]
#define avtab_auditdeny(x) (x)->data[1]
#define avtab_auditallow(x) (x)->data[2]
#define avtab_transition(x) (x)->data[0]
#define avtab_change(x) (x)->data[1]
#define avtab_member(x) (x)->data[2]
} avtab_datum_t;

typedef struct avtab_node *avtab_ptr_t;

struct avtab_node {
	avtab_key_t key;
	avtab_datum_t datum;
	avtab_ptr_t next;
	void *parse_context;	/* generic context pointer used by parser;
				 * not saved in binary policy */
};

typedef struct avtab {
	avtab_ptr_t *htable;
	__u32 nel;	/* number of elements */
} avtab_t;

#define AVTAB_HASH_BITS 15
#define AVTAB_HASH_BUCKETS (1 << AVTAB_HASH_BITS)
#define AVTAB_HASH_MASK (AVTAB_HASH_BUCKETS-1)

#define AVTAB_SIZE AVTAB_HASH_BUCKETS

/* end avtab.h */



#endif


