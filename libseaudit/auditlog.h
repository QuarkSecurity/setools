/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: kcarr@tresys.com and Karl MacMillan <kmacmillan@tresys.com>
 * Date: October 1, 2003
 * 
 * This file contains the data structure definitions for storing
 * audit logs.
 *
 * auditlog.h
 */

#ifndef LIBAUDIT_AUDITLOG_H
#define LIBAUDIT_AUDITLOG_H
#include <time.h>
#include "../libapol/util.h"
#include "../libapol/avl-util.h"

#define LIBSEAUDIT_VERSION_STRING "1.0"

/* 
 * msg_type_t defines the different types of audit messages this library will
 * handle.  AVC_MSG is a standard 'allowed' or 'denied' type message.  
 * LOAD_POLICY_MSG is the message that results when a policy is loaded into the
 * system.
 */
#define AVC_MSG 	0x00000001
#define	LOAD_POLICY_MSG 0x00000002

/* defines for the fields in the message types */
#define AVC_MSG_FIELD 		0
#define AVC_EXE_FIELD 		1
#define AVC_PATH_FIELD 		2
#define AVC_DEV_FIELD 		3
#define AVC_SRC_USER_FIELD	4
#define AVC_SRC_ROLE_FIELD	5
#define AVC_SRC_TYPE_FIELD	6
#define AVC_TGT_USER_FIELD	7
#define AVC_TGT_ROLE_FIELD	8
#define AVC_TGT_TYPE_FIELD	9
#define AVC_OBJ_CLASS_FIELD	10
#define AVC_PERM_FIELD		11
#define AVC_INODE_FIELD		12
#define AVC_PID_FIELD		13
#define AVC_SRC_SID_FIELD       14
#define AVC_TGT_SID_FIELD       15
#define AVC_COMM_FIELD          16
#define AVC_NETIF_FIELD         17
#define AVC_KEY_FIELD           18
#define AVC_CAPABILITY_FIELD    19
#define AVC_PORT_FIELD          20
#define AVC_LPORT_FIELD         21
#define AVC_FPORT_FIELD         22
#define AVC_DEST_FIELD          23
#define AVC_SOURCE_FIELD        24
#define AVC_LADDR_FIELD         25
#define AVC_FADDR_FIELD         26
#define AVC_DADDR_FIELD         27
#define AVC_SADDR_FIELD         28
#define AVC_SRC_CONTEXT         29
#define AVC_TGT_CONTEXT         30
#define AVC_NAME_FIELD          31
#define AVC_MISC_FIELD          32
#define AVC_NUM_FIELDS		33

#define LOAD_POLICY_USERS_FIELD   33
#define LOAD_POLICY_ROLES_FIELD   34
#define LOAD_POLICY_TYPES_FIELD   35
#define LOAD_POLICY_CLASSES_FIELD 36
#define LOAD_POLICY_RULES_FIELD   37
#define LOAD_POLICY_BINARY_FIELD  38
#define LOAD_POLICY_NUM_FIELDS    6

#define DATE_FIELD		39
#define HOST_FIELD              40

#define MSG_MAX_NFIELDS AVC_NUM_FIELDS
#define NUM_FIELDS		41

extern const char *audit_log_field_strs[NUM_FIELDS]; 
int audit_log_field_strs_get_index(const char *str);
				       	       
enum avc_msg_class_t {
	AVC_AUDIT_DATA_NO_VALUE,
	AVC_AUDIT_DATA_IPC,
	AVC_AUDIT_DATA_CAP,
	AVC_AUDIT_DATA_FS,
	AVC_AUDIT_DATA_NET,
	AVC_AUDIT_DATA_MALFORMED
};
/*
 * avc_msg contains all fields unique to an AVC message.
 */
#define AVC_DENIED  0
#define AVC_GRANTED 1
typedef struct avc_msg {
	enum avc_msg_class_t avc_type;
	char *exe;           /* executable and path */
	char *comm;
	char *path;          /* path of the OBJECT */
	char *dev;           /* device for the object */
	char *netif;
	char *laddr;
	char *faddr;
	char *daddr;
	char *saddr;
	char *name;
        int *perms;	     /* object permissions */
	int num_perms;	     /* num of object permissions */
	int msg;             /* message ie. AVC_DENIED or AVC_GRANTED */
	int key;
	bool_t is_key;
	int capability;
	bool_t is_capability;
	int lport;
	int fport;
	int dest;
	int port;
	int source;
	int src_user;         /* source user */
	int src_role;         /* source role */
	int src_type;         /* source type */
	int tgt_user;         /* target user */
	int tgt_role;         /* target role */
	int tgt_type;         /* target type */
	int obj_class;        /* object class */
        unsigned int src_sid; /* source sid */
	unsigned int tgt_sid; /* target sid */
	unsigned int pid;     /* process ID of the subject */
	unsigned long inode;  /* inode of the object */
	bool_t is_inode;
} avc_msg_t;

/* 
 * load_policy_msg contains all fields unique to the loaded policy message.
 */
typedef struct load_policy_msg {
	unsigned int users;   /* number of users */
	unsigned int roles;   /* number of roles */
	unsigned int types;   /* number of types */
	unsigned int classes; /* number of classes */
	unsigned int rules;   /* number of rules */
	char *binary;         /* path for binary that was loaded */
} load_policy_msg_t;


/*
 * msg_t is the type for all audit log messages.  It will contain either 
 * avc_msg_t or load_policy_msg_t, but not both.
 */
typedef struct msg {
	struct tm *date_stamp; /* audit message datestamp */
	unsigned int msg_type; /* audit message type..AVC_MSG or LOAD_POLICY_MSG */
	int host;              /* key for the hostname that generated the message */
	union {
		avc_msg_t *avc_msg;                 /* if msg_type = AVC_MSG */
		load_policy_msg_t *load_policy_msg; /* if msg_type = LOAD_POLICY_MSG */
	} msg_data;
} msg_t;

/*
 * strs_t is a type for storing dynamically allocated arrays of strings.
 */
typedef struct strs {
	char **strs; /* strings */
	int strs_sz; /* size of array */
	int num_strs;/* number of strings */
} strs_t;

/* Set the initial size of the strings array to 100 and increment by that
 * amount as needed */
#define ARRAY_SZ 100

#define TYPE_TREE 0
#define USER_TREE 1
#define ROLE_TREE 2
#define OBJ_TREE  3
#define PERM_TREE 4
#define HOST_TREE 5
#define NUM_TREES 6

typedef struct audit_log {
	msg_t **msg_list;    /* the array of messages */
	int msg_list_sz;     /* the size of message list */
	int num_msgs;        /* the number of messages */
	avl_tree_t trees[NUM_TREES];
	strs_t symbols[NUM_TREES];
	struct filter *filters; /* filters */
	int *fltr_msgs;      /* filtered and sorted messages */
	bool_t fltr_out;
	bool_t fltr_and;
	int fltr_msgs_types; /* the message types stored in the fltr_msgs array */
	int num_fltr_msgs;   /* num of filtered and sorted messages */
	int fltr_msgs_sz;    /* size of filtered messages array */
	struct sort_action_node *sort_actions; /* sort functions */
	struct sort_action_node *last_sort_action;
} audit_log_t;

audit_log_t* audit_log_create(void);
msg_t* avc_msg_create(void);
msg_t* load_policy_msg_create(void);
#define msg_get_avc_data(msg) msg->msg_data.avc_msg
#define msg_get_load_policy_data(msg) msg->msg_data.load_policy_msg

void audit_log_destroy(audit_log_t *tmp);
void msg_destroy(msg_t *tmp);/* Free all memory associated with a message */
int audit_log_add_msg (audit_log_t*, msg_t*);   /* add msg_t pointer to audit log database */
int audit_log_add_str(audit_log_t *log, char *string, int *id, int which);
int audit_log_get_str_idx(audit_log_t *log, const char *str, int which);
const char* audit_log_get_str(audit_log_t *log, int idx, int which);
int audit_log_add_filter(audit_log_t *log, struct filter *filter);
void audit_log_purge_filters(audit_log_t *log);
void audit_log_msgs_print(audit_log_t *log, FILE *file);     /* FIX: not complete.  used for debugging */
void audit_log_fltr_msgs_print(audit_log_t *log, FILE *file);/* FIX: not complete.  used for debugging */

int audit_log_do_filter(audit_log_t *log, bool_t details, int **deleted, int *num_deleted);
enum avc_msg_class_t which_avc_msg_class(msg_t *msg);

#define audit_log_add_type(log, str, id) audit_log_add_str(log, str, id, TYPE_TREE)
#define audit_log_add_user(log, str, id) audit_log_add_str(log, str, id, USER_TREE)
#define audit_log_add_role(log, str, id) audit_log_add_str(log, str, id, ROLE_TREE)
#define audit_log_add_obj(log, str, id)  audit_log_add_str(log, str, id, OBJ_TREE)
#define audit_log_add_perm(log, str, id) audit_log_add_str(log, str, id, PERM_TREE)
#define audit_log_add_host(log, str, id) audit_log_add_str(log, str, id, HOST_TREE)

#define audit_log_get_type_idx(log, str) audit_log_get_str_idx(log, str, TYPE_TREE)
#define audit_log_get_user_idx(log, str) audit_log_get_str_idx(log, str, USER_TREE)
#define audit_log_get_role_idx(log, str) audit_log_get_str_idx(log, str, ROLE_TREE)
#define audit_log_get_obj_idx(log, str)  audit_log_get_str_idx(log, str, OBJ_TREE)
#define audit_log_get_perm_idx(log, str) audit_log_get_str_idx(log, str, PERM_TREE)
#define audit_log_get_host_idx(log, str) audit_log_get_str_idx(log, str, HOST_TREE)

#define audit_log_get_type(log, idx) audit_log_get_str(log, idx, TYPE_TREE)
#define audit_log_get_user(log, idx) audit_log_get_str(log, idx, USER_TREE)
#define audit_log_get_role(log, idx) audit_log_get_str(log, idx, ROLE_TREE)
#define audit_log_get_obj(log, idx)  audit_log_get_str(log, idx, OBJ_TREE)
#define audit_log_get_perm(log, idx) audit_log_get_str(log, idx, PERM_TREE)
#define audit_log_get_host(log, idx) audit_log_get_str(log, idx, HOST_TREE)

#endif
