/* Copyright (C) 2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/*
 * Author: mbrown@tresys.com
 * Date: October 3, 2003
 * Modified 3/26/2004 <don.patterson@tresys.com>
 *
 * This file contains the implementation of the parse.h
 *
 */

#include "parse.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>

#define MEMORY_BLOCK_MAX_SIZE 256
#define NUM_TIME_COMPONENTS 3
#define OLD_LOAD_POLICY_STRING "loadingpolicyconfigurationfrom"
#define AVCMSG " avc: "
#define LOADMSG " security: "
#define HEADER_STRING "audit"
#define BOOLMSG "committed booleans"
#define PARSE_AVC_MSG 1
#define PARSE_LOAD_MSG 2
#define PARSE_BOOL_MSG 3
#define PARSE_NON_SELINUX -1
#define PARSE_NUM_CONTEXT_FIELDS 3
#define PARSE_NOT_MATCH -1
#define MSG_MEMORY_ERROR -1
#define MSG_INSERT_SUCCESS 0
#define AVC_MSG_INSERT_INVALID_CONTEXT -2

#define LOAD_POLICY_MSG_USERS_FIELD   0
#define LOAD_POLICY_MSG_ROLES_FIELD   1
#define LOAD_POLICY_MSG_TYPES_FIELD   2
#define LOAD_POLICY_MSG_CLASSES_FIELD 3
#define LOAD_POLICY_MSG_RULES_FIELD   4
#define LOAD_POLICY_MSG_NUM_POLICY_COMPONENTS 5  

#define LOAD_POLICY_FALSE_POS	0x00000001
#define LOAD_POLICY_NEXT_LINE 	0x00000002

static unsigned int get_tokens(char *line, int msgtype, audit_log_t *log, FILE *audit_file, msg_t **msg);

static int is_selinux(char *line) 
{
	assert(line != NULL);
	if (strstr(line, BOOLMSG))
		return PARSE_BOOL_MSG;
	else if (strstr(line, LOADMSG)) 
		return PARSE_LOAD_MSG;
	else if (strstr(line, AVCMSG))
		return PARSE_AVC_MSG;
	else 
		return PARSE_NON_SELINUX;
}

static int avc_msg_is_token_new_audit_header(char *token) 
{
	assert(token != NULL);
	if (strstr(token, HEADER_STRING)) 
		return TRUE;
	else 
		return FALSE;
}

static unsigned int get_line(FILE *audit_file, char **dest)
{
	char *line = NULL, c = '\0';
	int length = 0, i = 0;

	assert(audit_file != NULL && dest != NULL);
	while ((c = fgetc(audit_file)) != EOF) {
		if (i < length - 1) {
			line[i] = c;
		} else {
			length += MEMORY_BLOCK_MAX_SIZE;
			if ((line = (char*) realloc(line, length * sizeof(char))) == NULL){
				return PARSE_RET_MEMORY_ERROR;
			}
			line[i] = c;
		}

		if (c == '\n') {
			line[i+1] = '\0';
			*dest = *(&line);
			return PARSE_RET_SUCCESS;
		}
		i++;
	}

	if (i > 0){
		if (i < length - 1){
			line[i] = '\0';
			*dest = *(&line);
		} else {
			length += MEMORY_BLOCK_MAX_SIZE;
			if ((line = (char*) realloc(line, length * sizeof(char))) == NULL){
				return PARSE_RET_MEMORY_ERROR;
			}
			line[i] = '\0';
			*dest = *(&line);
		}
	}
	
	return PARSE_RET_SUCCESS;
}


static int avc_msg_is_prefix(char *token, char *prefix, char **result)
{
	bool_t is_match = TRUE;
	int i = 0, length;
	
	assert(token != NULL && prefix != NULL);
	length = strlen(prefix);
	if (strlen(token) < length)
		return FALSE;

	for (i = 0; i < length; i++){
		if (token[i] != prefix[i]){
			is_match = FALSE;
			break;
		}
	}
	if (!is_match)
		return FALSE;
	
	/* Set the result to all text after the prefix. */
	*result = &token[length];
	return TRUE;
}

static unsigned int avc_msg_insert_perms(char **tokens, msg_t *msg, audit_log_t *log, int *position, int num_tokens)
{
	int i = 0, num_perms = 0, id = 0, start_pos;
	
	assert(tokens != NULL && msg != NULL && log != NULL && *position >= 0);
	/* Permissions should start and end with brackets and if not, then this is invalid. */		
	if (strcmp(tokens[*position], "{")) {
		return PARSE_RET_INVALID_MSG_WARN;
	}

	(*position)++;
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	start_pos = *position;
	for (i = *position; i < num_tokens && (strcmp(tokens[i], "}") != 0); i++) {
		num_perms++;
		(*position)++;
	}
	
	/* Make sure that if we have no more tokens, we have grabbed the closing bracket for this to be valid. 
	 * Otherwise, if there are no more tokens and we have grabbed the closing bracket the message is still
	 * incomplete and thus invalid. */
	if (*position == num_tokens && strcmp(tokens[*position - 1], "}") != 0)
		return PARSE_RET_INVALID_MSG_WARN;
	else if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;

	/* Allocate memory for the permissions */
	msg->msg_data.avc_msg->num_perms = num_perms;
	if ((msg->msg_data.avc_msg->perms = (int*) malloc(num_perms * sizeof(int))) == NULL){
		return PARSE_RET_MEMORY_ERROR;
	}

	for (i = 0 ; i < num_perms ; i++) {
		if(audit_log_add_perm(log, tokens[i + start_pos], &id) == -1)
			return PARSE_RET_MEMORY_ERROR;
		msg->msg_data.avc_msg->perms[i] = id;
	}
	return PARSE_RET_SUCCESS;
}


static unsigned int insert_time(char **tokens, msg_t *msg, int *position, int num_tokens)
{
	char *time = NULL;
	int i, length = 0;
	
	assert(tokens != NULL && msg != NULL && *position >= 0);
	for (i = (*position); i < NUM_TIME_COMPONENTS; i++) {
		length += strlen(tokens[i]);
	}
	
	/* Increase size for terminating string char and whitespace within. */
	length += 1 + (NUM_TIME_COMPONENTS - 1); 
	if ((time = (char*) malloc(length * (sizeof(char)))) == NULL)
		return PARSE_RET_MEMORY_ERROR;
	
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	strcpy(time, tokens[*position]);	
	time = strcat(time, " ");
	(*position)++;
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	time = strcat(time, tokens[*position]);
	time = strcat(time, " " );
	(*position)++;
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	time = strcat(time, tokens[*position]);
   
	if (!msg->date_stamp) {
		if ((msg->date_stamp = (struct tm*) malloc(sizeof(struct tm))) == NULL)
			return PARSE_RET_MEMORY_ERROR;
	}

	if (!strptime(time, "%b %d %T", msg->date_stamp)) {    
		free(time); 
		return PARSE_RET_INVALID_MSG_WARN;
	} else {
		free(time);
		/* random year to make mktime happy */
		msg->date_stamp->tm_year = 2000 - 1900;
		return PARSE_RET_SUCCESS;
	}
	
}

static unsigned int avc_msg_insert_access_type(char *token, msg_t *msg) 
{
	assert(token != NULL && msg != NULL);
	if (strcmp(token, "granted") == 0) {
		msg->msg_data.avc_msg->msg = AVC_GRANTED;
		return PARSE_RET_SUCCESS;
	} else if (strcmp(token, "denied") == 0) {
		msg->msg_data.avc_msg->msg = AVC_DENIED;
		return PARSE_RET_SUCCESS;
	} else
		return PARSE_RET_INVALID_MSG_WARN;     
}


static int avc_msg_insert_capability(msg_t *msg, char **tmp)
{
	assert(msg != NULL && tmp != NULL && *tmp != NULL);		
	msg->msg_data.avc_msg->capability = atoi(*tmp);
	msg->msg_data.avc_msg->is_capability = TRUE;
	
	return MSG_INSERT_SUCCESS;
}


static int avc_msg_insert_ino(msg_t *msg, char **tmp)
{
	assert(msg != NULL && tmp != NULL && *tmp != NULL);
	msg->msg_data.avc_msg->inode = atoi(*tmp);
	msg->msg_data.avc_msg->is_inode = TRUE;
	return MSG_INSERT_SUCCESS;
}

static int avc_msg_insert_key(msg_t *msg, char **tmp)
{
	assert(msg != NULL && tmp != NULL && *tmp != NULL);		
	msg->msg_data.avc_msg->key = atoi(*tmp);
	msg->msg_data.avc_msg->is_key = TRUE;
	return MSG_INSERT_SUCCESS;
}

static int avc_msg_insert_tclass(msg_t *msg, char **tmp, audit_log_t *log)
{
	int id = -1;
	
	assert(msg != NULL && tmp != NULL && *tmp != NULL && log != NULL);
	if (audit_log_add_obj(log, *tmp, &id) == -1)
		return MSG_MEMORY_ERROR;
	msg->msg_data.avc_msg->obj_class = id;
	
	return MSG_INSERT_SUCCESS;
}

static int parse_context(char *token, char *user, char *role, char *type)
{
	/* Parse user:role:type */
	int i = 0;
	char *fields[PARSE_NUM_CONTEXT_FIELDS];

	assert(token != NULL);
        while ((fields[i] = strsep(&token, ":")) != NULL && i < PARSE_NUM_CONTEXT_FIELDS) {
		i++;       	       	
        }

	if (i != PARSE_NUM_CONTEXT_FIELDS)
		return -1;

	strcpy(user, fields[0]);
	strcpy(role, fields[1]);
	strcpy(type, fields[2]);
	return PARSE_RET_SUCCESS;
       
}

static int avc_msg_insert_tcon(msg_t *msg, char **tmp, audit_log_t *log)
{
	char *user = NULL, *role = NULL, *type = NULL;
	int id = -1, length;

	assert(msg != NULL && tmp != NULL && *tmp != NULL && log != NULL);
	if (*tmp != NULL) {
		length = strlen(*tmp) + 1;
		if ((user = (char*) malloc(length * (sizeof(char)))) == NULL)
			return MSG_MEMORY_ERROR;
		if ((role = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			return MSG_MEMORY_ERROR;
		}
		if ((type = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			free(role);
			return MSG_MEMORY_ERROR;
		}
		if (parse_context(*tmp, user, role, type) < 0){
			free(user);
			free(role);
			free(type);
			return AVC_MSG_INSERT_INVALID_CONTEXT;			
		}
		if (audit_log_add_user(log, user, &id) == -1){
			free(user);
			free(role);
			free(type);
			return MSG_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->tgt_user = id;

		if (audit_log_add_role(log, role, &id) == -1){
			free(user);
			free(role);
			free(type);
			return MSG_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->tgt_role = id;

		if (audit_log_add_type(log, type, &id) == -1){
			free(user);
			free(role);
			free(type);
			return MSG_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->tgt_type = id;
	       
		free(user);
		free(role);
		free(type);
		return PARSE_RET_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}

static int avc_msg_insert_scon(msg_t *msg, char **tmp, audit_log_t *log)
{
	char *user = NULL, *role = NULL, *type = NULL;
	int id = -1, length;

	assert(msg != NULL && tmp != NULL && *tmp != NULL && log != NULL);
	if (*tmp != NULL) {
		length = strlen(*tmp) + 1;
		if ((user = (char*) malloc(length * (sizeof(char)))) == NULL)
			return MSG_MEMORY_ERROR;
		if ((role = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			return MSG_MEMORY_ERROR;
		}
		if ((type = (char*) malloc(length * (sizeof(char)))) == NULL){
			free(user);
			free(role);
			return MSG_MEMORY_ERROR;
		}

		if (parse_context(*tmp, user, role, type) < 0) {
			free(user);
			free(role);
			free(type);
			return AVC_MSG_INSERT_INVALID_CONTEXT;
		}

		if (audit_log_add_user(log, user, &id) == -1){
			free(user);
			free(role);
			free(type);
			return MSG_MEMORY_ERROR;
		}

		msg->msg_data.avc_msg->src_user = id;

		if (audit_log_add_role(log, role, &id) == -1) {
			free(user);
			free(role);
			free(type);
			return MSG_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->src_role = id;

		if (audit_log_add_type(log, type, &id) == -1){
			free(user);
			free(role);
			free(type);
			return MSG_MEMORY_ERROR;
		}
		msg->msg_data.avc_msg->src_type = id;
	       
		free(user);
		free(role);
		free(type);
		return MSG_INSERT_SUCCESS;
	} else
		return PARSE_NOT_MATCH;
}

static int avc_msg_insert_string(char **dest, char **src)
{
	assert(dest != NULL && src != NULL && *src != NULL);
	if ((*dest = (char*) malloc((strlen(*src) + 1) *sizeof(char))) == NULL)
		return MSG_MEMORY_ERROR;
	strcpy(*dest, *src);
	
	return MSG_INSERT_SUCCESS;
}

static unsigned int insert_hostname(audit_log_t *log, char **tokens, msg_t *msg, int *position, int num_tokens)
{
        int id;
	
	assert(log != NULL && tokens != NULL && msg != NULL && *position >= 0);
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
        if (audit_log_add_host(log, tokens[*position], &id) == -1)
                return PARSE_RET_MEMORY_ERROR;
        else {
                msg->host = id;
                return PARSE_RET_SUCCESS;
        }
}

static int avc_msg_insert_int(int *dest, char **src)
{
	assert(dest != NULL && src != NULL && *src != NULL);		
	*dest = atoi(*src);
	return MSG_INSERT_SUCCESS;
}

static int avc_msg_insert_uint(unsigned int *dest, char **src)
{
	assert(dest != NULL && src != NULL && *src != NULL);
	*dest = atoi(*src);
	return MSG_INSERT_SUCCESS;
}

static int avc_msg_is_valid_additional_field(char *orig_token)
{
	int count = 0;
	char *token_copy = NULL, *token = NULL;
					
	assert(orig_token != NULL);
	/* Make a copy of the given token argument, so we don't modify it. */
	if ((token_copy = strdup(orig_token)) == NULL)
		return MSG_MEMORY_ERROR;
	token = token_copy;
					
	while (strsep(&token, "=") != NULL) {
	       	count++;
        }
        free(token_copy);
        
	if (count == 2) 
		return TRUE;
	else 
		return FALSE;

}

static int avc_msg_reformat_path_field_string(char *new_token, char *start_token, char **path_str)
{
	int length;
			
	assert(new_token != NULL && start_token != NULL);
	if (*path_str == NULL) {
		if ((*path_str = (char*) malloc((strlen(start_token) + 1) * sizeof(char))) == NULL) {
			return MSG_MEMORY_ERROR;
		}
		/* Append the start token */
        	strcpy(*path_str, start_token);
	} 
	
	/* Add 2 to concatenate the whitespace char and the terminating string char. */
	length = strlen(*path_str) + strlen(new_token) + 2;
	if ((*path_str = (char*) realloc(*path_str, length * sizeof(char))) == NULL) {
		return MSG_MEMORY_ERROR;;
	}
	*path_str = strcat(*path_str, " ");	
	*path_str = strcat(*path_str, new_token);
		
	return MSG_INSERT_SUCCESS;
}

static unsigned int avc_msg_insert_additional_field_data(char **tokens, msg_t *msg, audit_log_t *log, int *position, int num_tokens)
{
	int i = 0, is_valid, end_fname_idx = 0;
	char *field_value = NULL, *path_str = NULL;
	unsigned int found[AVC_NUM_FIELDS];
	unsigned int return_val = PARSE_RET_SUCCESS;

	assert(tokens != NULL && msg != NULL && log != NULL && *position >= 0 && num_tokens > 0);
	for (i = 0; i < AVC_NUM_FIELDS; i++)
		found[i] = PARSE_NOT_MATCH;

	msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_FS;

	for (i = (*position); i < num_tokens && strcmp(*(&tokens[i]), "") != 0; i++) {
		if (found[AVC_PID_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "pid=", &field_value) != FALSE) {
			found[AVC_PID_FIELD] = avc_msg_insert_uint(&msg->msg_data.avc_msg->pid, &field_value);
			if (found[AVC_PID_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_EXE_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "exe=", &field_value) != FALSE) {
			found[AVC_EXE_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->exe, &field_value);
			if (found[AVC_EXE_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
		
		if (found[AVC_COMM_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "comm=", &field_value) != FALSE) {
			found[AVC_COMM_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->comm, &field_value);
			if (found[AVC_COMM_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
		if (found[AVC_PATH_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "path=", &field_value) != FALSE) {
			/* Gather all tokens located after the path=XXXX token until we encounter a valid additional field. 
			 * This is because a path name file name may be seperated by whitespace. Look ahead at the next 
			 * token, but we make sure not to access memory beyond the total number of tokens. */
			end_fname_idx = i + 1;
			while (end_fname_idx < num_tokens) {
				if ((is_valid = avc_msg_is_valid_additional_field(*(&tokens[end_fname_idx]))) == MSG_MEMORY_ERROR) {
					return PARSE_RET_MEMORY_ERROR;
				} 
				
				if (is_valid) 
					break;	
				
				if (avc_msg_reformat_path_field_string(*(&tokens[end_fname_idx]), *(&tokens[i]), &path_str) == MSG_MEMORY_ERROR) {
					return PARSE_RET_MEMORY_ERROR;
				} 
				end_fname_idx++; 
			}
							
			if (path_str != NULL) {
				found[AVC_PATH_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->path, &path_str);
				free(path_str);
				/* Move the position to the last file name item. */
				i = end_fname_idx - 1;
			} else 
				found[AVC_PATH_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->path, &field_value);
				
			if (found[AVC_PATH_FIELD] == PARSE_RET_MEMORY_ERROR){
				return PARSE_RET_MEMORY_ERROR;
			}
		}

		if (found[AVC_NAME_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "name=", &field_value) != FALSE) {
			found[AVC_NAME_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->name, &field_value);
			if (found[AVC_NAME_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

       
		if (found[AVC_DEV_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "dev=", &field_value) != FALSE) {
			found[AVC_DEV_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->dev, &field_value);
			if (found[AVC_DEV_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_SADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "saddr=", &field_value) != FALSE) {
			found[AVC_SADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->saddr, &field_value);
			if (found[AVC_SADDR_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_SOURCE_FIELD] == PARSE_NOT_MATCH && 
		    (avc_msg_is_prefix(*(&tokens[i]), "source=", &field_value) != FALSE || 
		     avc_msg_is_prefix(*(&tokens[i]), "src=", &field_value) != FALSE)) {
			found[AVC_SOURCE_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->source, &field_value);
			if (found[AVC_SOURCE_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_DADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "daddr=", &field_value) != FALSE) {
			found[AVC_DADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->daddr, &field_value);
			if (found[AVC_DADDR_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_DEST_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "dest=", &field_value) != FALSE) {
			found[AVC_DEST_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->dest, &field_value);
			if (found[AVC_DEST_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
		
		if (found[AVC_NETIF_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "netif=", &field_value) != FALSE) {
			found[AVC_NETIF_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->netif, &field_value);
			if (found[AVC_NETIF_FIELD] == PARSE_RET_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			if (found[AVC_NETIF_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_LADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "laddr=", &field_value) != FALSE) {
			found[AVC_LADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->laddr, &field_value);
			if (found[AVC_LADDR_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_LPORT_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "lport=", &field_value) != FALSE) {
			found[AVC_LPORT_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->lport, &field_value);
			if (found[AVC_LPORT_FIELD] == PARSE_RET_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			else if (found[AVC_LPORT_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_FADDR_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "faddr=", &field_value) != FALSE) {
			found[AVC_FADDR_FIELD] = avc_msg_insert_string(&msg->msg_data.avc_msg->faddr, &field_value);
			if (found[AVC_FADDR_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_FPORT_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "fport=", &field_value) != FALSE) {
			found[AVC_FPORT_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->fport, &field_value);
			if (found[AVC_FPORT_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_PORT_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "port=", &field_value) != FALSE) {
			found[AVC_PORT_FIELD] = avc_msg_insert_int(&msg->msg_data.avc_msg->port, &field_value);
			if (found[AVC_PORT_FIELD] == PARSE_RET_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_NET;
			else if (found[AVC_PORT_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
		
		if (found[AVC_SRC_SID_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "ssid=", &field_value) != FALSE) {
			found[AVC_SRC_SID_FIELD] = avc_msg_insert_uint(&msg->msg_data.avc_msg->src_sid, &field_value);
			if (found[AVC_SRC_SID_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
	
		if (found[AVC_TGT_SID_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "tsid=", &field_value) != FALSE) {
			found[AVC_TGT_SID_FIELD] = avc_msg_insert_uint(&msg->msg_data.avc_msg->tgt_sid , &field_value);
			if (found[AVC_TGT_SID_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
		
		if (found[AVC_CAPABILITY_FIELD] == PARSE_NOT_MATCH &&
		    avc_msg_is_prefix(*(&tokens[i]), "capability=", &field_value) != FALSE) {
			found[AVC_CAPABILITY_FIELD] = avc_msg_insert_capability(msg, &field_value);
			if (found[AVC_CAPABILITY_FIELD] == PARSE_RET_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_CAP;
			else if (found[AVC_CAPABILITY_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_KEY_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "key=", &field_value) != FALSE) {
			found[AVC_KEY_FIELD] = avc_msg_insert_key(msg, &field_value);
			if (found[AVC_KEY_FIELD] == PARSE_RET_SUCCESS)
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_IPC;
			else if (found[AVC_KEY_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}

		if (found[AVC_INODE_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "ino=", &field_value) != FALSE) {
			found[AVC_INODE_FIELD] = avc_msg_insert_ino(msg, &field_value);
			if (found[AVC_INODE_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
	  
		if (found[AVC_SRC_USER_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "scontext=", &field_value) != FALSE){
			found[AVC_SRC_USER_FIELD] = avc_msg_insert_scon(msg, &field_value, log);
			if (found[AVC_SRC_USER_FIELD] == AVC_MSG_INSERT_INVALID_CONTEXT) {
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
				return_val |= PARSE_RET_INVALID_MSG_WARN;
			}
			if (found[AVC_SRC_USER_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
	      		
		if (found[AVC_TGT_USER_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "tcontext=", &field_value) != FALSE){
			found[AVC_TGT_USER_FIELD] = avc_msg_insert_tcon(msg, &field_value, log);
			if (found[AVC_SRC_USER_FIELD] == AVC_MSG_INSERT_INVALID_CONTEXT) {
				msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
				return_val |= PARSE_RET_INVALID_MSG_WARN;
			}
			if (found[AVC_TGT_USER_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
	       
		if (found[AVC_OBJ_CLASS_FIELD] == PARSE_NOT_MATCH && avc_msg_is_prefix(*(&tokens[i]), "tclass=", &field_value) != FALSE){
			found[AVC_OBJ_CLASS_FIELD] = avc_msg_insert_tclass(msg, &field_value, log);
			if (found[AVC_OBJ_CLASS_FIELD] == PARSE_RET_MEMORY_ERROR)
			    return PARSE_RET_MEMORY_ERROR;
		}
		if (field_value == NULL){
			msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
			return_val |= PARSE_RET_INVALID_MSG_WARN;
		}
		field_value = NULL;
		(*position)++;
	}

	if (found[AVC_SRC_SID_FIELD] == PARSE_NOT_MATCH && found[AVC_SRC_USER_FIELD] == PARSE_NOT_MATCH){
		msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
		return PARSE_RET_INVALID_MSG_WARN;
	}
	
	if (found[AVC_TGT_SID_FIELD] == PARSE_NOT_MATCH && found[AVC_TGT_USER_FIELD] == PARSE_NOT_MATCH){
		msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
		return PARSE_RET_INVALID_MSG_WARN;
	}
	
	if (found[AVC_OBJ_CLASS_FIELD] == PARSE_NOT_MATCH){
		msg->msg_data.avc_msg->avc_type = AVC_AUDIT_DATA_MALFORMED;
		return PARSE_RET_INVALID_MSG_WARN;
	}
	       
	return return_val;
}

static unsigned int insert_standard_msg_header(char **tokens, msg_t *msg, audit_log_t *log, int *position, int num_tokens)
{
	unsigned int ret = PARSE_RET_SUCCESS;
	
	assert(tokens != NULL && msg != NULL && log != NULL && *position >= 0);
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	/* Insert time */
	ret |= insert_time(tokens, msg, position, num_tokens);
	if (ret == PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
		
	(*position)++;
	if (*position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	
	/* Insert hostname */
	ret |= insert_hostname(log, tokens, msg, position, num_tokens);
	if (ret == PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
		
	return ret;
}

static unsigned int avc_msg_insert_field_data(char **tokens, msg_t *msg, audit_log_t *log, int num_tokens)
{
	int position = 0;
	unsigned int ret = PARSE_RET_SUCCESS;
	
	assert(tokens != NULL && msg != NULL && log != NULL && num_tokens > 0);
	ret |= insert_standard_msg_header(*(&tokens), msg, log, &position, num_tokens);
	if (ret == PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
		
	/* Check the following token for the string "kernel:". */
	position++;
	if (position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	if (strcmp(*(&tokens[position]), "kernel:") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}

	/* Skip the audit header token, if it exists. */
	if (avc_msg_is_token_new_audit_header(*(&tokens[position]))) {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	
	/* Make sure the following token is the string "avc:" */
	if (strcmp(*(&tokens[position]), "avc:") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;			
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	
	/* Insert denied or granted */
	ret |= avc_msg_insert_access_type(*(&tokens[position]), msg);	
	if (ret == PARSE_RET_SUCCESS) {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
		
	/* Insert perm(s) */
	ret |= avc_msg_insert_perms(tokens, msg, log, &position, num_tokens);
	if (ret == PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
	if (position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	if (ret == PARSE_RET_SUCCESS) {
		position++;
      		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	
	if (strcmp(tokens[position], "for") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
					
	/* At this point we have a valid message, for we have gathered all of the standard fields 
	 * so insert anything else. If nothing else is left, the message is still considered valid. */
	ret |= avc_msg_insert_additional_field_data(tokens, msg, log, &position, num_tokens);
		
	return ret;
}

static int load_policy_msg_is_old_load_policy_string(char **tokens, int *tmp_position, int num_tokens)
{
	int i, rt, length = 0;
	char *tmp = NULL;
	 
	assert(tokens != NULL && *tmp_position >= 0);
	for (i = 0 ; i < 4 ; i++) {
		if ((*tmp_position + i) == num_tokens)
			return FALSE;
		length += strlen(tokens[(*tmp_position) + i]);
	}

	if ((tmp = (char*) malloc((length + 1) * sizeof(char))) == NULL) {
		return MSG_MEMORY_ERROR;
	}
	/* Must inititialize the string before we can concatenate. */
	tmp[0] = '\0';
       
	for (i = 0; i < 4; i++){
		tmp = strcat(tmp, tokens[*tmp_position]);
		(*tmp_position)++;
	}

	rt = strcmp(tmp, OLD_LOAD_POLICY_STRING);
	free(tmp);
	
	if (rt == 0)
		return TRUE;
	else 
		return FALSE;
}

static unsigned int load_policy_msg_get_policy_components(char **tokens, bool_t *found_bools, msg_t **msg, 
							  int position, int num_tokens)
{
	unsigned int ret = PARSE_RET_SUCCESS;
	
	assert(tokens != NULL);
	if (position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	if ((*msg)->msg_data.load_policy_msg->classes == 0 && strstr(tokens[position], "classes")) {
		found_bools[LOAD_POLICY_MSG_CLASSES_FIELD] = TRUE;
		(*msg)->msg_data.load_policy_msg->classes = atoi(tokens[position - 1]); 
	} else if ((*msg)->msg_data.load_policy_msg->rules == 0 && strstr(tokens[position], "rules")) {
		found_bools[LOAD_POLICY_MSG_RULES_FIELD] = TRUE;
		(*msg)->msg_data.load_policy_msg->rules = atoi(tokens[position - 1]); 
	} else if ((*msg)->msg_data.load_policy_msg->users == 0 && strstr(tokens[position], "users")) {
		found_bools[LOAD_POLICY_MSG_USERS_FIELD] = TRUE;
		(*msg)->msg_data.load_policy_msg->users = atoi(tokens[position - 1]); 
	} else if ((*msg)->msg_data.load_policy_msg->roles == 0 && strstr(tokens[position], "roles")) {
		found_bools[LOAD_POLICY_MSG_ROLES_FIELD] = TRUE;
		(*msg)->msg_data.load_policy_msg->roles = atoi(tokens[position - 1]); 
	} else if ((*msg)->msg_data.load_policy_msg->types == 0 && strstr(tokens[position], "types")) {
		found_bools[LOAD_POLICY_MSG_TYPES_FIELD] = TRUE;
		(*msg)->msg_data.load_policy_msg->types = atoi(tokens[position - 1]); 
	} 
		
	return ret;
}

static unsigned int load_policy_msg_insert_field_data(char **tokens, msg_t **msg, FILE *audit_file, 
						      audit_log_t *log, int num_tokens)
{
	int i, length = 0, position = 0, tmp_position, rt;
	unsigned int ret = PARSE_RET_SUCCESS;
	bool_t found[LOAD_POLICY_MSG_NUM_POLICY_COMPONENTS];
	
	assert(tokens != NULL && msg != NULL && *msg != NULL && log != NULL && audit_file != NULL && num_tokens > 0);
	for (i = 0; i < LOAD_POLICY_MSG_NUM_POLICY_COMPONENTS; i++)
		found[i] = FALSE;

	ret |= insert_standard_msg_header(*(&tokens), *msg, log, &position, num_tokens);
	if (ret == PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
				
	position++;
	if (position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;		
	if (strcmp(tokens[position], "invalidating") == 0) {
		return LOAD_POLICY_FALSE_POS;
	}
	
	if ((position + 1) == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	if (strcmp(tokens[position + 1], "bools") == 0) {
		return LOAD_POLICY_FALSE_POS;
	}
	
	/* Check the following token for the string "kernel:" */
	if (strcmp(*(&tokens[position]), "kernel:") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;	
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	
	if (strcmp(tokens[position], "security:")) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
		
	tmp_position = position;
	rt = load_policy_msg_is_old_load_policy_string(*(&tokens), &tmp_position, num_tokens);		
	if (rt == MSG_MEMORY_ERROR) {
		return PARSE_RET_MEMORY_ERROR;
	} else if (rt) {
		position = tmp_position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
		length = strlen(tokens[position]) + 1;

		if (((*msg)->msg_data.load_policy_msg->binary = (char*) malloc(length * sizeof(char))) == NULL) {
			return PARSE_RET_MEMORY_ERROR;
		}
		strcpy((*msg)->msg_data.load_policy_msg->binary, tokens[position]);
		ret |= LOAD_POLICY_NEXT_LINE;
	} else {
		while (position < num_tokens) {
			ret |= load_policy_msg_get_policy_components(*(&tokens), found, msg, position, num_tokens);
			position++;
		}
		
		/* This is rather limiting, but for now we assume that the classes and rules objects signal the end 
		 * of the policy components. So, if we have grabbed these components, then we return SUCCESS flag. */
		if (found[LOAD_POLICY_MSG_CLASSES_FIELD] && found[LOAD_POLICY_MSG_RULES_FIELD]){
			/* Should have already parsed users, roles and types. If not, return INVALID flag. */
			if ((*msg)->msg_data.load_policy_msg->users >= 0 && 
			    (*msg)->msg_data.load_policy_msg->roles >= 0 &&
			    (*msg)->msg_data.load_policy_msg->types >= 0)
				ret |= PARSE_RET_SUCCESS;
			else
				ret |= PARSE_RET_INVALID_MSG_WARN;
		} else if (!((*msg)->msg_data.load_policy_msg->classes && (*msg)->msg_data.load_policy_msg->rules && 
		    (*msg)->msg_data.load_policy_msg->users && (*msg)->msg_data.load_policy_msg->roles && 
		    (*msg)->msg_data.load_policy_msg->types)){
		    	/* Check to see if we have gathered ALL policy components. If not, we need to load the next line. */
			ret |= LOAD_POLICY_NEXT_LINE;
		}
	}
	
	return ret;
}

static unsigned int boolean_msg_insert_bool(char *token, int *bool, bool_t *val, audit_log_t *log)
{
        int len;
	
        len = strlen(token);

	/* Strip off ending comma */
        if (token[len - 1] == ','){
                token[len - 1] = '\0';
                len--;
        }

        if (token[len - 2] != ':')
                return PARSE_RET_INVALID_MSG_WARN;

        if (token[len - 1] == '0')
                *val = FALSE;
        else if (token[len - 1] == '1')
                *val = TRUE;
        else
                return PARSE_RET_INVALID_MSG_WARN;

        token[len - 2] = '\0';

        if (audit_log_add_bool(log, token, bool) == -1)
                return PARSE_RET_MEMORY_ERROR;
 
        return PARSE_RET_SUCCESS;
}

static unsigned int boolean_msg_insert_field_data(char **tokens, msg_t **msg, audit_log_t *log, int num_tokens)
{
        int i, num_bools = 0, num_bools_valid = 0, bool, start_bools_pos;
	int *booleans = NULL, position = 0, bool_idx = 0;
	unsigned int ret = PARSE_RET_SUCCESS, rt;
	bool_t *values = NULL, val;
	
	assert(tokens != NULL && msg != NULL && *msg != NULL && log != NULL && num_tokens > 0);
	ret |= insert_standard_msg_header(*(&tokens), *msg, log, &position, num_tokens);
	if (ret == PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
	
	position++;
	if (position == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	/* Make sure the following token is the string "kernel:" */
	if (strcmp(*(&tokens[position]), "kernel:") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;		
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	if(strcmp(tokens[position], "security:")) {
	        ret |= PARSE_RET_INVALID_MSG_WARN;
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	if(strcmp(tokens[position], "committed")) {
	        ret |= PARSE_RET_INVALID_MSG_WARN;
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	if(strcmp(tokens[position], "booleans")) {
	        ret |= PARSE_RET_INVALID_MSG_WARN;
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	if(strcmp(tokens[position], "{")) {
	        ret |= PARSE_RET_INVALID_MSG_WARN;
	} else {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}

	start_bools_pos = position;
	for (i = position; i < num_tokens && (strcmp(tokens[i], "}") != 0); i++) {
		num_bools++;
		position++;
	}
	/* Make sure that if we have no more tokens, we have grabbed the closing bracket for this to be valid. 
	 * Otherwise, if there are no more tokens and we have grabbed the closing bracket the message is still
	 * incomplete and thus invalid. */
	if (position == num_tokens && strcmp(tokens[position - 1], "}") != 0)
		return PARSE_RET_INVALID_MSG_WARN;
	else if (i == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;

	if (num_bools == 0){
	         return PARSE_RET_INVALID_MSG_WARN;
	}

	if ((booleans = (int*) malloc(num_bools * sizeof(int))) == NULL) {
		return PARSE_RET_MEMORY_ERROR;
	}
	if ((values = (bool_t*) malloc(num_bools * sizeof(bool_t))) == NULL) {
	        free(booleans);
		return PARSE_RET_MEMORY_ERROR;
	}
	
	for (i = 0; i < num_bools; i++){
		rt = boolean_msg_insert_bool(tokens[i + start_bools_pos], &bool, &val, log);
		if (rt == PARSE_RET_MEMORY_ERROR){
		        free(booleans);
		        free(values);
		        return PARSE_RET_MEMORY_ERROR;
		} else if (rt == PARSE_RET_INVALID_MSG_WARN) {
			ret |= PARSE_RET_INVALID_MSG_WARN;
		        continue;
		} 
		booleans[bool_idx] = bool;
		values[bool_idx] = val;
		bool_idx++;
		num_bools_valid++;
	}
	if (num_bools_valid) {
		(*msg)->msg_data.boolean_msg->num_bools = num_bools_valid;
		(*msg)->msg_data.boolean_msg->booleans = booleans;
		(*msg)->msg_data.boolean_msg->values = values;
	} 

        return ret;
}

static int free_field_tokens(char **fields, int num_tokens)
{
	int i;
	
	if (fields != NULL) {
		for (i = 0; i < num_tokens; i++)
			free(fields[i]);
		free(fields);
		fields = NULL;
	}
	return 0;
}

static unsigned int get_tokens(char *line, int msgtype, audit_log_t *log, FILE *audit_file, msg_t **msg)
{
	char *tokens = NULL, *tmp = NULL, **fields = NULL;
	int idx = 0, num_tokens = 0;
	unsigned int ret = PARSE_RET_SUCCESS;
	
	assert(msg != NULL && log != NULL && audit_file != NULL);	
	tokens = line;
	
	/* Tokenize line while ignoring any adjacent whitespace chars. */ 
        while ((tmp = strsep(&tokens, " ")) != NULL) {
	       	if (strcmp(tmp, "") && !str_is_only_white_space(tmp)) {
	       		num_tokens++;
	         	if ((fields = (char**)realloc(fields, num_tokens * sizeof(char*))) == NULL) {
				return PARSE_RET_MEMORY_ERROR;
			}
			if((fields[idx] = (char*)malloc((strlen(tmp) + 1) * sizeof(char))) == NULL) {
				/* Free all tokens up to the previous token, which is number of tokens - 1. */
				free_field_tokens(*(&fields), num_tokens - 1);	
				return PARSE_RET_MEMORY_ERROR;
			}
			strcpy(fields[idx], tmp);
			idx++;
       	       	}
        }
     		
	if (msgtype == PARSE_AVC_MSG) {
		if (*msg == NULL)
			*msg = avc_msg_create();
		ret |= avc_msg_insert_field_data(fields, *msg, log, num_tokens);
		if (ret == PARSE_RET_MEMORY_ERROR) {
			msg_destroy(*msg);
			*msg = NULL;
			free_field_tokens(*(&fields), num_tokens);
			return PARSE_RET_MEMORY_ERROR;
		} else {
			if (audit_log_add_msg(log, *msg) == -1){
				free_field_tokens(*(&fields), num_tokens);			
				return PARSE_RET_MEMORY_ERROR;
			}
			*msg = NULL;
		}
	} else if (msgtype == PARSE_LOAD_MSG) {
		if (*msg == NULL)
			*msg = load_policy_msg_create();
		
		ret |= load_policy_msg_insert_field_data(fields, msg, audit_file, log, num_tokens);
		if (ret == PARSE_RET_MEMORY_ERROR || ret == LOAD_POLICY_FALSE_POS) {
			msg_destroy(*msg);
			*msg = NULL;
			free_field_tokens(*(&fields), num_tokens);
			return PARSE_RET_MEMORY_ERROR;
		} else if (ret == LOAD_POLICY_NEXT_LINE) {
			/* Don't add the message to the log yet, but hold the pointer to the message. */
			ret = LOAD_POLICY_NEXT_LINE;
		} else {
			if (audit_log_add_msg(log, *msg) == -1) {
				free_field_tokens(*(&fields), num_tokens);
				return PARSE_RET_MEMORY_ERROR;
			}
			/* Reset pointer to message. */
			*msg = NULL;
		}
	} else if (msgtype == PARSE_BOOL_MSG) {
		if (*msg == NULL)
			*msg = boolean_msg_create();
			
	        ret |= boolean_msg_insert_field_data(fields, msg, log, num_tokens);
		if (ret == PARSE_RET_MEMORY_ERROR) {
			msg_destroy(*msg); 
			*msg = NULL;
			free_field_tokens(*(&fields), num_tokens);
			return PARSE_RET_MEMORY_ERROR;
		} else {
			if (audit_log_add_msg(log, *msg) == -1){
				free_field_tokens(*(&fields), num_tokens);				
				return PARSE_RET_MEMORY_ERROR;
			}       
			*msg = NULL;
	        }      
	 } else {
		fprintf(stderr, "Invalid message type provided: %d\n", msgtype);
	}
	free_field_tokens(*(&fields), num_tokens);
	
	return ret;
}

unsigned int parse_audit(FILE *syslog, audit_log_t *log)
{
	FILE *audit_file = syslog;
	msg_t *msg = NULL;
	char *line = NULL;
	int is_sel = -1, selinux_msg = 0;
	unsigned int ret = PARSE_RET_SUCCESS;
	
	assert(audit_file != NULL && log != NULL);       
	clearerr(audit_file);
	if (feof(audit_file))
		return PARSE_RET_EOF_ERROR;

	if (get_line(audit_file, &line) & PARSE_RET_MEMORY_ERROR) {
		return PARSE_RET_MEMORY_ERROR;
	}
	if (trim_string(&line) != 0)
		return PARSE_RET_MEMORY_ERROR;
		
	while (line != NULL) {
     		is_sel = is_selinux(line);
		if (is_sel != PARSE_NON_SELINUX) {
			if (ret == LOAD_POLICY_NEXT_LINE && is_sel != PARSE_LOAD_MSG) {
				ret = PARSE_RET_INVALID_MSG_WARN;
				msg = NULL;
			}
			ret = get_tokens(line, is_sel, log, audit_file, &msg);	
		
			if (ret == PARSE_RET_MEMORY_ERROR) {
				return PARSE_RET_MEMORY_ERROR;
			} else if (ret == PARSE_RET_INVALID_MSG_WARN) {
				ret = PARSE_RET_INVALID_MSG_WARN;
				selinux_msg++;
			} else if (ret == PARSE_RET_SUCCESS) {
				selinux_msg++;
			}
		}
		free(line);
		line = NULL;
		if (get_line(audit_file, &line) & PARSE_RET_MEMORY_ERROR) {
			return PARSE_RET_MEMORY_ERROR;
		}
	}
	
	if (selinux_msg == 0)
		return PARSE_RET_NO_SELINUX_ERROR;
		
	return ret;
}














