/**
 *  @file parse.c
 *  Implementation for the audit log parser.
 *
 *  @author Meggan Whalen mwhalen@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Jason Tang jtang@tresys.com
 *
 *  Copyright (C) 2003-2006 Tresys Technology, LLC
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "seaudit_internal.h"
#include <seaudit/parse.h>
#include <apol/util.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define ALT_SYSCALL_STRING "msg=audit("  /* should contain SYSCALL_STRING */
#define AUDITD_MSG "type="
#define AVCMSG " avc: "
#define BOOLMSG "committed booleans"
#define LOADMSG " security: "
#define MEMORY_BLOCK_MAX_SIZE 512
#define NUM_TIME_COMPONENTS 3
#define PARSE_NUM_CONTEXT_FIELDS 3
#define PARSE_NUM_SYSCALL_FIELDS 3
#define SYSCALL_STRING "audit("

#if 0
#define OLD_LOAD_POLICY_STRING "loadingpolicyconfigurationfrom"
#define PARSE_NOT_MATCH -1
#define MSG_MEMORY_ERROR -1
#define MSG_INSERT_SUCCESS 0
#define AVC_MSG_INSERT_INVALID_CONTEXT -2

#define LOAD_POLICY_MSG_USERS_FIELD   0
#define LOAD_POLICY_MSG_ROLES_FIELD   1
#define LOAD_POLICY_MSG_TYPES_FIELD   2
#define LOAD_POLICY_MSG_CLASSES_FIELD 3
#define LOAD_POLICY_MSG_RULES_FIELD   4
#define LOAD_POLICY_MSG_BOOLS_FIELD   5
#define LOAD_POLICY_MSG_NUM_POLICY_COMPONENTS 6

#endif

/**
 * Allocate a string and return the next line within the file pointer.
 * The caller is responsible for free()ing the string.
 */
static int get_line(seaudit_log_t *log, FILE *audit_file, char **dest)
{
	char *line = NULL, *s, c = '\0';
	int  length = 0, i = 0, error;

	*dest = NULL;
	while ((c = fgetc(audit_file)) != EOF) {
		if (i < length - 1) {
			line[i] = c;
		} else {
			length += MEMORY_BLOCK_MAX_SIZE;
			if ((s = (char*) realloc(line, length * sizeof(char))) == NULL) {
				error = errno;
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
			line = s;
			line[i] = c;
		}

		if (c == '\n') {
			line[i+1] = '\0';
			*dest = line;
                        return 0;
		}
		i++;
	}

	if (i > 0) {
		if (i < length - 1) {
			line[i] = '\0';
			*dest = line;
		} else {
			length += MEMORY_BLOCK_MAX_SIZE;
			if ((s = (char*) realloc(line, length * sizeof(char))) == NULL) {
				error = errno;
				ERR(log, "%s", strerror(error));
				errno = error;
				return -1;
			}
			line = s;
			line[i] = '\0';
			*dest = line;
		}
	}
        return 0;
}

/**
 * Given a line from an audit log, create and return a vector of
 * tokens from that line.  The caller is responsible for calling
 * apol_vector_destroy() upon that vector, passing free as the second
 * parameter.
 */
static int get_tokens(seaudit_log_t *log, const char *line, apol_vector_t **tokens)
{
	char *line_dup = NULL, *line_ptr, *next;
	*tokens = NULL;
	int error = 0;

	if ((line_dup = strdup(line)) == NULL ||
	    (*tokens = apol_vector_create()) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		goto cleanup;
	}
	line_ptr = line_dup;
	/* Tokenize line while ignoring any adjacent whitespace chars. */
	while ((next = strsep(&line_ptr, " ")) != NULL) {
		if (strcmp(next, "") && !apol_str_is_only_white_space(next)) {
			if (apol_vector_append(*tokens, next) < 0) {
				error = errno;
				ERR(log, "%s", strerror(error));
				goto cleanup;
			}
		}
	}
 cleanup:
	free(line_dup);
	apol_vector_destroy(tokens, NULL);
	if (error != 0) {
		errno = error;
		return -1;
	}
	return 0;
}


/**
 * Given a line, determine what type of audit message it is.
 */
static seaudit_message_type_e is_selinux(char *line)
{
	if (strstr(line, BOOLMSG) && (strstr(line, "kernel") || strstr(line, AUDITD_MSG)))
		return SEAUDIT_MESSAGE_TYPE_BOOL;
	else if (strstr(line, LOADMSG) && (strstr(line, "kernel") || strstr(line, AUDITD_MSG)))
		return SEAUDIT_MESSAGE_TYPE_LOAD;
	else if (strstr(line, AVCMSG) && (strstr(line, "kernel") || strstr(line, AUDITD_MSG)))
		return SEAUDIT_MESSAGE_TYPE_AVC;
	else
		return SEAUDIT_MESSAGE_TYPE_INVALID;
}

/**
 * Fill in the date_stamp field of a message.  If the stamp was not
 * already allocated space then do it here.
 *
 * @return 0 on success, > 0 on warning, < 0 on error.
 */
static int insert_time(seaudit_log_t *log, apol_vector_t *tokens, size_t *position, seaudit_message_t *msg)
{
	char *t = NULL;
	size_t i, length = 0;
	int error;
	extern int daylight;

	if (*position + NUM_TIME_COMPONENTS >= apol_vector_get_size(tokens)) {
		WARN(log, "%s", "Not enough tokens for time.");
		return 1;
	}
	for (i = 0; i < NUM_TIME_COMPONENTS; i++) {
		length += strlen((char *) apol_vector_get_element(tokens, i + *position));
	}

	/* Increase size for terminating string char and whitespace within. */
	length += 1 + (NUM_TIME_COMPONENTS - 1);
	if ((t = (char*) calloc(1, length)) == NULL) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}

	for (i = 0; i < NUM_TIME_COMPONENTS; i++) {
		if (i > 0) {
			strcat(t, " ");
		}
		strcat(t, (char *) apol_vector_get_element(tokens, i + *position));
		(*position)++;
	}

	if (!msg->date_stamp) {
		if ((msg->date_stamp = (struct tm*) calloc(1, sizeof(struct tm))) == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			free(t);
			errno = error;
			return -1;
		}
	}

	if (strptime(t, "%b %d %T", msg->date_stamp) != NULL) {
		/* set year to 1900 since we know no valid logs were
		   generated.  this will tell us that the msg does not
		   really have a year */
		msg->date_stamp->tm_isdst = 0;
		msg->date_stamp->tm_year = 0;
	}
	free(t);
	return 0;
}

/**
 * Fill in the host field of a message.
 *
 * @return 0 on success, > 0 on warning, < 0 on error.
 */
static int insert_hostname(seaudit_log_t *log, apol_vector_t *tokens, size_t *position, seaudit_message_t *msg)
{
	char *s, *host;
	if (*position >= apol_vector_get_size(tokens)) {
		WARN(log, "%s", "Not enough tokens for hostname.");
		return 1;
	}
        s = apol_vector_get_element(tokens, *position);
	(*position)++;
	/* Make sure this is not the kernel string identifier, which
	 * may indicate that the hostname is empty. */
	if (strstr(s, "kernel")) {
		msg->host = NULL;
		return 1;
	}
	if ((host = strdup(s)) == NULL ||
	    apol_bst_insert_and_get(log->hosts, (void **) &host, NULL, free) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	free(msg->host);
	msg->host = host;
	return 0;
}

static int insert_standard_msg_header(seaudit_log_t *log, apol_vector_t *tokens, size_t *position, seaudit_message_t *msg)
{
	int ret = 0;
	if ((ret = insert_time(log, tokens, position, msg)) != 0) {
		return ret;
	}
	if ((ret = insert_hostname(log, tokens, position, msg)) != 0) {
		return ret;
	}
	return ret;
}

/**
 * Parse a context (user:role:type).  For each of the pieces, add them
 * to the log's BSTs.  Set reference pointers to those strings.
 */
static int parse_context(seaudit_log_t *log, char *token, char **user, char **role, char **type)
{
	size_t i = 0;
	char *fields[PARSE_NUM_CONTEXT_FIELDS], *s;
	int error;

	*user = *role = *type = NULL;
	while (i < PARSE_NUM_CONTEXT_FIELDS && (fields[i] = strsep(&token,":")) != NULL){
		i++;
	}
	if (i != PARSE_NUM_CONTEXT_FIELDS) {
		WARN(log, "%s", "Not enough tokens for context.");
		return 1;
	}

	if ((s = strdup(fields[0])) == NULL ||
	    apol_bst_insert_and_get(log->users, (void **) &s, NULL, free) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	*user = s;

	if ((s = strdup(fields[1])) == NULL ||
	    apol_bst_insert_and_get(log->roles, (void **) &s, NULL, free) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	*role = s;

	if ((s = strdup(fields[2])) == NULL ||
	    apol_bst_insert_and_get(log->types, (void **) &s, NULL, free) < 0) {
		error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	*type = s;

	return 0;
}

/******************** AVC message parsing ********************/


/**
 * Given a token, determine if it is the new AVC header or not.
 */
static int avc_msg_is_token_new_audit_header(char *token)
{
	return (strstr(token, SYSCALL_STRING) ? 1 : 0);
}

/**
 * If the given token begins with prefix, then set reference pointer
 * result to everything following prefix and return 1.  Otherwise
 * return 0.
 */
static int avc_msg_is_prefix(char *token, char *prefix, char **result)
{
	size_t i = 0, length;

	length = strlen(prefix);
	if (strlen(token) < length)
		return 0;

	for (i = 0; i < length; i++) {
		if (token[i] != prefix[i]) {
			return 0;
		}
	}

	*result = token + length;
	return 1;
}

/**
 * Beginning with element *position, fill in the given avc message
 * with all permissions found.  Afterwards update *position to point
 * to the next unprocessed token.  Permissions should start and end
 * with braces and if not, then this is invalid.
 *
 * @return 0 on success, > 0 on warning, < 0 on error.
 */
static int avc_msg_insert_perms(seaudit_log_t *log,
				apol_vector_t *tokens,
				size_t *position,
				seaudit_avc_message_t *msg)
{
	char *s, *perm;
	int error;
	if ((s = apol_vector_get_element(tokens, *position)) == NULL ||
	    strcmp(s, "{") != 0) {
		WARN(log, "%s", "Expected an opening brace while parsing permissions.");
		return 1;
	}
	(*position)++;

	while (*position < apol_vector_get_size(tokens)) {
		s = apol_vector_get_element(tokens, *position);
		assert(s != NULL);
		(*position)++;
		if (strcmp(s, "}") == 0) {
			return 0;
		}

		if ((perm = strdup(s)) == NULL ||
		    apol_bst_insert_and_get(log->perms, (void **) &perm, NULL, free) < 0 ||
		    apol_vector_append(msg->perms, perm) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}

	/* if got here, then message is too short */
	WARN(log, "%s", "Expected a closing brace while parsing permissions.");
	return 1;
}

static int avc_msg_insert_syscall_info(seaudit_log_t *log, char *token, seaudit_message_t *msg, seaudit_avc_message_t *avc)
{
	size_t length, header_len = 0, i = 0;
	char *fields[PARSE_NUM_SYSCALL_FIELDS];
	char *time_str = NULL;
	time_t temp;

	length = strlen(token);

	/* Chop off the ':' at the end of the syscall info token */
	if (token[length - 1] == ':') {
		token[length - 1] = '\0';
		length--;
	}
	/* Chop off the ')' at the end of the syscall info token */
	if (token[length - 1] == ')') {
		token[length - 1] = '\0';
		length--;
	}
	header_len = strlen(SYSCALL_STRING);

	/* Check to see if variations on syscall header exist */
	if (strstr(token, ALT_SYSCALL_STRING)) {
		header_len = strlen(ALT_SYSCALL_STRING);
	}

	time_str = token + header_len;
	/* Parse seconds.nanoseconds:serial */
	while (i < PARSE_NUM_SYSCALL_FIELDS && (fields[i] = strsep(&time_str, ".:")) != NULL) {
		i++;
	}

	if (i != PARSE_NUM_SYSCALL_FIELDS) {
		WARN(log, "%s", "Not enough fields for syscall info.");
		return 1;
	}

	temp = (time_t) atol(fields[0]);
	avc->tm_stmp_sec = temp;
	avc->tm_stmp_nano = atoi(fields[1]);
	avc->serial = atoi(fields[2]);

	if (msg->date_stamp == NULL) {
		if ((msg->date_stamp = (struct tm*) malloc(sizeof(struct tm))) == NULL) {
			int error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}
	localtime_r(&temp, msg->date_stamp);
	return 0;
}

static int avc_msg_insert_access_type(seaudit_log_t *log, char *token, seaudit_avc_message_t *avc)
{
	if (strcmp(token, "granted") == 0) {
		avc->msg = SEAUDIT_AVC_GRANTED;
		return 0;
	}
	else if (strcmp(token, "denied") == 0) {
		avc->msg = SEAUDIT_AVC_DENIED;
		return 0;
	}
	WARN(log, "%s", "No AVC message type found.");
	return 1;
}

static int avc_msg_insert_scon(seaudit_log_t *log, seaudit_avc_message_t *avc, char *tmp)
{
	char *user, *role, *type;
	int retval;
	if (tmp == NULL) {
		WARN(log, "%s", "Invalid source context.");
		return 1;
	}
	retval = parse_context(log, tmp, &user, &role, &type);
	if (retval != 0) {
		return retval;
	}
	avc->suser = user;
	avc->srole = role;
	avc->stype = type;
	return 0;
}

static int avc_msg_insert_tcon(seaudit_log_t *log, seaudit_avc_message_t *avc, char *tmp)
{
	char *user, *role, *type;
	int retval;
	if (tmp == NULL) {
		WARN(log, "%s", "Invalid target context.");
		return 1;
	}
	retval = parse_context(log, tmp, &user, &role, &type);
	if (retval != 0) {
		return retval;
	}
	avc->tuser = user;
	avc->trole = role;
	avc->ttype = type;
	return 0;
}

static int avc_msg_insert_tclass(seaudit_log_t *log, seaudit_avc_message_t *avc, char *tmp)
{
	char *tclass;
	if ((tclass = strdup(tmp)) == NULL ||
	    apol_bst_insert_and_get(log->classes, (void **) &tclass, NULL, free) < 0) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	free(avc->tclass);
	avc->tclass = tclass;
	return 0;
}

static int avc_msg_insert_string(seaudit_log_t *log, char *src, char **dest)
{
	if ((*dest = strdup(src)) == NULL) {
		int error = errno;
		ERR(log, "%s", strerror(error));
		errno = error;
		return -1;
	}
	return 0;
}

/**
 * Removes quotes from a string, this is currently to remove quotes
 * from the command argument.
 */
static int avc_msg_remove_quotes_insert_string(seaudit_log_t *log, char *src, char **dest)
{
	size_t i, j, l;

	l = strlen(src);
	/* see if there are any quotes to begin with if there aren't
	   just run insert string */
	if (src[0] == '\"' && l > 0 && src[l - 1] == '\"') {
		if ((*dest = calloc(1, l + 1)) == NULL) {
			int error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		for (i = 0, j = 0; i < l; i++) {
			if (src[i] != '\"') {
				(*dest)[j] = src[i];
				j++;
			}
		}
		return 0;
	} else
		return avc_msg_insert_string(log, src, dest);
}

/**
 * If there is exactly one equal sign in orig_token then return 1.
 * Otherwise return 0.
 */
static int avc_msg_is_valid_additional_field(char *orig_token)
{
	char *first_eq = strchr(orig_token, '=');

	if (first_eq != NULL) {
		return 0;
	}
	if (strchr(first_eq + 1, '=') != NULL) {
		return 0;
	}
	return 1;
}

static int avc_msg_reformat_path(seaudit_log_t *log, seaudit_avc_message_t *avc, char *token)
{
	int error;
	if (avc->path == NULL) {
		if ((avc->path = strdup(token)) == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
	}
	else {
		size_t len = strlen(avc->path) + strlen(token) + 2;
		char *s = realloc(avc->path, len);
		if (s == NULL) {
			error = errno;
			ERR(log, "%s", strerror(error));
			errno = error;
			return -1;
		}
		avc->path = s;
		strcat(avc->path, " ");
		strcat(avc->path, token);
	}
	return 0;
}

/**
 * Parse the remaining tokens of an AVC message, filling as much
 * information as possible.
 *
 * @return 0 on success, > 0 if warnings, < 0 on error
 */
static int avc_msg_insert_additional_field_data(seaudit_log_t *log, apol_vector_t *tokens, seaudit_avc_message_t *avc, size_t *position)
{
	char *token, *v;
	int retval, has_warnings = 0;

	avc->avc_type = SEAUDIT_AVC_DATA_FS;
	for ( ; (*position) < apol_vector_get_size(tokens); (*position)++) {
		token = apol_vector_get_element(tokens, (*position));
		v = NULL;
		if (strcmp(token, "") == 0) {
			break;
		}

		if (!avc->is_pid && avc_msg_is_prefix(token, "pid=", &v)) {
			avc->pid = atoi(v);
			avc->is_pid = 1;
			continue;
		}

		if (!avc->exe && avc_msg_is_prefix(token, "exe=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->exe) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->comm && avc_msg_is_prefix(token, "comm=", &v)) {
			if (avc_msg_remove_quotes_insert_string(log, v, &avc->comm) < 0) {
				return -1;
			}
			continue;
		}

		/* Gather all tokens located after the path=XXXX token
		 * until we encounter a valid additional field.  This
		 * is because a path name file name may be seperated
		 * by whitespace.  Look ahead at the next token, but we
		 * make sure not to access memory beyond the total
		 * number of tokens. */
		if (!avc->path && avc_msg_is_prefix(token, "path=", &v)) {
			if (avc_msg_reformat_path(log, avc, v) < 0) {
				return -1;
			}
			while (*position + 1 < apol_vector_get_size(tokens)) {
				token = apol_vector_get_element(tokens, *position + 1);
				if (avc_msg_is_valid_additional_field(token)) {
					break;
				}
				(*position)++;
				if (avc_msg_reformat_path(log, avc, token) < 0) {
					return -1;
				}
			}
			continue;
		}

		if (!avc->name && avc_msg_is_prefix(token, "name=", &v)) {
			if (avc_msg_remove_quotes_insert_string(log, v, &avc->name) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->dev && avc_msg_is_prefix(token, "dev=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->dev) < 0) {
				return -1;
			}
			continue;
		}


		if (!avc->saddr && avc_msg_is_prefix(token, "saddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->saddr) < 0) {
				return -1;
			}
			continue;
		}

		if (!avc->source &&
		    (avc_msg_is_prefix(token, "source=", &v) ||
		     avc_msg_is_prefix(token, "src=", &v))) {
			avc->source = atoi(v);
			continue;
		}

		if (!avc->daddr && avc_msg_is_prefix(token, "daddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->daddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->dest && avc_msg_is_prefix(token, "dest=", &v)) {
			avc->dest = atoi(v);
			continue;
		}

		if (!avc->netif && avc_msg_is_prefix(token, "netif=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->netif)) {
				return -1;
			}
			avc->avc_type = SEAUDIT_AVC_DATA_NET;
			continue;
		}

		if (!avc->laddr && avc_msg_is_prefix(token, "laddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->laddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->lport && avc_msg_is_prefix(token, "lport=", &v)) {
			avc->lport = atoi(v);
			avc->avc_type = SEAUDIT_AVC_DATA_NET;
			continue;
		}


		if (!avc->faddr && avc_msg_is_prefix(token, "faddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->faddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->fport && avc_msg_is_prefix(token, "fport=", &v)) {
			avc->fport = atoi(v);
			continue;
		}

		if (!avc->port && avc_msg_is_prefix(token, "port=", &v)) {
			avc->port = atoi(v);
			avc->avc_type = SEAUDIT_AVC_DATA_NET;
			continue;
		}

		if (!avc->is_src_sid && avc_msg_is_prefix(token, "ssid=", &v)) {
			avc->src_sid = (unsigned int) strtoul(v, NULL, 10);
			avc->is_src_sid = 1;
			continue;
		}

		if (!avc->is_tgt_sid && avc_msg_is_prefix(token, "tsid=", &v)) {
			avc->tgt_sid = (unsigned int) strtoul(v, NULL, 10);
			avc->is_tgt_sid = 1;
			continue;
		}

		if (!avc->is_capability && avc_msg_is_prefix(token, "capability=", &v)) {
			avc->capability = atoi(v);
			avc->is_capability = 1;
			avc->avc_type = SEAUDIT_AVC_DATA_CAP;
			continue;
		}

		if (!avc->is_key && avc_msg_is_prefix(token, "key=", &v)) {
			avc->key = atoi(v);
			avc->is_key = 1;
			avc->avc_type = SEAUDIT_AVC_DATA_IPC;
			continue;
		}

		if (!avc->is_inode && avc_msg_is_prefix(token, "ino=", &v)) {
			avc->inode = strtoul(v, NULL, 10);
			avc->is_inode = 1;
			continue;
		}

		if (!avc->ipaddr && avc_msg_is_prefix(token, "ipaddr=", &v)) {
			if (avc_msg_insert_string(log, v, &avc->ipaddr)) {
				return -1;
			}
			continue;
		}

		if (!avc->suser && avc_msg_is_prefix(token, "scontext=", &v)) {
			retval = avc_msg_insert_scon(log, avc, v);
			if (retval < 0) {
				return retval;
			}
			else if (retval > 0) {
				has_warnings = 1;
			}
			continue;
		}

		if (!avc->tuser && avc_msg_is_prefix(token, "tcontext=", &v)) {
			retval = avc_msg_insert_tcon(log, avc, v);
			if (retval < 0) {
				return retval;
			}
			else if (retval > 0) {
				has_warnings = 1;
			}
			continue;
		}

		if (!avc->tclass && avc_msg_is_prefix(token, "tclass=", &v)) {
			if (avc_msg_insert_tclass(log, avc, v) < 0) {
				return -1;
			}
			continue;
		}

		has_warnings = 1;
	}

	/* can't have both a sid and a context */
	if ((avc->is_src_sid && avc->suser) ||
	    (avc->is_tgt_sid && avc->tuser)) {
		has_warnings = 1;
	}

	if (!avc->tclass) {
		has_warnings = 1;
	}

	if (has_warnings) {
		avc->avc_type = SEAUDIT_AVC_DATA_MALFORMED;
	}

	return has_warnings;
}

static int avc_parse(seaudit_log_t *log, apol_vector_t *tokens)
{
        seaudit_message_t *msg;
        seaudit_avc_message_t *avc;
        seaudit_message_type_e type;
	int ret, has_warnings = 0;
	size_t position = 0, num_tokens = apol_vector_get_size(tokens);
	char *token;

	if ((msg = message_create(log, SEAUDIT_MESSAGE_TYPE_AVC)) == NULL) {
		return -1;
	}
	avc = seaudit_message_get_data(msg, &type);

	token = apol_vector_get_element(tokens, position);

	/* Check for new auditd log format */
	if (strstr(token, AUDITD_MSG)) {
		position++;
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for audit header.");
			return 1;
		}
		log->logtype = SEAUDIT_LOG_TYPE_AUDITD;
		token = apol_vector_get_element(tokens, position);
	}

	/* Insert the audit header if it exists */
	if (avc_msg_is_token_new_audit_header(token)) {
		ret = avc_msg_insert_syscall_info(log, token, msg, avc);
		if (ret < 0) {
			return ret;
		}
		else if (ret > 0) {
			has_warnings = 1;
		}
		else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for new audit header.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}
	}
	else {
		ret = insert_standard_msg_header(log, tokens, &position, msg);
		if (ret < 0) {
			return ret;
		}
		else if (ret > 0) {
			has_warnings = 1;
		}
		if (position >= num_tokens) {
			WARN(log, "%s", "Not enough tokens for new audit header.");
			return 1;
		}
		token = apol_vector_get_element(tokens, position);

		if (!strstr(token, "kernel")) {
			WARN(log, "%s", "Expected to see kernel here.");
			has_warnings = 1;
			/* Hold the position */
		} else {
			position++;
			if (position >= num_tokens) {
				WARN(log, "%s", "Not enough tokens for new audit header.");
				return 1;
			}
			token = apol_vector_get_element(tokens, position);
		}

		/* new style audit messages can show up in syslog
		 * files starting with FC5. This means that both the
		 * old kernel: header and the new audit header might
		 * be present. So, here we check again for the audit
		 * message.
		 */
		if (avc_msg_is_token_new_audit_header(token)) {
			ret = avc_msg_insert_syscall_info(log, token, msg, avc);
			if (ret < 0) {
				return ret;
			}
			else if (ret > 0) {
				has_warnings = 1;
			}
			else {
				position += 2;
				if (position >= num_tokens) {
					WARN(log, "%s", "Not enough tokens for new audit header.");
					return 1;
				}
				token = apol_vector_get_element(tokens, position);
			}
		}
	}

	return has_warnings;
}

/******************** boolean parsing ********************/

static int bool_parse(seaudit_log_t *log, apol_vector_t *tokens)
{
        int retval = -1;
        return retval;
}

/******************** policy load parsing ********************/

static int load_parse(seaudit_log_t *log, apol_vector_t *tokens)
{
        int retval = -1;
        return retval;
}

int seaudit_log_parse(seaudit_log_t *log, FILE *syslog)
{
	FILE *audit_file = syslog;
	char *line = NULL;
	seaudit_message_type_e is_sel;
	apol_vector_t *tokens = NULL;
	int retval = -1, retval2, has_warnings = 0, error = 0;

	if (log == NULL || syslog == NULL) {
		ERR(log, "%s", strerror(EINVAL));
		error = EINVAL;
		goto cleanup;
	}

	if (!log->tz_initialized) {
		tzset();
		log->tz_initialized = 1;
	}

	clearerr(audit_file);
	if (feof(audit_file)) {
		ERR(log, "%s", strerror(EIO));
		errno = EIO;
		return -1;
	}

	while (1) {
		free(line);
		apol_vector_destroy(&tokens, NULL);
		if (get_line(log, audit_file, &line) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		if (line == NULL) {
			break;
		}

		if (apol_str_trim(&line) != 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		is_sel = is_selinux(line);
		if (is_sel == SEAUDIT_MESSAGE_TYPE_INVALID) {
			continue;
		}
                /* FIX ME
		if (log->next_line) {
			log->next_line = 0;
			if (is_sel != SEAUDIT_MESSAGE_TYPE_LOAD) {
				WARN(log, "%s", "Parser was in the middle of a line, but message is not a load message.");
				has_warnings = 1;
				continue;
			}

		}
                */

		if (get_tokens(log, line, &tokens) < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}

		switch (is_sel) {
		case SEAUDIT_MESSAGE_TYPE_AVC:
			retval2 = avc_parse(log, tokens);
			break;
		case SEAUDIT_MESSAGE_TYPE_BOOL:
			retval2 = bool_parse(log, tokens);
			break;
		case SEAUDIT_MESSAGE_TYPE_LOAD:
			retval2 = load_parse(log, tokens);
			break;
		default:
			/* should never get here */
			assert(0);
		}
		if (retval2 < 0) {
			error = errno;
			ERR(log, "%s", strerror(error));
			goto cleanup;
		}
		else if (retval2 > 0) {
			has_warnings = 1;
		}
	}

        retval = 0;
 cleanup:
	free(line);
	apol_vector_destroy(&tokens, NULL);
        if (retval < 0) {
                errno = error;
                return -1;
        }
	return has_warnings;
}


#if 0

static int avc_msg_insert_field_data(seaudit_log_t *log, apol_vector_t *tokens, seaudit_avc_message_t *avc)
{
	/* Check for new auditd log format */
	if (strstr(tokens[position], AUDITD_MSG)) {
		position++;
		if (position >= num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
		if (audit_log_get_log_type(log) != AUDITLOG_AUDITD)
			audit_log_set_log_type(log, AUDITLOG_AUDITD);
	}

	/* Insert the audit header if it exists */
	if (avc_msg_is_token_new_audit_header(tokens[position])) {
		tmp_ret |= avc_msg_insert_syscall_info(tokens[position], msg);
		if (tmp_ret & PARSE_RET_SUCCESS) {
			position++;
			if (position >= num_tokens)
				return PARSE_RET_INVALID_MSG_WARN;
		}
		ret |= tmp_ret;
		/* Reset our bitmask */
		tmp_ret = 0;
	} else {
		tmp_ret |= insert_standard_msg_header(tokens, msg, log, &position, num_tokens);
		if (tmp_ret & PARSE_RET_MEMORY_ERROR)
			return PARSE_RET_MEMORY_ERROR;
		else if (tmp_ret & PARSE_REACHED_END_OF_MSG)
			return PARSE_RET_INVALID_MSG_WARN;
		else if (!(tmp_ret & PARSE_RET_INVALID_MSG_WARN)) {
			position += 2;
			if (position >= num_tokens)
				return PARSE_RET_INVALID_MSG_WARN;
		}
		ret |= tmp_ret;
		/* Reset our bitmask */
		tmp_ret = 0;

		if (!strstr(tokens[position], "kernel")) {
			ret |= PARSE_RET_INVALID_MSG_WARN;
			/* Hold the position */
		} else {
			position++;
			if (position >= num_tokens)
				return PARSE_RET_INVALID_MSG_WARN;
		}

		/* new style audit messages can show up in syslog files starting with
		 * FC5. This means that both the old kernel: header and the new
		 * audit header might be present. So, here we check again for the
		 * audit message.
		 */
		if (avc_msg_is_token_new_audit_header(tokens[position])) {
			tmp_ret |= avc_msg_insert_syscall_info(tokens[position], msg);
			if (tmp_ret & PARSE_RET_SUCCESS) {
				position += 2;
				if (position >= num_tokens)
					return PARSE_RET_INVALID_MSG_WARN;
			}
			ret |= tmp_ret;
			/* Reset our bitmask */
			tmp_ret = 0;
		}

	}

	/* Make sure the following token is the string "avc:" */
	if (strcmp(tokens[position], "avc:") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;
		if (position >= num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}

	/* Insert denied or granted */
	tmp_ret |= avc_msg_insert_access_type(tokens[position], msg);
	if (tmp_ret & PARSE_RET_SUCCESS) {
		position++;
		if (position >= num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	ret |= tmp_ret;
	/* Reset our bitmask */
	tmp_ret = 0;

	/* Insert perm(s) */
	tmp_ret |= avc_msg_insert_perms(tokens, msg, log, &position, num_tokens);
	if (tmp_ret & PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
	else if (tmp_ret & PARSE_REACHED_END_OF_MSG)
		return PARSE_RET_INVALID_MSG_WARN;
	else {
		position++;
		if (position >= num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	ret |= tmp_ret;
	/* Reset our bitmask */
	tmp_ret = 0;

	if (strcmp(tokens[position], "for") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
		/* Hold the position */
	} else {
		position++;
		if (position >= num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}

	/* At this point we have a valid message, for we have gathered all of the standard fields
	 * so insert anything else. If nothing else is left, the message is still considered valid. */
	ret |= avc_msg_insert_additional_field_data(tokens, msg, log, &position, num_tokens);

	return (ret | PARSE_RET_SUCCESS);
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

static void load_policy_msg_get_policy_components(char **tokens, bool_t *found_bools, msg_t **msg,
					         int position, int num_tokens)
{
	assert(tokens != NULL);
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
	} else if ((*msg)->msg_data.load_policy_msg->bools == 0 && strstr(tokens[position], "bools")) {
		found_bools[LOAD_POLICY_MSG_BOOLS_FIELD] = TRUE;
		(*msg)->msg_data.load_policy_msg->bools = atoi(tokens[position - 1]);
	}
}

static unsigned int load_policy_msg_insert_field_data(char **tokens, msg_t **msg, FILE *audit_file,
						      audit_log_t *log, int num_tokens)
{
	int i, length = 0, position = 0, tmp_position, rt;
	unsigned int ret = 0, tmp_ret = 0;
	bool_t found[LOAD_POLICY_MSG_NUM_POLICY_COMPONENTS];

	assert(tokens != NULL && msg != NULL && *msg != NULL && log != NULL && audit_file != NULL && num_tokens > 0);
	for (i = 0; i < LOAD_POLICY_MSG_NUM_POLICY_COMPONENTS; i++)
		found[i] = FALSE;

	tmp_ret |= insert_standard_msg_header(*(&tokens), *msg, log, &position, num_tokens);
	if (tmp_ret & PARSE_RET_MEMORY_ERROR) {
		return PARSE_RET_MEMORY_ERROR;
	} else if (tmp_ret & PARSE_REACHED_END_OF_MSG) {
		return PARSE_RET_INVALID_MSG_WARN;
	} else if (!(tmp_ret & PARSE_RET_INVALID_MSG_WARN)) {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	ret |= tmp_ret;
	tmp_ret = 0;

	if (strcmp(tokens[position], "invalidating") == 0) {
		return LOAD_POLICY_FALSE_POS;
	}

	if ((position + 1) == num_tokens)
		return PARSE_RET_INVALID_MSG_WARN;
	if (strcmp(tokens[position + 1], "bools") == 0) {
		return LOAD_POLICY_FALSE_POS;
	}

	/* Check the following token for the string "kernel:" */
	if (!strstr(*(&tokens[position]), "kernel")) {
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
			load_policy_msg_get_policy_components(*(&tokens), found, msg, position, num_tokens);
			position++;
		}

		/* This is rather limiting, but for now we assume that the classes and rules objects signal the end
		 * of the policy components. So, if we have grabbed these components, then we return SUCCESS flag. */
		if (found[LOAD_POLICY_MSG_CLASSES_FIELD] && found[LOAD_POLICY_MSG_RULES_FIELD]){
			/* Should have already parsed users, roles and types. If not, return INVALID flag. */
			if (((*msg)->msg_data.load_policy_msg->users >= 0 &&
			    (*msg)->msg_data.load_policy_msg->roles >= 0 &&
			    (*msg)->msg_data.load_policy_msg->types >= 0) ||
			    (*msg)->msg_data.load_policy_msg->bools >= 0) {
				ret |= PARSE_RET_SUCCESS;
			} else {
				ret |= PARSE_RET_INVALID_MSG_WARN;
			}
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
	unsigned int ret = 0, tmp_ret = 0;
	bool_t *values = NULL, val = FALSE;

	assert(tokens != NULL && msg != NULL && *msg != NULL && log != NULL && num_tokens > 0);

	tmp_ret |= insert_standard_msg_header(*(&tokens), *msg, log, &position, num_tokens);
	if (tmp_ret & PARSE_RET_MEMORY_ERROR)
		return PARSE_RET_MEMORY_ERROR;
	else if (tmp_ret & PARSE_REACHED_END_OF_MSG)
		return PARSE_RET_INVALID_MSG_WARN;
	else if (!(tmp_ret & PARSE_RET_INVALID_MSG_WARN)) {
		position++;
		if (position == num_tokens)
			return PARSE_RET_INVALID_MSG_WARN;
	}
	ret |= tmp_ret;
	tmp_ret = 0;

	/* Make sure the following token is the string "kernel:" */
	if (!strstr(*(&tokens[position]), "kernel")) {
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
	if (position == num_tokens && strcmp(tokens[position - 1], "}") != 0) {
		ret |= PARSE_RET_INVALID_MSG_WARN;
	}

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
		tmp_ret |= boolean_msg_insert_bool(tokens[i + start_bools_pos], &bool, &val, log);
		if (tmp_ret & PARSE_RET_MEMORY_ERROR){
		        free(booleans);
		        free(values);
		        return PARSE_RET_MEMORY_ERROR;
		} else if (tmp_ret & PARSE_RET_INVALID_MSG_WARN) {
			ret |= PARSE_RET_INVALID_MSG_WARN;
		        continue;
		}
		booleans[bool_idx] = bool;
		values[bool_idx] = val;
		bool_idx++;
		num_bools_valid++;
	}
	ret |= tmp_ret;

	if (num_bools_valid) {
		(*msg)->msg_data.boolean_msg->num_bools = num_bools_valid;
		(*msg)->msg_data.boolean_msg->booleans = booleans;
		(*msg)->msg_data.boolean_msg->values = values;
	}

        return (ret | PARSE_RET_SUCCESS);
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

int audit_log_parse(seaudit_log_t *log, FILE *syslog)
{
	FILE *audit_file = syslog;
	msg_t *msg = NULL;
	char *line = NULL;
	int is_sel = -1, selinux_msg = 0;
	unsigned int ret = 0, tmp_ret = 0;
	static bool_t tz_initialized = 0, next_line = FALSE;

	assert(audit_file != NULL && log != NULL);

	if (!tz_initialized) {
		tzset();
		tz_initialized = 1;
	}

	clearerr(audit_file);
	if (feof(audit_file))
		return PARSE_RET_EOF_ERROR;

	if (get_line(audit_file, &line) == PARSE_RET_MEMORY_ERROR) {
		return PARSE_RET_MEMORY_ERROR;
	}

	while (line != NULL) {
		if (apol_str_trim(&line) != 0)
			return PARSE_RET_MEMORY_ERROR;
		is_sel = is_selinux(line);
		if (is_sel != PARSE_NON_SELINUX) {
			if (next_line && (is_sel != PARSE_LOAD_MSG)) {
				ret |= PARSE_RET_INVALID_MSG_WARN;
				msg = NULL;
			}
			next_line = FALSE;
			tmp_ret |= get_tokens(line, is_sel, log, audit_file, &msg);
			if (tmp_ret & PARSE_RET_MEMORY_ERROR) {
				return PARSE_RET_MEMORY_ERROR;
			} else if (tmp_ret & PARSE_RET_INVALID_MSG_WARN) {
				if (audit_log_add_malformed_msg(line, &log) != 0) {
					return PARSE_RET_MEMORY_ERROR;
				}
				selinux_msg++;
			} else if (tmp_ret & PARSE_RET_SUCCESS) {
				selinux_msg++;
			}
			/* if the load policy next line bit is ON then turn it OFF. */
			if (tmp_ret & LOAD_POLICY_NEXT_LINE) {
				next_line = TRUE;
				tmp_ret &= ~LOAD_POLICY_NEXT_LINE;
			}
			ret |= tmp_ret;
			tmp_ret = 0;
		}
		free(line);
		line = NULL;
		if (get_line(audit_file, &line) == PARSE_RET_MEMORY_ERROR) {
			return PARSE_RET_MEMORY_ERROR;
		}
	}

	if (selinux_msg == 0)
		return PARSE_RET_NO_SELINUX_ERROR;

	return ret;
}

#endif
