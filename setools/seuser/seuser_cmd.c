 /* Copyright (C) 2002-2003 Tresys Technology, LLC
 * see file 'COPYING' for use and warranty information */

/* 
 * Author: mayerf@tresys.com 
 */

/* This file contains the main for seuser
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include "../libapol/util.h"
#include "../libseuser/seuser_db.h"
#include "../libapol/policy-io.h"
#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#define STRING_LENGTH_MAX 255

/* The following should be defined in the make environment */
#ifndef SEUSERCMD_VERSION_STRING
	#define SEUSERCMD_VERSION_STRING "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2002-2004 Tresys Technology, LLC"

/* command line commands */
#define ADD		0
#define CHANGE		1
#define DELETE		2
#define RENAME		3
#define LOAD		4
#define SHOW		5
#define LABEL		6
#define VERSION		7

#define SEUSER_GUI_PROG	"seuserx"

#define ALLOC_SZ 512
/* ensure string buffer is large enough and if not increase it */
static int check_str_sz(char **str, int *sz, int needed)
{
	char *tmp;
	
	if((strlen(*str) + needed) >= (*sz)+1) {
		if(needed > ALLOC_SZ)
			*sz += needed;
		else
			*sz += ALLOC_SZ;
			
		tmp = (char *)realloc(*str, *sz);
		if(tmp == NULL) {
			fprintf(stderr, "out of memory");
			return -1;
		}
		*str = tmp;
	}	
	return 0;
}


/* return a string with users and user roles, if user == NULL then show all users,
 * otherwise only the user provided.  Returns:
 * 0	success
 * 1	provided user does not exists
 * -1	other error
 */
const int seu_show_users(const char *user, char **outstr, user_db_t *db, policy_t *policy)
{
	user_item_t *ptr;
	char *name, *role, *tmp;
	int sz;
	bool_t found = FALSE;
	ta_item_t *item;
		
	if(db == NULL || outstr == NULL) {
		return -1;
	}
	
	sz = ALLOC_SZ;
	tmp = (char *)malloc(sz);
	if(tmp == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	tmp[0] = '\0';
	for(ptr = db->users.head; get_user_name(ptr, &name) == 0; ptr = ptr->next) {
		if(user != NULL) {
			if(strcmp(user, name) == 0) 
				found = TRUE;
			else 
				continue;
		}
		/* ensure enough room for name and ending \n character and ": "*/
		if(check_str_sz(&tmp, &sz, strlen(name)+3) != 0) {
			return -1;
		}
		strcat(tmp, name);
		strcat(tmp, ": ");

		/* add each role */
		for(item = ptr->roles; item != NULL; item = item->next) {
			if(get_role_name(item->idx, &role, policy) != 0) {
				return -1;
			}
			if(check_str_sz(&tmp, &sz, strlen(role)+1) != 0) {
				return -1;
			}
			strcat(tmp, role);
			strcat(tmp, " ");
			free(role);
		}
		
		strcat(tmp, "\n");
		free(name);
	}
	
	if(strlen(tmp) == 0) {
		free(tmp);
		if(user != NULL)
			return 1; /* user specified but not found */
		*outstr = NULL; /* no users defined at all */
	}
	else
		*outstr = tmp;
		
	return 0;
}

/* display all roles */
const int seu_show_roles(char **outstr, user_db_t *db, policy_t *policy)
{
	char *tmp, *role;
	int i, sz;
	
	if(db == NULL || outstr == NULL || policy == NULL) {
		return -1;
	}
	sz = ALLOC_SZ;
	tmp = (char *)malloc(sz);
	if(tmp == NULL) {
		fprintf(stderr, "out of memory");
		return -1;
	}
	tmp[0] = '\0';
	for(i = 0; is_valid_role_idx(i, policy); i++) {
		if(get_role_name(i, &role, policy) != 0) {
			return -1;
		}
		if(check_str_sz(&tmp, &sz, strlen(role)+1) != 0) {
			return -1;
		}
		strcat(tmp, role);
		strcat(tmp, "\n");
		free(role);
	}
	if(strlen(tmp) == 0) {
		free(tmp);
		*outstr = NULL;
	}
	else
		*outstr = tmp;	
	
	
	return 0;
}



void usage(bool_t brief)
{
	fprintf(stdout, "\nUsage:\n");
	fprintf(stdout, "  seuser -X\n");
	fprintf(stdout, "  seuser delete [-N] username\n");
	fprintf(stdout, "  seuser add | change [f] [-N] -R role1[,...] username\n");
	fprintf(stdout, "  seuser rename [-f] [-N] oldname newname\n");
	fprintf(stdout, "  seuser label username\n");
	fprintf(stdout, "  seuser show users [username] | roles\n");
	fprintf(stdout, "  seuser load\n");
	fprintf(stdout, "  seuser version\n\n");
	
	if(brief) {
		fprintf(stdout, "Use \"seuser -h\" for extended help\n\n");
	}
	else {
		fprintf(stdout, "The -X form of this command will run a GUI.\n\n");
		fprintf(stdout, "The delete command will remove the specified user from the SE Linux policy.\n\n");
		fprintf(stdout, "The add/change commands will add/change a user and the user's policy \n");
		fprintf(stdout, "information.  You must provide role for change/add as such:\n");
		fprintf(stdout, "     -R     authorized role(s)\n\n");
		fprintf(stdout, "The label command will label home directory files for the specified user.\n");
		fprintf(stdout, "The rename command will change the name of oldname to newname, leaving all\n");
		fprintf(stdout, "other information the same.\n\n");
		fprintf(stdout, "The show command will display users or roles currently defined in the policy.\n\n");
		fprintf(stdout, "The load command will reload the currently installed policy; most useful if -N\n");
		fprintf(stdout, "is used.\n\n");
		fprintf(stdout, "\nOther options:\n\n");
		fprintf(stdout, "   -N  Do not reload the updated policy; otherwise changes are made and installed,\n");
		fprintf(stdout, "       but not loaded as the running kernel policy (but will be on next boot).\n");
		fprintf(stdout, "       Use the load command to manually reload the installed policy when using\n");
		fprintf(stdout, "       this policy.\n\n");
		fprintf(stdout, "   -f  Force. Only used for add, change, and rename commands.  Allows you to add a user\n");
		fprintf(stdout, "       to the policy that is not an existing system user in the passwd file.\n");
		fprintf(stdout, "       This would be used, for example, to add the special user_u policy user.\n");
		fprintf(stdout, "\n");
	}
	return;
}


bool_t isSysUser(const char *user)
{
	/* TODO: Need to add checking for buffer overflows */ 
	bool_t rt_val;
	struct passwd *tmp = NULL;
	if(user == NULL)
		return FALSE;
		
	tmp = getpwnam(user);
	if(tmp == NULL)
		rt_val = FALSE;
	else 
		rt_val = TRUE;
	return rt_val;
}

int parse_roles(char *in, char ***roles, int *num, char *user)
{
	int cnt, i;
	char *ptr;

	if(num == NULL)
		return -1;		
	if(in == NULL) {
		*roles = NULL;
		num = 0;
		return 0;
	}
	
	if ( strcmp(in, "") == 0 ) {
		fprintf(stderr, "\nA null role is not a valid role.\n");
		return -1;
	}
	
	/* How many roles.*/
	for(cnt= 1, ptr = strpbrk(in, ","); ptr != NULL; ptr = strpbrk(++ptr, ","), cnt++) { ; }
			
	if(cnt > 0) {
		*roles = (char **)malloc(cnt * sizeof(char *));
		if(roles == NULL) {
			fprintf(stderr, "out of memory\n");
			return -1;
		}
	}
	else {
		*roles = NULL;
		num = 0;
		return 0;
	}		
	
	/* set array pointers to roles */
	i = 0;
	ptr = strtok(in, ",");
	while(ptr != NULL) {
		assert(i < cnt);
		(*roles)[i] = ptr;
		ptr = strtok(NULL, ",");
		i++;
	}
	*num = cnt;

	return 0;
}


int main(int argc, char *argv[])
{
	int i, rt, numroles, show_cmd = 0, /* 0 = users, 1 = roles */
		cmd; 
	char *user = NULL, **roles, *olduser = NULL;
	bool_t role  = FALSE, load = TRUE, force = FALSE;
	user_db_t db;
	policy_t *policy = NULL;
	char *tmpmakeout = NULL;

	if(argc < 2) 
		goto usage_err;

	seuser_init_db(&db, TRUE);

	/* we use this file name for our temporary make output */
	/* tmpmakeout is a global variable */
	tmpmakeout = tempnam("/tmp", "seuser_tmp.");
	

	/* GUI */
	if(argv[1][0] == '-') {
		/* replaced -g with less desireable -X because -g already used by
		* one of the user[add|mod|del] commands */
		if(argv[1][1] == 'X' ) { 
			rt = execlp(SEUSER_GUI_PROG, NULL);
			if(rt == -1) {
				perror(SEUSER_GUI_PROG);
			}
  			exit(1);
  			/* otherwise execlp() won't ever return! */
		}
		else if(argv[1][1] == 'h') {
			usage(FALSE);
			exit(0);
		}
		else 
			goto usage_err;
	}
	/* command line */
	if(strcmp("version", argv[1]) == 0) {
		fprintf(stdout, "\n%s (%s)\n\n", COPYRIGHT_INFO, SEUSERCMD_VERSION_STRING);
		exit(0);
	}

	/* load the policy */
	rt = seuser_read_conf_info(&db);
	if(rt != 0) {
		fprintf(stderr, seuser_decode_read_conf_err(rt));
		return -1;
	}

	if(strcmp("delete", argv[1]) == 0) {
		cmd = DELETE;
	}
	else if(strcmp("add", argv[1]) == 0) {
		cmd = ADD;
	}
	else if(strcmp("change", argv[1]) == 0) {
		cmd = CHANGE;
	}
	else if(strcmp("label", argv[1]) == 0) {
		cmd = LABEL;
	}
	else if(strcmp("show", argv[1]) == 0) {
		cmd = SHOW;
		if(argc < 3 )
			goto usage_err;
		if(argv[2][0] == '-' || (argc == 4 && argv[3][0] == '-')) 
			goto usage_err;
		if(strcmp("users", argv[2]) == 0) {
			show_cmd = 0;
		}
		else if(strcmp("roles", argv[2]) == 0) {
			show_cmd = 1;
			if(argc != 3)
				goto usage_err;
		}
		else {
			goto usage_err;
		}		
	}
	else if(strcmp("load", argv[1]) == 0) {
		cmd = LOAD;
		if(argc != 2)
			goto usage_err;
	}
	else if(strcmp("rename", argv[1]) == 0) {
		cmd = RENAME;
	}
	else 
		goto usage_err;

	/* parse options the old fashion way! */	
	if(cmd == SHOW) 
		i = 3;
	else
		i = 2;
	for(; i < argc; i++) {
		if(argv[i][0] != '-') {
			break;
		}
		else {
			if(cmd > RENAME)
				goto usage_err;
			switch(argv[i][1]) {
			case 'N':
				load = FALSE;
				break;
			/* replaced -r with less desireable -R because -r already used by
			 * one of the user[add|mod|del] commands */
			case 'R':
				if(role || cmd > CHANGE)
					goto usage_err;
				else
					role = TRUE;
				if(++i >= argc || argv[i][0] == '-')
					goto usage_err;
				rt = parse_roles(argv[i], &roles, &numroles, user);
				if(rt != 0) {
					fprintf(stderr, "\nerror parsing roles\n\n");
					exit(1);
				}
				break;
			case 'f':
				if(!(cmd == ADD || cmd == RENAME || cmd == CHANGE))
					goto usage_err;
				force = TRUE;
				break;
			default:
				goto usage_err;
			}
		}
	}

	/* old user for rename */
	if(cmd == RENAME) {
		olduser = argv[i];
		i++;
	}
	/* Get the user which should be the final argument except for load cmd. */	
	if(cmd != LOAD) {
		if(cmd == SHOW ) {
			if (argc == 4 ) {
				if(i != 3) {
					goto usage_err;
				}
				user = argv[i];
			}
			else {
				user = NULL;
			}
		}
		else {
			assert(cmd == ADD || cmd == CHANGE || cmd == DELETE || cmd == RENAME || cmd == LABEL);
			if(i+1 != argc)
				goto usage_err;
			user = argv[i];
		}
	}				
	
	if((cmd == ADD || cmd == CHANGE) && !role) {
		fprintf(stderr, "\nRoles (-R) for user not specified\n");
		goto usage_err;	
	}
	if(cmd == DELETE) {
		if(strcmp(user, "system_u") == 0) {
			fprintf(stderr, "\nFailed: can't remove the special system_u account\n\n");
			exit(1);
		}
	}
	if(!force) {
		if(cmd == ADD || cmd == RENAME) {
			if(!isSysUser(user)) {
				fprintf(stderr, "\nFailed: trying to %s a non-system user (%s). Use -f option.\n\n",(cmd==ADD?"add":"rename to"), user);
				exit(1);
			}
		}
	}	
	if(cmd != SHOW) {
		if(seuser_check_commit_perm(&db) != 0) {
			fprintf(stderr, "You do not have permission to comit user changes.\n");
			exit(1);
		}
	}
	if(cmd != LOAD) {
		rt = seuser_open_user_db(&db, &policy);
	}

	if(force && cmd == CHANGE) {
		/* if the user doesn't exist and change -f request, change the command to a add */
		if(!seuser_does_user_exist(user, &db)) {
			cmd = ADD;
		}
	}
	
	switch(cmd) {
	case ADD: 
	case CHANGE: 
	{
		bool_t  new_user;
		if(cmd == ADD) 
			new_user = TRUE;
		else
			new_user = FALSE;
		rt = seuser_add_change_user(new_user, user, roles, numroles, &db, policy);
		switch(rt) {
		case 1:	fprintf(stderr, "Cannot add user %s; use already exists\n", user);
			break;
		case 2:	fprintf(stderr, "Cannot change user %s; user does not exist\n", user);
			break;
		case 3:	fprintf(stderr, "Bug: improperly formed user record within library\n");
			break;
		case 4:	fprintf(stderr, "An invalid role name was provided\n");
			break;
		case 5:	fprintf(stderr, "Bug: problem inserting role into user record within library\n");
			break;
		}
		break;
	}
	case DELETE: 
		rt = seuser_remove_user(user, &db);
		switch(rt) {
		case 1:	fprintf(stderr, "Cannot delete user %s; user does not exist.\n", user);
			break;
		case -1: fprintf(stderr, "Unknown error trying to delete user %s\n", user);
			break;
		}
		break;
	case RENAME:
		rt = seuser_rename_user(olduser, user, &db);
		switch(rt) {
		case 1:	fprintf(stderr, "Cannot rename user %s; user does not exist.\n", olduser);
			break;
		case 2: fprintf(stderr, "Cannot rename user %s, the new user name (%s) already exists\n", olduser, user);
			break;
		default:
			break;
		}
		break;
	case LOAD:
		rt = 0;
		/*load = TRUE; (load == TRUE) by default unless -N option included */
		break;
	case SHOW: {
		char *outstr;
		load = FALSE;
		if(show_cmd == 0)  {
			rt = seu_show_users(user, &outstr, &db, policy);
			switch(rt) {
			case 1:	fprintf(stderr, "User (%s) is not an existing user\n", user);
				break;
			case -1: fprintf(stderr, "Unknown error trying to display user(s)\n");
				break;
			case 0: /* success */
				if(outstr == NULL)
					fprintf(stderr, "\nNo users currently defined.\n");
				else {
					fprintf(stderr, "\n%s\n", outstr);
					free(outstr);
				}
			}
		}
		else {
			rt = seu_show_roles(&outstr, &db, policy);
			switch(rt){
			case 0:
				if(outstr == NULL)
					fprintf(stderr, "\nNo roles currently defined.\n");
				else {
					fprintf(stderr, "\n%s\n", outstr);
					free(outstr);
				}
				break;
			case -1:
				fprintf(stderr, "Unknown error while trying to show roles.\n");
				break;
			}
		}
		break;
	}
	case LABEL: 
		/* We should only relabel after the policy has reloaded successfully. */
		rt = seuser_label_home_dir(user, &db, policy, tmpmakeout);
		if (rt != 0) {
			fprintf(stderr, "Error relabeling users home directory files: %s", seuser_decode_labeling_err(rt));
			break;
		}
		load = FALSE;
		break;
	default:
		fprintf(stderr, "unexepected err!\n");
		exit(1);
	}
	
	
	if(rt != 0) {
		if(cmd == ADD || cmd == CHANGE)
			free(roles);
		exit(rt);
	}

	if(cmd <= RENAME && rt == 0) {
		fprintf(stdout, "committing changes....\n");
		rt = seuser_write_user_file(&db, policy);
		if(rt != 0) {
			fprintf(stdout, "Problem committing changes\n");
			exit(1);
		}
		fprintf(stdout, "re-making policy...\n");
		rt = seuser_remake_policy_conf(tmpmakeout, &db);
		if(rt != 0) {
			fprintf(stdout, "Problem re-making policy.conf\n");
			exit(1);
		}
	}

	
	if(load) {
		fprintf(stdout, "loading new policy...\n");
		rt = seuser_reinstall_policy(tmpmakeout, &db);
		if(rt != 0) {
			fprintf(stdout, "Problem loading new policy\n");
			exit(1);
		}
	}
	fprintf(stdout, "\n");
	if(cmd <= CHANGE)
		free(roles);
	if(tmpmakeout != NULL) {
		remove(tmpmakeout);
	}
	seuser_free_db(&db, TRUE);
	exit(0);	

usage_err:	
	usage(TRUE);
	exit(1);
}

