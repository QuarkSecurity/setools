/*
 *  Copyright (C) 2003-2004 Tresys Technology, LLC
 *  see file 'COPYING' for use and warranty information
 *
 */

/*
 *  Authors: Terrence Mitchem <tmitchem@tresys.com>
 *	     Karl Macmillan <kmacmillan@tresys.com>
 *
 *  indexcon: a tool for indexing the security contexts of filesystem entities
 */

/* SE Linux includes*/
#include <selinux/selinux.h>
#include <selinux/context.h>
/* standard library includes */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fnmatch.h>
#define _GNU_SOURCE
#include <getopt.h>
/* file tree walking commands */
#define __USE_XOPEN_EXTENDED 1
#include <ftw.h>
#include <mntent.h>
/* AVL Tree Handling */
#include <avl-util.h>
#include <policy.h>

#include <fsdata.h>

/* INDEXCON_VERSION_NUM should be defined in the make environment */
#ifndef INDEXCON_VERSION_NUM
#define INDEXCON_VERSION_NUM "UNKNOWN"
#endif

#define COPYRIGHT_INFO "Copyright (C) 2004 Tresys Technology, LLC"

static struct option const longopts[] =
{
  {"directory", required_argument, NULL, 'd'},
  {"help", no_argument, NULL, 'h'},
  {"version", no_argument, NULL, 'v'},
  {NULL, 0, NULL, 0}
};


void usage(const char *program_name, int brief)
{
	printf("%s (indexcon ver. %s)\n\n", COPYRIGHT_INFO, INDEXCON_VERSION_NUM);
	printf("Usage: %s <filename> [OPTIONS]\n", program_name);
	if(brief) {
		printf("\n   Try %s --help for more help.\n\n", program_name);
		return;
	}
	fprintf(stdout, "\n\
Index SELinux contexts on the filesystem\n\
  -d directory, --directory=directory 	Start scanning at directory\n\
  -h, --help                 display this help and exit\n\
  -v, --version              output version information and exit\n");
	return;
}


int main(int argc, char **argv, char **envp)
{
	char *outfilename = NULL, *dir = "/", **mounts = NULL;
	int optc = 0, num_mounts = 0, i;
	sefs_filesystem_data_t fsdata;
	
	outfilename = argv[1];
	if (outfilename == NULL) {
		usage(argv[0], 1);
		exit(1);
	}

	while ((optc = getopt_long (argc, argv, "d:hv", longopts, NULL)) != -1)  {
		switch (optc) {
	  	case 'd': /* directory */
	  		dir = optarg;
	  		break;
		case 'h': /* help */
	  		usage(argv[0], 0);
	  		exit(0);
		case 'v': /* version */
	  		printf("\n%s (indexcon ver. %s)\n\n", COPYRIGHT_INFO, INDEXCON_VERSION_NUM);
	  		exit(0);
		default:
	  		usage(argv[0], 1);
	  		exit(1);
		}
	}


	if (sefs_filesystem_data_init(&fsdata) == -1) {
		fprintf(stderr, "fsdata_init failed\n");
		return -1;
	}
	
	if (find_mount_points(dir, mounts, &num_mounts, 0))
		return -1;

	if (sefs_scan_tree(dir) == -1) {
		fprintf(stderr, "fsdata_scan_tree failed\n");
		return -1;
	}
	
	for (i = 0; i < num_mounts; i++ ){
		if (sefs_scan_tree(mounts[i]) == -1) {
			fprintf(stderr, "fsdata_scan_tree failed\n");
			return -1;
		}
	}

	printf("types: %d inodes: %d \n", fsdata.num_types, fsdata.num_files);

	if (sefs_filesystem_data_save(&fsdata, outfilename) != 0) {
		fprintf(stderr, "Error writing path database\n");
		return -1;
	}

	free(mounts);

	return 0;	
}


