/**
 *  @file parse.h
 *  Public interface for parsing an audit log.
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

#ifndef SEAUDIT_PARSE_H
#define SEAUDIT_PARSE_H

#include "log.h"
#include <stdio.h>

#if 0
#define	PARSE_RET_SUCCESS		0x00000001	/* success, no warnings nor errors */
#define PARSE_RET_MEMORY_ERROR		0x00000002	/* general error */
#define PARSE_RET_EOF_ERROR	0x00000004	/* file was eof */
#define PARSE_RET_NO_SELINUX_ERROR	0x00000008	/* no selinux messages found */
#define PARSE_RET_INVALID_MSG_WARN	0x00000010	/* invalid message, but added to audit log anyway */
#define PARSE_REACHED_END_OF_MSG	0x00000020	/* we reached the end of the message before gathering all information */
#define LOAD_POLICY_FALSE_POS		0x00000040	/* indicates that the message is not a load message although has 'security:' string */
#define LOAD_POLICY_NEXT_LINE		0x00000080	/* indicates that we've parsed the first line of a load message */

#define PARSE_MEMORY_ERROR_MSG "Memory error while parsing the log!"
#define PARSE_NO_SELINUX_ERROR_MSG "No SELinux messages found in log!"
#define PARSE_SUCCESS_MSG "Parse success!"
#define PARSE_INVALID_MSG_WARN_MSG "Warning! One or more invalid messages found in audit log.  See help file for more information."
#endif

/**
 * Parse the file specified by syslog and puts all selinux audit
 * messages into the log.  It is assumed that log will be created
 * before this function.
 *
 * @param log Audit log to which append messages.
 * @param syslog Handler to a file containing audit messages.
 *
 * @return 0 on success, < 0 on error and errno will be set.
 */
extern int seaudit_log_parse(seaudit_log_t *log, FILE *syslog);

#endif
