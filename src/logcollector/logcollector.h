/*   $OSSEC, logcollector.h, v0.3, 2005/11/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#ifndef __LOGREADER_H

#define __LOGREADER_H

#ifndef ARGV0
#define ARGV0 "ossec-logcollector"
#endif


#include "shared.h"
#include "config/localfile-config.h"
#include "config/config.h"




/*** Function prototypes ***/


/* Read logcollector config */
int LogCollectorConfig(char * cfgfile);

/* Stary log collector daemon */
void LogCollectorStart();

/* Handle files */
int handle_file(int i);

/* Read syslog file */
void *read_syslog(int pos, int *rc);

/* Read snort full file */
void *read_snortfull(int pos, int *rc);

/* Read nmap grepable format */
void *read_nmapg(int pos, int *rc);

/* sends agent notification to server. */
void run_notify();


#ifdef WIN32
/* Windows only */
void win_startel();
void win_readel();
void send_win32_info();
#endif


/*** Global variables ***/


int loop_timeout;
int logr_queue;
int open_file_attempts;
logreader *logff;


#endif
