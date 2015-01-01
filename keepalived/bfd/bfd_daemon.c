/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        BFD child process handling
 *
 * Author:      Ilya Voronin, <ivoronin@gmail.com>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2015 Alexandre Cassen, <acassen@gmail.com>
 */

#ifdef BFD_SCHED_RT
#include <sched.h>
#endif
#include "bfd.h"
#include "bfd_daemon.h"
#include "bfd_data.h"
#include "bfd_parser.h"
#include "bfd_scheduler.h"
#include "bfd_event.h"
#include "pidfile.h"
#include "logger.h"
#include "signals.h"
#include "list.h"
#include "main.h"
#include "parser.h"
#include "time.h"

extern char *bfd_pidfile;
static int reload_bfd_thread(thread_t *);

/* Daemon stop sequence */
static void
stop_bfd(void)
{
	signal_handler_destroy();

	/* Stop daemon */
	pidfile_rm(bfd_pidfile);

	/* Clean data */
	free_global_data(global_data);
	bfd_dispatcher_release(bfd_data);
	free_bfd_data(bfd_data);
	free_bfd_buffer();
	thread_destroy_master(master);

#ifdef _DEBUG_
	keepalived_free_final("BFD Child process");
#endif

	/*
	 * Reached when terminate signal catched.
	 * finally return to parent process.
	 */
	closelog();
	exit(0);
}

/* Daemon init sequence */
static void
start_bfd(void)
{
	srand(time(NULL));

	global_data = alloc_global_data();
	bfd_data = alloc_bfd_data();
	alloc_bfd_buffer();

	init_data(conf_file, bfd_init_keywords);
	if (!bfd_data) {
		stop_bfd();
		return;
	}

	if (bfd_complete_init()) {
		stop_bfd();
		return;
	}

	if (debug & 4) {
		dump_bfd_data(bfd_data);
	}

	thread_add_event(master, bfd_dispatcher_init, bfd_data, 0);
}

/* Reload handler */
static void
sighup_bfd( __attribute__ ((unused))
	   void *v, __attribute__ ((unused))
	   int sig)
{
	thread_add_event(master, reload_bfd_thread, NULL, 0);
}

/* Terminate handler */
static void
sigend_bfd( __attribute__ ((unused))
	   void *v, __attribute__ ((unused))
	   int sig)
{
	if (master)
		thread_add_terminate_event(master);
}

/* BFD Child signal handling */
static void
bfd_signal_init(void)
{
	signal_handler_init();
	signal_set(SIGHUP, sighup_bfd, NULL);
	signal_set(SIGINT, sigend_bfd, NULL);
	signal_set(SIGTERM, sigend_bfd, NULL);
	signal_ignore(SIGPIPE);
}

/* Reload thread */
static int
reload_bfd_thread( __attribute__ ((unused)) thread_t * thread)
{
	timeval_t timer;
	timer = timer_now();

	/* set the reloading flag */
	SET_RELOAD;

	/* Signal handling */
	signal_reset();
	signal_handler_destroy();

	/* Destroy master thread */
	bfd_dispatcher_release(bfd_data);
	thread_destroy_master(master);
	master = thread_make_master();
	free_global_data(global_data);
	free_bfd_buffer();

	old_bfd_data = bfd_data;
	bfd_data = NULL;

	/* Reload the conf */
	mem_allocated = 0;
	bfd_signal_init();
	signal_set(SIGCHLD, thread_child_handler, master);
	start_bfd();

	free_bfd_data(old_bfd_data);
	UNSET_RELOAD;

	log_message(LOG_INFO, "Reload finished in %li usec",
		    timer_tol(timer_sub_now(timer)));

	return 0;
}

/* BFD Child respawning thread */
static int
bfd_respawn_thread(thread_t * thread)
{
	pid_t pid;

	/* Fetch thread args */
	pid = THREAD_CHILD_PID(thread);

	/* Restart respawning thread */
	if (thread->type == THREAD_CHILD_TIMEOUT) {
		thread_add_child(master, bfd_respawn_thread, NULL,
				 pid, RESPAWN_TIMER);
		return 0;
	}

	/* We catch a SIGCHLD, handle it */
	if (!(debug & 64)) {
		log_message(LOG_ALERT, "BFD child process(%d) died: Respawning",
			    pid);
		start_bfd_child();
	} else {
		log_message(LOG_ALERT, "BFD child process(%d) died: Exiting",
			    pid);
		raise(SIGTERM);
	}
	return 0;
}

int
start_bfd_child(void)
{
#ifndef _DEBUG_
	pid_t pid;
	int ret;

	/* Initialize child process */
	pid = fork();

	if (pid < 0) {
		log_message(LOG_INFO, "BFD child process: fork error(%m)");
		return -1;
	} else if (pid) {
		bfd_child = pid;
		log_message(LOG_INFO, "Starting BFD child process, pid=%d",
			    pid);
		/* Start respawning thread */
		thread_add_child(master, bfd_respawn_thread, NULL,
				 pid, RESPAWN_TIMER);
		return 0;
	}

	/* Opening local BFD syslog channel */
	openlog(PROG_BFD, LOG_PID | ((debug & 1) ? LOG_CONS : 0),
		(log_facility == LOG_DAEMON) ? LOG_LOCAL1 : log_facility);

#ifdef BFD_SCHED_RT
	/* Set realtime priority */
	struct sched_param sp;
	sp.sched_priority = sched_get_priority_max(SCHED_RR);
	if (sched_setscheduler(pid, SCHED_RR, &sp))
		log_message(LOG_WARNING,
			    "BFD child process: cannot raise priority");
#endif

	/* Child process part, write pidfile */
	if (!pidfile_write(bfd_pidfile, getpid())) {
		/* Fatal error */
		log_message(LOG_INFO,
			    "BFD child process: cannot write pidfile");
		exit(0);
	}

	/* Create the new master thread */
	signal_handler_destroy();
	thread_destroy_master(master);
	master = thread_make_master();

	/* change to / dir */
	ret = chdir("/");
	if (ret < 0) {
		log_message(LOG_INFO, "BFD child process: error chdir");
	}

	/* Set mask */
	umask(0);
#endif

	/* If last process died during a reload, we can get there and we
	 * don't want to loop again, because we're not reloading anymore.
	 */
	UNSET_RELOAD;

	/* Signal handling initialization */
	bfd_signal_init();

	/* Start BFD daemon */
	start_bfd();

	/* Launch the scheduling I/O multiplexer */
	launch_scheduler();

	/* Finish BFD daemon process */
	stop_bfd();
	exit(0);
}
