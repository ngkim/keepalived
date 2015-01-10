/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Scheduling framework for bfd code
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

#include <syslog.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bfd.h"
#include "bfd_data.h"
#include "bfd_scheduler.h"
#include "bfd_event.h"
#include "parser.h"
#include "logger.h"
#include "memory.h"

static int bfd_send_packet(int, bfdpkt_t *);
static void bfd_sender_schedule(bfd_t *);

static void bfd_state_down(bfd_t *, char diag);
static void bfd_state_admindown(bfd_t *);
static void bfd_state_up(bfd_t *);
static void bfd_dump_timers(bfd_t *);

/*
 * Session sender thread
 *
 * Runs every local_tx_intv, or after reception of a packet
 * with Poll bit set
 */

/* Sends one BFD control packet and reschedules itself if needed */
static int
bfd_sender_thread(thread_t * thread)
{
	bfd_t *bfd = NULL;
	bfdpkt_t *pkt = NULL;

	assert(thread);
	bfd = THREAD_ARG(thread);
	assert(bfd);
	assert(!BFD_ISADMINDOWN(bfd));

	bfd->thread_out = NULL;

	pkt = (bfdpkt_t *) MALLOC(sizeof (bfdpkt_t));
	bfd_build_packet(pkt, bfd, bfd_buffer, BFD_BUFFER_SIZE);
	if (bfd_send_packet(bfd->fd_out, pkt) == -1) {
		log_message(LOG_ERR, "BFD_Instance(%s) Error sending packet,"
			    " disabling instance", bfd->iname);
		bfd_state_admindown(bfd);
	}
	FREE(pkt);

	/* Reset final flag if set */
	if (bfd->final)
		bfd->final = 0;

	/* Schedule next run if not called as an event thread */
	if (thread->type != THREAD_EVENT && !BFD_ISADMINDOWN(bfd))
		bfd_sender_schedule(bfd);

	return 0;
}

/* Schedules bfd_sender_thread to run in local_tx_intv minus applied jitter */
static void
bfd_sender_schedule(bfd_t * bfd)
{
	u_int32_t min_jitter = 0, jitter = 0;

	assert(bfd);
	assert(!bfd->thread_out);

	/*
	 * RFC5880:
	 * The periodic transmission of BFD Control packets MUST be jittered
	 * on a per-packet basis by up to 25%, that is, the interval MUST be
	 * reduced by a random value of 0 to 25% <...>
	 *
	 * If bfd.DetectMult is equal to 1, the interval between transmitted
	 * BFD Control packets MUST be no more than 90% of the negotiated
	 * transmission interval, and MUST be no less than 75% of the
	 * negotiated transmission interval.
	 */
	if (bfd->local_detect_mult)
		min_jitter = bfd->local_tx_intv * 0.1;

	jitter = rand_intv(min_jitter, bfd->local_tx_intv * 0.25);
	bfd->thread_out =
	    thread_add_timer(master, bfd_sender_thread, bfd,
			     bfd->local_tx_intv - jitter);
}

/* Cancels bfd_sender_thread run */
static void
bfd_sender_cancel(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_out);
	thread_cancel(bfd->thread_out);
	bfd->thread_out = NULL;
}

/* Reschedules bfd_sender_thread run (usually after local_tx_intv change) */
static void
bfd_sender_reschedule(bfd_t * bfd)
{
	assert(bfd);
	bfd_sender_cancel(bfd);
	bfd_sender_schedule(bfd);
}

/* Returns 1 if bfd_sender_thread is scheduled to run, 0 otherwise */
static int
bfd_sender_scheduled(bfd_t * bfd)
{
	assert(bfd);
	return bfd->thread_out != NULL;
}

/* Suspends sender thread. Needs freshly updated time_now */
static void
bfd_sender_suspend(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_out);
	assert(bfd->sands_out == -1);
	bfd->sands_out = THREAD_TIME_TO_WAKEUP(bfd->thread_out);
	bfd_sender_cancel(bfd);
}

/* Resumes sender thread */
static void
bfd_sender_resume(bfd_t * bfd)
{
	assert(bfd);
	assert(!bfd->thread_out);
	assert(bfd->sands_out != -1);
	bfd->thread_out =
	    thread_add_timer(master, bfd_sender_thread, bfd, bfd->sands_out);
	bfd->sands_out = -1;
}

/* Returns 1 if bfd_sender_thread is suspended, 0 otherwise */
static int
bfd_sender_suspended(bfd_t * bfd)
{
	assert(bfd);
	return bfd->sands_out != -1;
}

static void
bfd_sender_discard(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->sands_out != -1);
	bfd->sands_out = -1;
}

/*
 * Session expiration thread
 *
 * Runs after local_detect_time has passed since receipt of last
 * BFD control packet from neighbor
 */

/* Marks session as down because of Control Detection Time Expiration */
static int
bfd_expire_thread(thread_t * thread)
{
	bfd_t *bfd = NULL;
	u_int32_t dead_time, overdue_time;

	assert(thread);
	bfd = THREAD_ARG(thread);
	assert(bfd);
	/* Session cannot expire while not in Up or Init states */
	assert(BFD_ISUP(bfd) || BFD_ISINIT(bfd));

	bfd->thread_exp = NULL;

	/* Time since last received control packet */
	dead_time = timer_tol(timer_sub_now(bfd->last_seen));
	/* Difference between expected and actual failure detection time */
	overdue_time = dead_time - bfd->local_detect_time;

	log_message(LOG_WARNING, "BFD_Instance(%s) Expired after"
		    " %i ms (%i usec overdue)",
		    bfd->iname, dead_time / 1000, overdue_time);

	/*
	 * RFC5580:
	 * <...> If a period of a Detection Time passes without the
	 * receipt of a valid, authenticated BFD packet from the remote
	 * system, this <bfd.RemoteDiscr> variable MUST be set to zero.
	 */
	bfd->remote_discr = 0;
	bfd_state_down(bfd, BFD_DIAG_EXPIRED);

	return 0;
}

/* Schedules bfd_expire_thread to run in local_detect_time */
static void
bfd_expire_schedule(bfd_t * bfd)
{
	assert(bfd);
	assert(!bfd->thread_exp);

	bfd->thread_exp =
	    thread_add_timer(master, bfd_expire_thread, bfd,
			     bfd->local_detect_time);
}

/* Cancels bfd_expire_thread run */
static void
bfd_expire_cancel(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_exp);
	thread_cancel(bfd->thread_exp);
	bfd->thread_exp = NULL;
}

/* Reschedules bfd_expire_thread run (usually after control packet receipt) */
static void
bfd_expire_reschedule(bfd_t * bfd)
{
	assert(bfd);
	bfd_expire_cancel(bfd);
	bfd_expire_schedule(bfd);
}

/* Returns 1 if bfd_expire_thread is scheduled to run, 0 otherwise */
static int
bfd_expire_scheduled(bfd_t * bfd)
{
	assert(bfd);
	return bfd->thread_exp != NULL;
}

/* Suspends expire thread. Needs freshly updated time_now */
static void
bfd_expire_suspend(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_exp);
	assert(bfd->sands_exp == -1);
	bfd->sands_exp = THREAD_TIME_TO_WAKEUP(bfd->thread_exp);
	bfd_expire_cancel(bfd);
}

/* Resumes expire thread */
static void
bfd_expire_resume(bfd_t * bfd)
{
	assert(bfd);
	assert(!bfd->thread_exp);
	assert(bfd->sands_exp != -1);
	bfd->thread_exp =
	    thread_add_timer(master, bfd_expire_thread, bfd, bfd->sands_exp);
	bfd->sands_exp = -1;
}

/* Returns 1 if bfd_expire_thread is suspended, 0 otherwise */
static int
bfd_expire_suspended(bfd_t * bfd)
{
	assert(bfd);
	return bfd->sands_exp != -1;
}

static void
bfd_expire_discard(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->sands_exp != -1);
	bfd->sands_exp = -1;
}

/*
 * Session reset thread
 *
 * Runs after local_detect_time has passed after BFD session
 * gone to Down state.
 */

/* Resets BFD session to initial state */
static int
bfd_reset_thread(thread_t * thread)
{
	bfd_t *bfd = NULL;

	assert(thread);
	bfd = THREAD_ARG(thread);
	assert(bfd);
	assert(bfd->thread_rst);

	bfd->thread_rst = NULL;

	bfd_init_state(bfd);
	return 0;
}

/* Schedules bfd_reset_thread to run in local_detect_time */
static void
bfd_reset_schedule(bfd_t * bfd)
{
	assert(bfd);
	assert(!bfd->thread_rst);

	bfd->thread_rst =
	    thread_add_timer(master, bfd_reset_thread, bfd,
			     bfd->local_detect_time);
}

/* Cancels bfd_reset_thread run */
static void
bfd_reset_cancel(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_rst);

	thread_cancel(bfd->thread_rst);
	bfd->thread_rst = NULL;
}

/* Returns 1 if bfd_reset_thread is scheduled to run, 0 otherwise */
static int
bfd_reset_scheduled(bfd_t * bfd)
{
	assert(bfd);
	return bfd->thread_rst != NULL;
}

/* Suspends reset thread. Needs freshly updated time_now */
static void
bfd_reset_suspend(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->thread_rst);
	assert(bfd->sands_rst == -1);
	bfd->sands_rst = THREAD_TIME_TO_WAKEUP(bfd->thread_rst);
	bfd_reset_cancel(bfd);
}

/* Resumes reset thread */
static void
bfd_reset_resume(bfd_t * bfd)
{
	assert(bfd);
	assert(!bfd->thread_rst);
	assert(bfd->sands_rst != -1);
	bfd->thread_rst =
	    thread_add_timer(master, bfd_reset_thread, bfd, bfd->sands_rst);
	bfd->sands_rst = -1;
}

/* Returns 1 if bfd_reset_thread is suspended, 0 otherwise */
static int
bfd_reset_suspended(bfd_t * bfd)
{
	assert(bfd);
	return bfd->sands_rst != -1;
}

static void
bfd_reset_discard(bfd_t * bfd)
{
	assert(bfd);
	assert(bfd->sands_rst != -1);
	bfd->sands_rst = -1;
}

/*
 * State change handlers
 */
/* Common actions for Down and AdminDown states */
static void
bfd_state_fall(bfd_t * bfd)
{
	assert(bfd);

	/*
	 * RFC5880:
	 * When bfd.SessionState is not Up, the system MUST set
	 * bfd.DesiredMinTxInterval to a value of not less than
	 * one second (1,000,000 microseconds)
	 */
	bfd_idle_local_tx_intv(bfd);

	if (bfd_expire_scheduled(bfd))
		bfd_expire_cancel(bfd);

	bfd_event_send(bfd);
}

/* Runs when BFD session state goes Down */
static void
bfd_state_down(bfd_t * bfd, char diag)
{
	assert(bfd);
	assert(BFD_VALID_DIAG(diag));

	bfd->local_state = BFD_STATE_DOWN;
	bfd->local_diag = diag;

	log_message(LOG_WARNING, "BFD_Instance(%s) Entering %s state"
		    " (Local diagnostic - %s, Remote diagnostic - %s)",
		    bfd->iname, BFD_STATE_STR(bfd->local_state),
		    BFD_DIAG_STR(bfd->local_diag),
		    BFD_DIAG_STR(bfd->remote_diag));

	bfd_reset_schedule(bfd);

	bfd_state_fall(bfd);
}

/* Runs when BFD session state goes AdminDown */
static void
bfd_state_admindown(bfd_t * bfd)
{
	assert(bfd);

	bfd->local_state = BFD_STATE_ADMINDOWN;
	bfd->local_diag = BFD_DIAG_ADMIN_DOWN;

	if (bfd_sender_scheduled(bfd))
		bfd_sender_cancel(bfd);

	log_message(LOG_WARNING, "BFD_Instance(%s) Entering %s state",
		    bfd->iname, BFD_STATE_STR(bfd->local_state));

	bfd_state_fall(bfd);
}

/* Common actions for Init and Up states */
static void
bfd_state_rise(bfd_t * bfd)
{
	/* RFC5880 doesn't state if this must be done or not */
	bfd->local_diag = BFD_DIAG_NO_DIAG;

	log_message(LOG_INFO, "BFD_Instance(%s) Entering %s state",
		    bfd->iname, BFD_STATE_STR(bfd->local_state));

	if (bfd_reset_scheduled(bfd))
		bfd_reset_cancel(bfd);

	if (!bfd_expire_scheduled(bfd))
		bfd_expire_schedule(bfd);

	bfd_event_send(bfd);
}

/* Runs when BFD session state goes Up */
static void
bfd_state_up(bfd_t * bfd)
{
	assert(bfd);
	bfd->local_state = BFD_STATE_UP;
	bfd_state_rise(bfd);
}

/* Runs when BFD session state goes Init */
static void
bfd_state_init(bfd_t * bfd)
{
	assert(bfd);
	/* According to RFC5880 session cannot directly
	   transition from Init to Up state */
	assert(!BFD_ISUP(bfd));
	bfd->local_state = BFD_STATE_INIT;
	bfd_state_rise(bfd);
}

/* Dumps current timers values */
static void
bfd_dump_timers(bfd_t * bfd)
{
	assert(bfd);

	log_message(LOG_INFO, "BFD_Instance(%s)"
		    " --------------< Session parameters >-------------",
		    bfd->iname);
	log_message(LOG_INFO, "BFD_Instance(%s)"
		    "        min_tx  min_rx  tx_intv  mult  detect_time",
		    bfd->iname);
	log_message(LOG_INFO, "BFD_Instance(%s)"
		    " local %7u %7u %8u %5u %12u",
		    bfd->iname, bfd->local_min_tx_intv / 1000,
		    bfd->local_min_rx_intv / 1000,
		    bfd->local_tx_intv / 1000, bfd->local_detect_mult,
		    bfd->local_detect_time / 1000);
	log_message(LOG_INFO, "BFD_Instance(%s)" " remote %6u %7u %8u %5u %12u",
		    bfd->iname, bfd->remote_min_tx_intv / 1000,
		    bfd->remote_min_rx_intv / 1000,
		    bfd->remote_tx_intv / 1000, bfd->remote_detect_mult,
		    bfd->remote_detect_time / 1000);
}

/*
 * Packet handling functions
 */

/* Sends a control packet to the neighbor (called from bfd_sender_thread)
   returns -1 on error */
static int
bfd_send_packet(int fd, bfdpkt_t * pkt)
{
	int ret = 0;

	assert(fd >= 0);
	assert(pkt);

	ret =
	    sendto(fd, pkt->buf, pkt->len, 0,
		   (struct sockaddr *) &pkt->dst_addr, sizeof (pkt->dst_addr));
	if (ret == -1)
		log_message(LOG_ERR, "sendto() error (%m)");

	return ret;

}

/* Handles incoming control packet (called from bfd_reciever_thread) and
   processes it through a BFD state machine. */
static void
bfd_handle_packet(bfdpkt_t * pkt)
{
	unsigned int old_local_tx_intv = 0, old_remote_tx_intv = 0,
	    old_local_detect_time = 0, old_remote_detect_time = 0;
	bfd_t *bfd = NULL;

	assert(pkt);
	assert(pkt->hdr);

	/* Perform sanity checks on a packet */
	if (bfd_check_packet(pkt)) {
		if (debug & 32) {
			log_message(LOG_ERR,
				    "Discarding bogus packet from %s:%i",
				    inet_sockaddrtos(&pkt->src_addr),
				    inet_sockaddrport(&pkt->src_addr));
		}
		return;
	}

	/* Lookup session */
	if (!pkt->hdr->remote_discr)
		bfd = find_bfd_by_addr(&pkt->src_addr);
	else
		bfd = find_bfd_by_discr(ntohl(pkt->hdr->remote_discr));

	if (!bfd) {
		if (debug & 32) {
			log_message(LOG_ERR, "Discarding packet from %s:%i"
				    " (session is not found - your"
				    " discriminator field is %u)",
				    inet_sockaddrtos(&pkt->src_addr),
				    inet_sockaddrport(&pkt->src_addr),
				    pkt->hdr->remote_discr);
		}
		return;
	}

	/* Authentication is not supported for now */
	if (pkt->hdr->auth != 0) {
		if (debug & 32) {
			log_message(LOG_ERR, "Discarding packet from %s:%i"
				    " (auth bit is set, but no authentication"
				    "  is in use)",
				    inet_sockaddrtos(&pkt->src_addr),
				    inet_sockaddrport(&pkt->src_addr));
		}
		return;
	}

	/* Discard all packets while in AdminDown state */
	if (bfd->local_state == BFD_STATE_ADMINDOWN) {
		if (debug & 32) {
			log_message(LOG_INFO, "Discarding packet from %s:%i"
				    " (session is in AdminDown state)",
				    inet_sockaddrtos(&pkt->src_addr),
				    inet_sockaddrport(&pkt->src_addr));
		}
		return;
	}

	/* Update state variables */
	bfd->remote_discr = ntohl(pkt->hdr->local_discr);
	bfd->remote_state = pkt->hdr->state;
	bfd->remote_diag = pkt->hdr->diag;
	bfd->remote_min_rx_intv = ntohl(pkt->hdr->min_rx_intv);
	bfd->remote_min_tx_intv = ntohl(pkt->hdr->min_tx_intv);
	bfd->remote_demand = pkt->hdr->demand;
	bfd->remote_detect_mult = pkt->hdr->detect_mult;

	/* Terminate poll sequence */
	if (pkt->hdr->final)
		bfd->poll = 0;

	/* Save old timers */
	old_local_tx_intv = bfd->local_tx_intv;
	old_remote_tx_intv = bfd->remote_tx_intv;
	old_local_detect_time = bfd->local_detect_time;
	old_remote_detect_time = bfd->remote_detect_time;

	/*
	 * Recalculate local and remote TX intervals if:
	 *  Control packet with 'Final' bit is received OR
	 *  Control packet with 'Poll' bit is received OR
	 *  Session is not UP
	 */
	if ((pkt->hdr->final && bfd->local_state == BFD_STATE_UP)
	    || (pkt->hdr->poll && bfd->local_state == BFD_STATE_UP)
	    || bfd->local_state != BFD_STATE_UP) {
		bfd_update_local_tx_intv(bfd);
		bfd_update_remote_tx_intv(bfd);
	}

	/* Update the Detection Time */
	bfd->local_detect_time = bfd->remote_detect_mult * bfd->remote_tx_intv;
	bfd->remote_detect_time = bfd->local_detect_mult * bfd->local_tx_intv;

	/* Check if timers are changed */
	if (bfd->local_tx_intv != old_local_tx_intv ||
	    bfd->remote_tx_intv != old_remote_tx_intv ||
	    bfd->local_detect_time != old_local_detect_time ||
	    bfd->remote_detect_time != old_remote_detect_time)
		if (debug & 32)
			bfd_dump_timers(bfd);

	/* Reschedule sender if local_tx_intv is being reduced */
	if (bfd->local_tx_intv < old_local_tx_intv)
		if (bfd_sender_scheduled(bfd))
			bfd_sender_reschedule(bfd);

	/* Report detection time changes */
	if (bfd->local_detect_time != old_local_detect_time)
		log_message(LOG_INFO, "BFD_Instance(%s) Detection time"
			    " is %u ms (was %u ms)", bfd->iname,
			    bfd->local_detect_time / 1000,
			    old_local_detect_time / 1000);

	/* BFD state machine */
	if (bfd->remote_state == BFD_STATE_ADMINDOWN
	    && bfd->local_state != BFD_STATE_DOWN) {
		bfd_state_down(bfd, BFD_DIAG_NBR_SIGNALLED_DOWN);
	} else {
		if (bfd->local_state == BFD_STATE_DOWN) {
			if (bfd->remote_state == BFD_STATE_DOWN)
				bfd_state_init(bfd);
			else if (bfd->remote_state == BFD_STATE_INIT)
				bfd_state_up(bfd);
		} else if (bfd->local_state == BFD_STATE_INIT) {
			if (bfd->remote_state == BFD_STATE_INIT
			    || bfd->remote_state == BFD_STATE_UP)
				bfd_state_up(bfd);
		} else if (bfd->local_state == BFD_STATE_UP) {
			if (bfd->remote_state == BFD_STATE_DOWN)
				bfd_state_down(bfd,
					       BFD_DIAG_NBR_SIGNALLED_DOWN);
		}
	}

	if (bfd->remote_demand
	    && bfd->local_state == BFD_STATE_UP
	    && bfd->remote_state == BFD_STATE_UP)
		if (bfd_sender_scheduled(bfd))
			bfd_sender_cancel(bfd);

	if (!bfd->remote_demand
	    || bfd->local_state != BFD_STATE_UP
	    || bfd->remote_state != BFD_STATE_UP)
		if (!bfd_sender_scheduled(bfd))
			bfd_sender_schedule(bfd);

	if (pkt->hdr->poll) {
		bfd->final = 1;
		thread_add_event(master, bfd_sender_thread, bfd, 0);
	}

	/* Update last seen timer */
	bfd->last_seen = timer_now();

	/* Delay expiration if scheduled */
	if (bfd_expire_scheduled(bfd))
		bfd_expire_reschedule(bfd);
}

/* Reads one packet from input socket */
static int
bfd_recieve_packet(bfdpkt_t * pkt, int fd, char *buf, ssize_t bufsz)
{
	ssize_t len = 0;
	unsigned int ttl = 0;
	struct msghdr msg = { 0 };
	struct cmsghdr *cmsg = NULL;
	char cbuf[CMSG_SPACE(sizeof (ttl))] = { 0 };
	struct iovec iov[1] = { {0} };

	assert(pkt);
	assert(fd >= 0);
	assert(buf);
	assert(bufsz);

	iov[0].iov_base = buf;
	iov[0].iov_len = bufsz;

	msg.msg_name = &pkt->src_addr;
	msg.msg_namelen = sizeof (pkt->src_addr);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;
	msg.msg_control = cbuf;
	msg.msg_controllen = sizeof (cbuf);

	len = recvmsg(fd, &msg, MSG_DONTWAIT);
	if (len == -1) {
		log_message(LOG_ERR, "recvmsg() error (%m)");
		return 1;
	}

	if (msg.msg_flags & MSG_TRUNC) {
		log_message(LOG_WARNING, "recvmsg() message truncated");
		return 1;
	}

	if (msg.msg_flags & MSG_CTRUNC)
		log_message(LOG_WARNING, "recvmsg() control message truncated");

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IP || cmsg->cmsg_type != IP_TTL) {
			log_message(LOG_WARNING, "recvmsg() received"
				    " unexpected control message");
		} else {
			assert(!ttl);
			ttl = *CMSG_DATA(cmsg);
		}
	}

	if (!ttl)
		log_message(LOG_WARNING,
			    "recvmsg() returned no TTL control message");

	pkt->hdr = (bfdhdr_t *) buf;
	pkt->len = len;
	pkt->ttl = ttl;

	return 0;
}

/*
 * Reciever thread
 */

/* Runs when data is available in listening socket */
static int
bfd_reciever_thread(thread_t * thread)
{
	bfd_data_t *data = NULL;
	bfdpkt_t *pkt = NULL;
	int ret = 0;
	int fd = -1;

	assert(thread);
	data = THREAD_ARG(thread);
	fd = THREAD_FD(thread);
	assert(data);
	assert(fd >= 0);

	data->thread_in = NULL;

	/* Ignore THREAD_READ_TIMEOUT */
	if (thread->type == THREAD_READY_FD) {
		pkt = (bfdpkt_t *) MALLOC(sizeof (bfdpkt_t));
		ret = bfd_recieve_packet(pkt, fd, bfd_buffer, BFD_BUFFER_SIZE);
		if (!ret)
			bfd_handle_packet(pkt);
		FREE(pkt);
	}

	data->thread_in =
	    thread_add_read(thread->master, bfd_reciever_thread, data,
			    fd, 60 * TIMER_HZ);

	return 0;
}

/*
 * Initialization functions
 */

/* Prepares UDP socket for listening on *:3784 (both IPv4 and IPv6) */
static int
bfd_open_fd_in(bfd_data_t * data)
{
	struct addrinfo hints = { 0 };
	struct addrinfo *ai_in = NULL;
	int ret = 0;
	int yes = 1;

	assert(data);
	assert(data->fd_in == -1);

	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_socktype = SOCK_DGRAM;
	ai_in = (struct addrinfo *) MALLOC(sizeof (struct addrinfo));

	ret = getaddrinfo(NULL, BFD_CONTROL_PORT, &hints, &ai_in);
	if (ret != 0) {
		log_message(LOG_ERR, "getaddrinfo() error (%s)",
			    gai_strerror(ret));
		ret = 1;
		goto out;
	}

	data->fd_in = socket(ai_in->ai_family, ai_in->ai_socktype,
			     ai_in->ai_protocol);
	if (data->fd_in == -1) {
		log_message(LOG_ERR, "socket() error (%m)");
		ret = 1;
		goto out;
	}

	ret =
	    setsockopt(data->fd_in, IPPROTO_IP, IP_RECVTTL, &yes, sizeof (yes));
	if (ret == -1) {
		log_message(LOG_ERR, "setsockopt() error (%m)");
		ret = 1;
		goto out;
	}

	ret = bind(data->fd_in, ai_in->ai_addr, ai_in->ai_addrlen);
	if (ret == -1) {
		log_message(LOG_ERR, "bind() error (%m)");
		ret = 1;
		goto out;
	}

	ret = 0;

      out:
	freeaddrinfo(ai_in);
	return ret;
}

/* Prepares UDP socket for sending data to neighbor */
static int
bfd_open_fd_out(bfd_t * bfd)
{
	int ttl = BFD_CONTROL_TTL;
	int ret = 0;

	assert(bfd);
	assert(bfd->fd_out == -1);

	bfd->fd_out = socket(bfd->nbr_addr.ss_family, SOCK_DGRAM, IPPROTO_UDP);
	if (bfd->fd_out == -1) {
		log_message(LOG_ERR, "BFD_Instance(%s) socket() error (%m)",
			    bfd->iname);
		return 1;
	}

	if (bfd->src_addr.ss_family) {
		ret =
		    bind(bfd->fd_out, (struct sockaddr *) &bfd->src_addr,
			 sizeof (struct sockaddr));
		if (ret == -1) {
			log_message(LOG_ERR,
				    "BFD_Instance(%s) bind() error (%m)",
				    bfd->iname);
			return 1;
		}
	}

	ret = setsockopt(bfd->fd_out, IPPROTO_IP, IP_TTL, &ttl, sizeof (ttl));
	if (ret == -1) {
		log_message(LOG_ERR, "BFD_Instance(%s) setsockopt() "
			    " error (%m)", bfd->iname);
		return 1;
	}

	return 0;
}

/* Opens all needed sockets */
static int
bfd_open_fds(bfd_data_t * data)
{
	bfd_t *bfd = NULL;
	element e = NULL;

	assert(data);
	assert(data->bfd);

	/* Do not reopen input socket on reload */
	if (bfd_data->fd_in == -1) {
		if (bfd_open_fd_in(data)) {
			log_message(LOG_ERR, "Unable to open listening socket");
			/* There is no point to stay alive w/o listening socket */
			return 1;
		}
	}

	for (e = LIST_HEAD(data->bfd); e; ELEMENT_NEXT(e)) {
		bfd = ELEMENT_DATA(e);
		assert(bfd);

		/* Skip disabled instances */
		if (bfd->disabled)
			continue;

		if (bfd_open_fd_out(bfd)) {
			log_message(LOG_ERR, "BFD_Instance(%s) Unable to"
				    " open output socket, disabling instance",
				    bfd->iname);
			bfd_state_admindown(bfd);
		}
	}

	return 0;
}

/* Registers sender and reciever threads */
static void
bfd_register_workers(bfd_data_t * data)
{
	bfd_t *bfd = NULL;
	element e = NULL;

	assert(data);
	assert(!data->thread_in);

	/* Set timeout to 1 minute */
	data->thread_in = thread_add_read(master, bfd_reciever_thread,
					  data, data->fd_in, 60 * TIMER_HZ);

	/* Resume or schedule threads */
	for (e = LIST_HEAD(data->bfd); e; ELEMENT_NEXT(e)) {
		bfd = ELEMENT_DATA(e);

		/* Skip disabled instances */
		if (bfd->disabled)
			continue;

		/* Do not start anything if instance is in AdminDown state.
		   Discard saved state if any */
		if (bfd_sender_suspended(bfd)) {
			if (bfd_sender_suspended(bfd)) {
				if (BFD_ISADMINDOWN(bfd))
					bfd_sender_discard(bfd);
				else
					bfd_sender_resume(bfd);
			}
		} else if (!BFD_ISADMINDOWN(bfd))
			bfd_sender_schedule(bfd);

		if (bfd_expire_suspended(bfd)) {
			if (BFD_ISADMINDOWN(bfd))
				bfd_expire_discard(bfd);
			else
				bfd_expire_resume(bfd);
		}

		if (bfd_reset_suspended(bfd)) {
			if (BFD_ISADMINDOWN(bfd))
				bfd_reset_discard(bfd);
			else
				bfd_reset_resume(bfd);
		}
	}
}

/* Suspends threads, closes sockets */
void
bfd_dispatcher_release(bfd_data_t * data)
{
	bfd_t *bfd = NULL;
	element e = NULL;

	assert(data);

	/* Looks like dispatcher wasn't initialized yet
	   This can happen is case of a configuration error */
	if (!data->thread_in)
		return;

	assert(data->fd_in != -1);

	thread_cancel(data->thread_in);
	data->thread_in = NULL;

	/* Do not close fd_in on reload */
	if (!reload) {
		close(data->fd_in);
		data->fd_in = -1;
	}

	/* Suspend threads for possible resuming after reconfiguration */
	set_time_now();
	for (e = LIST_HEAD(data->bfd); e; ELEMENT_NEXT(e)) {
		bfd = ELEMENT_DATA(e);

		/* Skip disabled instances */
		if (bfd->disabled)
			continue;

		if (bfd_sender_scheduled(bfd))
			bfd_sender_suspend(bfd);

		if (bfd_expire_scheduled(bfd))
			bfd_expire_suspend(bfd);

		if (bfd_reset_scheduled(bfd))
			bfd_reset_suspend(bfd);

		assert(bfd->fd_out != -1);
		close(bfd->fd_out);
		bfd->fd_out = -1;
	}
}

/* Starts BFD dispatcher */
int
bfd_dispatcher_init(thread_t * thread)
{
	bfd_data_t *data = NULL;

	assert(thread);

	data = THREAD_ARG(thread);
	if (bfd_open_fds(data) == -1)
		exit(EXIT_FAILURE);
	bfd_register_workers(data);

	return 0;
}
