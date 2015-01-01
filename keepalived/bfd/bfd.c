/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        BFD implementation as specified by RFC5880, RFC5881
 *              Bidirectional Forwarding Detection (BFD) is a protocol
 *              which can provide failure detection on bidirectional path
 *              between two hosts. A pair of host creates BFD session for
 *              the communications path. During the communication, hosts
 *              transmit BFD packets periodically over the path between
 *              them, and if one host stops receiving BFD packets for
 *              long enough, some component in the path to the correspondent
 *              peer is assumed to have failed
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

#include "bfd.h"
#include "bfd_data.h"
#include "logger.h"

/* Initial state */
const bfd_t bfd0 = {
	.local_state = BFD_STATE_DOWN,
	.remote_state = BFD_STATE_DOWN,
	.local_discr = 0,	/* ! */
	.remote_discr = 0,
	.local_diag = BFD_DIAG_NO_DIAG,
	.remote_diag = BFD_DIAG_NO_DIAG,
	.remote_min_tx_intv = 0,
	.remote_min_rx_intv = 0,
	.local_demand = 0,
	.remote_demand = 0,
	.remote_detect_mult = 0,
	.poll = 0,
	.final = 0,
	.local_tx_intv = 0,
	.remote_tx_intv = 0,
	.local_detect_time = 0,
	.remote_detect_time = 0,
	.last_seen = (struct timeval) {0},
};

void
bfd_update_local_tx_intv(bfd_t * bfd)
{
	bfd->local_tx_intv = bfd->local_min_tx_intv > bfd->remote_min_rx_intv ?
	    bfd->local_min_tx_intv : bfd->remote_min_rx_intv;
}

void
bfd_update_remote_tx_intv(bfd_t * bfd)
{
	bfd->remote_tx_intv = bfd->local_min_rx_intv > bfd->remote_min_tx_intv ?
	    bfd->local_min_rx_intv : bfd->remote_min_tx_intv;
}

void
bfd_idle_local_tx_intv(bfd_t * bfd)
{
	bfd->local_tx_intv = bfd->local_idle_tx_intv;
}

void
bfd_set_poll(bfd_t * bfd)
{
	if (debug & 32)
		log_message(LOG_INFO, "BFD_Instance(%s) Starting poll sequence",
			    bfd->iname);
	/*
	 * RFC5880:
	 * ... If the timing is such that a system receiving a Poll Sequence
	 * wishes to change the parameters described in this paragraph, the
	 * new parameter values MAY be carried in packets with the Final (F)
	 * bit set, even if the Poll Sequence has not yet been sent.
	 */
	if (bfd->final != 1)
		bfd->poll = 1;
}

/* Copies BFD state */
void
bfd_copy_state(const bfd_t * bfd_old, bfd_t * bfd)
{
	assert(bfd_old);
	assert(bfd);

	/* Copy state variables */
	bfd->local_state = bfd_old->local_state;
	bfd->remote_state = bfd_old->remote_state;
	bfd->local_discr = bfd_old->local_discr;
	bfd->remote_discr = bfd_old->remote_discr;
	bfd->local_diag = bfd_old->local_diag;
	bfd->remote_diag = bfd_old->remote_diag;
	bfd->remote_min_tx_intv = bfd_old->remote_min_tx_intv;
	bfd->remote_min_rx_intv = bfd_old->remote_min_rx_intv;
	bfd->local_demand = bfd_old->local_demand;
	bfd->remote_demand = bfd_old->remote_demand;
	bfd->remote_detect_mult = bfd_old->remote_detect_mult;
	bfd->poll = bfd_old->poll;
	bfd->final = bfd_old->final;

	bfd->local_tx_intv = bfd_old->local_tx_intv;
	bfd->remote_tx_intv = bfd_old->remote_tx_intv;
	bfd->local_detect_time = bfd_old->local_detect_time;
	bfd->remote_detect_time = bfd_old->remote_detect_time;

	bfd->last_seen = bfd_old->last_seen;
}

/* Copies thread sands */
void
bfd_copy_sands(const bfd_t * bfd_old, bfd_t * bfd)
{
	bfd->sands_out = bfd_old->sands_out;
	bfd->sands_exp = bfd_old->sands_exp;
	bfd->sands_rst = bfd_old->sands_rst;
}

/* Resets BFD instance to initial state */
void
bfd_init_state(bfd_t * bfd)
{
	assert(bfd);

	bfd_copy_state(&bfd0, bfd);
	bfd->local_discr = bfd_get_random_discr(bfd_data);
	bfd->local_tx_intv = bfd->local_idle_tx_intv;
}

/*
 * Builds BFD packet
 */
void
bfd_build_packet(bfdpkt_t * pkt, const bfd_t * bfd, char *buf,
		 const ssize_t bufsz)
{
	ssize_t len = sizeof (bfdhdr_t);

	assert(bfd);
	assert(buf);
	assert(bufsz >= len);

	memset(buf, 0, bufsz);
	pkt->hdr = (bfdhdr_t *) buf;

	pkt->hdr->diag = bfd->local_diag;
	pkt->hdr->version = BFD_VERSION_1;
	pkt->hdr->state = bfd->local_state;
	pkt->hdr->poll = bfd->poll;
	pkt->hdr->final = bfd->final;
	pkt->hdr->cplane = 0;
	pkt->hdr->auth = 0;	/* Auth is not supported */
	pkt->hdr->demand = bfd->local_demand;
	pkt->hdr->multipoint = 0;
	pkt->hdr->detect_mult = bfd->local_detect_mult;
	pkt->hdr->len = len;
	pkt->hdr->local_discr = htonl(bfd->local_discr);
	pkt->hdr->remote_discr = htonl(bfd->remote_discr);
	pkt->hdr->min_tx_intv = htonl(bfd->local_min_tx_intv);
	pkt->hdr->min_rx_intv = htonl(bfd->local_min_rx_intv);
	pkt->hdr->min_echo_rx_intv = 0;	/* Echo function is not supported */

	pkt->len = len;
	pkt->dst_addr = bfd->nbr_addr;
	pkt->buf = buf;
}

/*
 * Performs sanity checks on a packet
 */
int
bfd_check_packet(const bfdpkt_t * pkt)
{
	assert(pkt->hdr);

	/* Preliminary sanity checks */
	if (sizeof (bfdhdr_t) > pkt->len) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet is too small: %u bytes",
				    pkt->len);
		return 1;
	}

	if (pkt->hdr->len != pkt->len) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet size mismatch:"
				    " length field: %u bytes"
				    ", buffer size: %u bytes",
				    pkt->hdr->len, pkt->len);
		return 1;
	}

	/* Generalized TTL Security Mechanism Check (RFC5881) */
	if (pkt->ttl && pkt->ttl != BFD_CONTROL_TTL) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet ttl(%i) != %i",
				    pkt->ttl, BFD_CONTROL_TTL);
		return 1;
	}

	/* Main Checks (RFC5880) */
	if (pkt->hdr->version != BFD_VERSION_1) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet is of unsupported"
				    " version: %i", pkt->hdr->version);
		return 1;
	}

	if (!pkt->hdr->detect_mult) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet 'detection multiplier'"
				    " field is zero");
		return 1;
	}

	if (pkt->hdr->multipoint) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet has 'multipoint' flag");
		return 1;
	}

	if (!pkt->hdr->local_discr) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet 'my discriminator'"
				    " field is zero");
		return 1;
	}

	if (!pkt->hdr->remote_discr
	    && pkt->hdr->state != BFD_STATE_DOWN
	    && pkt->hdr->state != BFD_STATE_ADMINDOWN) {
		if (debug & 32)
			log_message(LOG_ERR,
				    "Packet 'your discriminator' field is"
				    " zero and 'state' field is not"
				    " Down or AdminDown");
		return 1;
	}

	/* Additional sanity checks */
	if (pkt->hdr->poll && pkt->hdr->final) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet has both poll and final"
				    "  flags set");
		return 1;
	}

	if (!BFD_VALID_STATE(pkt->hdr->state)) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet has invalid 'state'"
				    " field: %u", pkt->hdr->state);
		return 1;
	}

	if (!BFD_VALID_DIAG(pkt->hdr->diag)) {
		if (debug & 32)
			log_message(LOG_ERR, "Packet has invalid 'diag'"
				    " field: %u", pkt->hdr->diag);
		return 1;
	}

	return 0;
}
