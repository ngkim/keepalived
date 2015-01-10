/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        bfd.c include file.
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
#ifndef _BFD_H_
#define _BFD_H_

#include "utils.h"
#include "scheduler.h"

/*
 * RFC5881
 */
#define BFD_CONTROL_PORT	"3784"
#define BFD_CONTROL_TTL		255

/*
 * Default parameters and limits
 */
#define BFD_MINRX_MIN		1
#define BFD_MINRX_MAX		1000
#define BFD_MINRX_DEFAULT	10

#define BFD_MINTX_MIN		1
#define BFD_MINTX_MAX		1000
#define BFD_MINTX_DEFAULT	10

#define BFD_IDLETX_MIN		1000
#define BFD_IDLETX_MAX		10000
#define BFD_IDLETX_DEFAULT	1000

#define BFD_MULTIPLIER_MIN	1
#define BFD_MULTIPLIER_MAX	10
#define BFD_MULTIPLIER_DEFAULT	5

/*
 * BFD Session
 */
/* Maximum instance name length including \0 */
#define BFD_INAME_MAX 32
typedef struct _bfd {
	/* Configuration parameters */
	char iname[BFD_INAME_MAX];	/* Instance name */
	struct sockaddr_storage nbr_addr;	/* Neighbor address */
	struct sockaddr_storage src_addr;	/* Source address */
	u_int32_t local_min_rx_intv;	/* Required min RX interval */
	u_int32_t local_min_tx_intv;	/* Desired min TX interval */
	u_int32_t local_idle_tx_intv;	/* Desired idle TX interval */
	u_char local_detect_mult;	/* Local detection multiplier */
	int disabled;		/* True if disabled in config */

	/* Internal variables */
	int fd_out;		/* Output socket fd */
	thread_t *thread_out;	/* Output socket thread */
	long sands_out;		/* Output thread sands, used for suspend/resume */
	thread_t *thread_exp;	/* Expire thread */
	long sands_exp;		/* Expire thread sands, used for suspend/resume */
	thread_t *thread_rst;	/* Reset thread */
	long sands_rst;		/* Reset thread sands, used for suspend/resume */

	/* State variables */
	u_char local_state:2;	/* Local state */
	u_char remote_state:2;	/* Remote state */
	u_int32_t local_discr;	/* Local discriminator */
	u_int32_t remote_discr;	/* Remote discriminator */
	u_char local_diag:5;	/* Local diagnostic code */
	u_char remote_diag:5;	/* Local diagnostic code */
	u_int32_t remote_min_tx_intv;	/* Remote min TX interval */
	u_int32_t remote_min_rx_intv;	/* Remote min RX interval */
	u_char local_demand;	/* Local demand mode */
	u_char remote_demand;	/* Remote demand mode */
	u_char remote_detect_mult;	/* Remote detection multiplier */
	u_char poll;		/* Poll sequence flag */
	u_char final;		/* Final flag */

	/* Calculated values */
	u_int32_t local_tx_intv;	/* Local transmit interval */
	u_int32_t remote_tx_intv;	/* Remote transmit interval */
	u_int32_t local_detect_time;	/* Local detection time */
	u_int32_t remote_detect_time;	/* Remote detection time */
	timeval_t last_seen;	/* Time of the last packet received */
} bfd_t;

/*
 * BFD Control Packet Header
 */
typedef struct _bfdhdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	u_char diag:5;
	u_char version:3;

	/* flags */
	u_char multipoint:1;
	u_char demand:1;
	u_char auth:1;
	u_char cplane:1;
	u_char final:1;
	u_char poll:1;
	u_char state:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	u_char version:3;
	u_char diag:5;

	/* flags */
	u_char state:2;
	u_char poll:1;
	u_char final:1;
	u_char cplane:1;
	u_char auth:1;
	u_char demand:1;
	u_char multipoint:1;
#else
#error "Unsupported byte order"
#endif
	u_char detect_mult;
	u_char len;

	u_int32_t local_discr;
	u_int32_t remote_discr;
	u_int32_t min_tx_intv;
	u_int32_t min_rx_intv;
	u_int32_t min_echo_rx_intv;
} bfdhdr_t;

/*
  Version
*/
#define BFD_VERSION_1			1

/*
   State (Sta)
*/

#define BFD_STATE_ADMINDOWN		0
#define BFD_STATE_DOWN			1
#define BFD_STATE_INIT			2
#define BFD_STATE_UP			3

#define	BFD_STATE_STR(s) \
	(BFD_STATE_ADMINDOWN == s ? "AdminDown" : \
	(BFD_STATE_DOWN == s ? "Down" : \
	(BFD_STATE_INIT == s ? "Init" : \
	(BFD_STATE_UP == s ? "Up" : "Unknown"))))

#define BFD_VALID_STATE(s) (s >= 0 && s <= 3)

#define BFD_ISADMINDOWN(b) (b->local_state == BFD_STATE_ADMINDOWN)
#define BFD_ISDOWN(b) (b->local_state == BFD_STATE_DOWN)
#define BFD_ISINIT(b) (b->local_state == BFD_STATE_INIT)
#define BFD_ISUP(b) (b->local_state == BFD_STATE_UP)

/*
   Diagnostic (Diag)
*/

#define BFD_DIAG_NO_DIAG		0
#define BFD_DIAG_EXPIRED		1
#define BFD_DIAG_ECHO_FAILED		2
#define BFD_DIAG_NBR_SIGNALLED_DOWN	3
#define BFD_DIAG_FWD_PLANE_RESET	4
#define BFD_DIAG_PATH_DOWN		5
#define BFD_DIAG_CAT_PATH_DOWN		6
#define BFD_DIAG_ADMIN_DOWN		7
#define BFD_DIAG_RCAT_PATH_DOWN		8

#define	BFD_DIAG_STR(d) \
	(BFD_DIAG_NO_DIAG == d ? "No Diagnostic" : \
	(BFD_DIAG_EXPIRED == d ? "Control Detection Time Expired" : \
	(BFD_DIAG_ECHO_FAILED == d ? "Echo Function Failed" : \
	(BFD_DIAG_NBR_SIGNALLED_DOWN == d ? "Neighbor Signaled Session Down" : \
	(BFD_DIAG_FWD_PLANE_RESET == d ? "Forwarding Plane Reset" : \
	(BFD_DIAG_PATH_DOWN == d ? "Path Down" : \
	(BFD_DIAG_CAT_PATH_DOWN == d ? "Concatenated Path Down" : \
	(BFD_DIAG_ADMIN_DOWN == d ? "Administratively Down" : \
	(BFD_DIAG_RCAT_PATH_DOWN == d ? "Reverse Concatenated Path Down" : "Unknown")))))))))

#define BFD_VALID_DIAG(d)    (d >= 0 && d <= 8)

/*
 * BFD Packet structure
 */
typedef struct _bfdpkt {
	bfdhdr_t *hdr;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage dst_addr;
	unsigned int ttl;
	unsigned int len;
	char *buf;
} bfdpkt_t;

extern void bfd_update_local_tx_intv(bfd_t *);
extern void bfd_update_remote_tx_intv(bfd_t *);
extern void bfd_idle_local_tx_intv(bfd_t * bfd);
extern void bfd_set_poll(bfd_t *);
extern void bfd_init_state(bfd_t *);
extern void bfd_copy_state(const bfd_t *, bfd_t *);
extern void bfd_copy_sands(const bfd_t *, bfd_t *);
extern int bfd_check_packet(const bfdpkt_t *);
extern void bfd_build_packet(bfdpkt_t * pkt, const bfd_t *, char *,
			     const ssize_t);

#endif				/* _BFD_H_ */
