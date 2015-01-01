/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        BFD event handling
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
#include "bfd_event.h"
#include "logger.h"
#include "main.h"

void
bfd_event_send(bfd_t * bfd)
{
	bfd_event_t *evt;
	ssize_t evtlen = sizeof (bfd_event_t);
	int ret = 0;

	assert(bfd);
	evt = (bfd_event_t *) MALLOC(evtlen);

	strncpy(evt->iname, bfd->iname, 31);
	evt->state = bfd->local_state;
	evt->sent_time = timer_now();

	ret = write(bfd_event_pipe[1], evt, evtlen);
	if (ret == -1 && debug & 32)
		log_message(LOG_ERR, "BFD_Instance(%s) write() error %m",
			    bfd->iname);

	FREE(evt);
}
