/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        Configuration file parser/reader.
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
#include "bfd_parser.h"
#include "logger.h"
#include "parser.h"
#include "global_parser.h"
#include "utils.h"

static void
bfd_handler(vector_t * strvec)
{
	char iname[BFD_INAME_MAX] = { 0 };
	char *name;
	int disabled = 0;
	assert(strvec);

	name = vector_slot(strvec, 1);
	(void) strncpy(iname, name, BFD_INAME_MAX - 1);

	if (iname[BFD_INAME_MAX - 1] != '\0') {
		iname[BFD_INAME_MAX - 1] = '\0';
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " name was truncated to %s (maximum length is %i"
			    " characters), disabling instance", name, iname,
			    BFD_INAME_MAX - 1);
		disabled = 1;
	}

	if (find_bfd_by_name(iname)) {
		(void) snprintf(iname, BFD_INAME_MAX, "<DUP-%i>",
				LIST_SIZE(bfd_data->bfd));
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s"
			    " was renamed to %s due to a duplicate name,"
			    " disabling instance", name, iname);
		disabled = 1;
	}

	alloc_bfd(iname, disabled);
}

static void
bfd_nbrip_handler(vector_t * strvec)
{
	bfd_t *bfd;
	int ret;
	struct sockaddr_storage nbr_addr;

	assert(strvec);
	assert(bfd_data);

	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);
	ret =
	    inet_stosockaddr(vector_slot(strvec, 1), BFD_CONTROL_PORT,
			     &nbr_addr);
	if (ret < 0) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " malformed neighbor address %s, disabling instance",
			    bfd->iname, FMT_STR_VSLOT(strvec, 1));
		bfd->disabled = 1;
	} else if (find_bfd_by_addr(&nbr_addr)) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " duplicate neighbor address %s, disabling instance",
			    bfd->iname, FMT_STR_VSLOT(strvec, 1));
		bfd->disabled = 1;
	} else {
		bfd->nbr_addr = nbr_addr;
	}
}

static void
bfd_srcip_handler(vector_t * strvec)
{
	bfd_t *bfd;
	int ret;
	struct sockaddr_storage src_addr;

	assert(strvec);
	assert(bfd_data);
	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);
	ret = inet_stosockaddr(vector_slot(strvec, 1), 0, &src_addr);
	if (ret < 0) {
		log_message(LOG_ERR,
			    "Configuration error: BFD instance %s has"
			    " malformed source address %s, ignoring",
			    bfd->iname, FMT_STR_VSLOT(strvec, 1));
	} else {
		bfd->src_addr = src_addr;
	}
}

static void
bfd_minrx_handler(vector_t * strvec)
{
	bfd_t *bfd = NULL;
	int value = 0;

	assert(strvec);
	assert(bfd_data);
	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = atoi(vector_slot(strvec, 1));

	if (value < BFD_MINRX_MIN || value > BFD_MINRX_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " min_rx value %i is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, value,
			    BFD_MINRX_MIN, BFD_MINRX_MAX);
	} else {
		bfd->local_min_rx_intv = value * 1000;
	}
}

static void
bfd_mintx_handler(vector_t * strvec)
{
	bfd_t *bfd = NULL;
	int value = 0;

	assert(strvec);
	assert(bfd_data);
	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = atoi(vector_slot(strvec, 1));

	if (value < BFD_MINTX_MIN || value > BFD_MINTX_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " min_tx value %i is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, value,
			    BFD_MINTX_MIN, BFD_MINTX_MAX);
	} else {
		bfd->local_min_tx_intv = value * 1000;
	}
}

static void
bfd_idletx_handler(vector_t * strvec)
{
	bfd_t *bfd = NULL;
	int value = 0;

	assert(strvec);
	assert(bfd_data);
	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = atoi(vector_slot(strvec, 1));

	if (value < BFD_IDLETX_MIN || value > BFD_IDLETX_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " min_tx value %i is not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, value,
			    BFD_IDLETX_MIN, BFD_IDLETX_MAX);
	} else {
		bfd->local_idle_tx_intv = value * 1000;
	}
}

static void
bfd_multiplier_handler(vector_t * strvec)
{
	bfd_t *bfd = NULL;
	int value = 0;

	assert(strvec);
	assert(bfd_data);
	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	value = atoi(vector_slot(strvec, 1));

	if (value < BFD_MULTIPLIER_MIN || value > BFD_MULTIPLIER_MAX) {
		log_message(LOG_ERR, "Configuration error: BFD instance %s"
			    " min_tx value %i not valid (must be in range"
			    " [%u-%u]), ignoring", bfd->iname, value,
			    BFD_MULTIPLIER_MIN, BFD_MULTIPLIER_MAX);
	} else {
		bfd->local_detect_mult = value;
	}
}

static void
bfd_disabled_handler(vector_t * strvec)
{
	bfd_t *bfd = NULL;

	assert(strvec);
	assert(bfd_data);
	bfd = LIST_TAIL_DATA(bfd_data->bfd);
	assert(bfd);

	bfd->disabled = 1;
}

vector_t *
bfd_init_keywords(void)
{
	global_init_keywords();

	install_keyword_root("bfd_instance", &bfd_handler);
	install_keyword("source_ip", &bfd_srcip_handler);
	install_keyword("neighbor_ip", &bfd_nbrip_handler);
	install_keyword("min_rx", &bfd_minrx_handler);
	install_keyword("min_tx", &bfd_mintx_handler);
	install_keyword("idle_tx", &bfd_idletx_handler);
	install_keyword("multiplier", &bfd_multiplier_handler);
	install_keyword("disabled", &bfd_disabled_handler);

	return keywords;
}
