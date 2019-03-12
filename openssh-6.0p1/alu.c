/* $OpenBSD: cleanup.c,v 1.5 2006/08/03 03:34:42 deraadt Exp $ */
/*
 * Copyright 2019 ALE USA Inc
 * Copyright (c) 2003 Markus Friedl <markus@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include <unistd.h>
#include <netdb.h>

#include "alu.h"
#include "log.h"

/*
 * This function will return 0 ("not allowed") if one of the host's ips:
 * 1. Is a NI (127.2.x)
 * 2. Belongs to link-local (fe80 etc.)
 * That is, unless current user is root.
 * If host is empty, we will just allow it.
 * If host already is an IP address, we will use it.
 */
int alu_is_remote_host_allowed(char *host) {
	if(0 == getuid()) {
		return 1;
	}
	if(!host || !*host) {
		return 1;
	}
    struct addrinfo *info, *pinfo;
    if(getaddrinfo(host, 0, 0, &info)) {
		return 0;
    }
    for(pinfo = info; pinfo; pinfo = pinfo->ai_next) {
    	switch(pinfo->ai_family) {
			case AF_INET: {
		        char presentation[INET_ADDRSTRLEN];
		        if(!strncmp("127.2.", inet_ntop(AF_INET, &(((struct sockaddr_in *)pinfo->ai_addr)->sin_addr), presentation, sizeof(presentation)), 6)) {
		        	freeaddrinfo(info);
		        	return 0;
		        }
				break;
			}
            /*
             * NIs do not currently have IPv6 addresses. Should this change, we would need to come up with a correct way to match them.
             * Link-local is too broad because it could be used over a local segment.
			case AF_INET6: {
		        char presentation[INET6_ADDRSTRLEN];
		        if(!strncmp("fe80:", inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)pinfo->ai_addr)->sin6_addr), presentation, sizeof(presentation)), 5)) {
		        	freeaddrinfo(info);
		        	return 0;
		        }
				break;
			}
            */
    	}
    }
    freeaddrinfo(info);
	return 1;
}

#ifdef ALU_ENHANCE_CAPABLE
static int enhanced_mode = 0;
int alu_is_enhanced_enable() {
	return enhanced_mode;
}
void alu_get_configure_enhanced_mode () {
	if ( access(ENHANCED_ENABLE_FILE, F_OK) == 0 )
		enhanced_mode = 1;
	else 
		enhanced_mode = 0;
}
#endif

#ifdef ALU_CC_CAPABLE
static int cc_mode = 0;
int alu_is_cc_enable() {
	return cc_mode;
}
void alu_get_configure_cc_mode () {
	if ( access(CC_ENABLE_FILE, F_OK) == 0 )	 
		cc_mode = 1;	 
	else 
		cc_mode = 0;
}
#endif

#ifdef ALU_JITC_CAPABLE	 
static int jitc_mode = 0;
int alu_is_jitc_enable() {
	return jitc_mode;
}
void alu_get_configure_jitc_mode () {
	if ( access(JITC_ENABLE_FILE, F_OK) == 0 )
		jitc_mode = 1;
	else
		jitc_mode = 0;
}	 
#endif
