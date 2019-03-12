/* $OpenBSD: version.h,v 1.64 2012/02/09 20:00:18 markus Exp $ */
/* Changes Copyright 2019 ALE USA Inc.  */
/* Changes added to provide indication that FIPS mode is enabled */


#define SSH_VERSION	"OpenSSH_6.0"

#define SSH_PORTABLE	"p1"

/* it is important to provide an indication that FIPS is supported */
#ifdef OPENSSL_FIPS_CAPABLE
	#define SSH_FIPS        "-FIPS"
#else
	#define SSH_FIPS        ""
#endif /* OPENSSL_FIPS_CAPABLE */
#define SSH_RELEASE     SSH_VERSION SSH_PORTABLE SSH_FIPS

