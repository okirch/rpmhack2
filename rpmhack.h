/*
 * rpmhack
 *
 *   Copyright (C) 2023 Olaf Kirch <okir@suse.de>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef RPMHACK_H
#define RPMHACK_H

#include <stdbool.h>

#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmdb.h>
#include <rpm/header.h>
#include <rpm/rpmlog.h>


#define DEFAULT_RPMDB_PATH "/usr/lib/sysimage/rpm"

typedef struct pkg {
	char *		name;
	char *		epoch;
	char *		version;
	char *		release;
	char *		NEVR;

	char *		header_path;
	Header		h;
} pkg_t;

typedef struct pkgarray {
	unsigned int	count;
	pkg_t **	data;
} pkgarray_t;

typedef struct pkgiter {
	const pkgarray_t *pkgs;
	unsigned int	pos;
} pkgiter_t;

typedef struct pkgdb {
	char *		path;
	char *		root;
	char *		fullpath;
	bool		zap_on_close;

	rpmts		ts;
	rpmdb		db;

	/* for processing headers */
	rpmtd		td_name, td_epoch, td_version, td_release;

	pkgarray_t	pkgs;
} pkgdb_t;

struct pkgdb_open_file {
	struct pkgdb_open_file *next;

	const pkg_t *	pkg;
	FD_t		rpmfd;
};

typedef struct {
	pkgarray_t	same;
	pkgarray_t	added;
	pkgarray_t	removed;
	pkgarray_t	upgraded;
	pkgarray_t	downgraded;

	/* For install */
	struct pkgdb_open_file *fdcache;
	pkg_t *		current_element;
} dbdiff_t;


extern void		pkgdb_free(pkgdb_t *db);


#define RPMLEAD_SIZE	96

extern int		rpmLeadBuild(Header h, unsigned char *buf, size_t size);
extern bool		rpmLeadOK(const unsigned char *buf, size_t size);

extern rpmRC		rpmGenerateSignature(char *SHA256, char *SHA1, uint8_t *MD5,
				rpm_loff_t size, rpm_loff_t payloadSize, FD_t fd);


extern void		fdInitDigest(FD_t fd, int hashalgo, rpmDigestFlags flags);
extern void		fdFiniDigest(FD_t fd, int id, void ** datap, size_t * lenp, int asAscii);


#endif /* RPMHACK_H */
