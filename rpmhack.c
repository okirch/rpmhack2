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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <getopt.h>

#include "rpmhack.h"
#include "tracing.h"


extern void		pkg_free(pkg_t *p);
extern int		pkg_compare(const pkg_t *pa, const pkg_t *pb, unsigned int *degree_p);
extern pkg_t *		pkg_read(const char *path);
extern bool		pkg_write(pkg_t *p, const char * path);

#define DROP(_ptr, _freefun) \
	do { \
		if (_ptr) { \
			_freefun(_ptr); \
			_ptr = NULL; \
		} \
	} while (0)


static inline void
set_string(char **ptr, const char *s)
{
	if (*ptr) {
		free(*ptr);
		*ptr = NULL;
	}
	if (s)
		*ptr = strdup(s);
}

static inline void
drop_string(char **ptr)
{
	set_string(ptr, NULL);
}

static const char *
__concat(const char *a, const char *b)
{
	static char path[PATH_MAX];

	if (a && b) {
		while (*b == '/')
			++b;
		snprintf(path, sizeof(path), "%s/%s", a, b);
		return path;
	}
	if (a)
		return a;
	return b;
}

pkgdb_t *
pkgdb_new(const char *root, const char *path)
{
	int vsflags = _RPMVSF_NOSIGNATURES; // |_RPMVSF_NODIGESTS;
	const char *fullpath;
	pkgdb_t *db;

	if (path == NULL)
		path = DEFAULT_RPMDB_PATH;

	db = calloc(1, sizeof(*db));
	set_string(&db->root, root);
	set_string(&db->path, path);

	db->ts = rpmtsCreate();

	if (root)
		rpmtsSetRootDir(db->ts, root);

	fullpath = __concat(root, path);
	set_string(&db->fullpath, fullpath);

	rpmtsSetVSFlags(db->ts, vsflags);

	return db;
}

pkgdb_t *
pkgdb_clone_tmp(const pkgdb_t *from, const char *clone_root)
{
	char pathbuf[PATH_MAX], cmdbuf[2 * PATH_MAX];
	const char *path;
	pkgdb_t *clone;

	if (clone_root == NULL) {
		log_error("%s: clone_root must not be NULL", __func__);
		return NULL;
	}

	snprintf(pathbuf, sizeof(pathbuf), "%s/tmp/rpmhack.XXXXXX", clone_root);
	path = mkdtemp(pathbuf);
	if (path == NULL) {
		snprintf(pathbuf, sizeof(pathbuf), "%s/rpmhack.XXXXXX", clone_root);
		path = mkdtemp(pathbuf);
	}
	if (path == NULL) {
		log_error("Unable to create temporary directory: %m");
		return NULL;
	}

	chmod(path, 0755);

	clone = pkgdb_new(clone_root, path + strlen(clone_root));
	clone->zap_on_close = true;

	snprintf(cmdbuf, sizeof(cmdbuf), "cp %s/* %s/", from->fullpath, clone->fullpath);
	if (system(cmdbuf) != 0) {
		log_error("failed to clone %s to %s", from->fullpath, clone->fullpath);
		pkgdb_free(clone);
		return NULL;
	}

	return clone;
}

void
pkgdb_zap(pkgdb_t *db)
{
	char cmdbuf[PATH_MAX];

	snprintf(cmdbuf, sizeof(cmdbuf), "rm -rf %s/", db->fullpath);
	if (system(cmdbuf) != 0)
		log_error("failed to remove %s", db->fullpath);
}

static void
pkgarray_destroy(pkgarray_t *a)
{
	unsigned int i;

	for (i = 0; i < a->count; ++i)
		pkg_free(a->data[i]);
	if (a->data)
		free(a->data);
	memset(a, 0, sizeof(*a));
}

static pkg_t *
pkgdb_find_best_match(pkgdb_t *db, const pkg_t *p)
{
	unsigned int i;
	unsigned int best_degree = 0;
	pkg_t *best_match = NULL;
	bool best_ambiguous = false;

	for (i = 0; i < db->pkgs.count; ++i) {
		pkg_t *match = db->pkgs.data[i];
		unsigned int degree = 0;

		(void) pkg_compare(p, match, &degree);
		if (!degree || degree < best_degree)
			continue;
		if (degree == best_degree) {
			best_ambiguous = true;
		} else {
			best_match = match;
			best_degree = degree;
			best_ambiguous = false;
		}
	}

	if (best_match) {
		if (best_ambiguous) {
			log_error("Unable to find best match for %s - ambiguous lookup", p->NEVR);
			return NULL;
		}

		return best_match;
	}

	return NULL;
}

static void
pkgarray_add(pkgarray_t *a, pkg_t *p)
{
	if ((a->count % 128) == 0) {
		a->data = realloc(a->data, (a->count + 128) * sizeof(p));
	}

	a->data[a->count++] = p;
}

static void
pkgarray_sort(pkgarray_t *a, int (*fn)(const void *, const void *))
{
	qsort(a->data, a->count, sizeof(a->data[0]), fn);
}

static void
pkgiter_init(pkgiter_t *i, const pkgarray_t *pkgs)
{
	memset(i, 0, sizeof(*i));
	i->pkgs = pkgs;
}

static pkg_t *
pkgiter_next(pkgiter_t *i)
{
	const pkgarray_t *pkgs = i->pkgs;
	pkg_t *pkg;

	if (i->pos >= pkgs->count)
		return NULL;

	pkg = pkgs->data[i->pos++];
	return pkg;
}

static dbdiff_t *
dbdiff_new(void)
{
	dbdiff_t *diff;

	diff = calloc(1, sizeof(*diff));
	return diff;
}

static void
dbdiff_free(dbdiff_t *diff)
{
	pkgarray_destroy(&diff->same);
}

static void
dbdiff_same(dbdiff_t *diff, pkg_t *p)
{
	pkgarray_add(&diff->same, p);
}

static void
dbdiff_removed(dbdiff_t *diff, pkg_t *p)
{
	pkgarray_add(&diff->removed, p);
}

static void
dbdiff_added(dbdiff_t *diff, pkg_t *p)
{
	pkgarray_add(&diff->added, p);
}

static void
dbdiff_upgraded(dbdiff_t *diff, pkg_t *p)
{
	pkgarray_add(&diff->upgraded, p);
}

static void
dbdiff_downgraded(dbdiff_t *diff, pkg_t *p)
{
	pkgarray_add(&diff->downgraded, p);
}

static void
dbdiff_write_set(FILE *log, const pkgarray_t *pkgs, char how)
{
	unsigned int i;

	for (i = 0; i < pkgs->count; ++i) {
		pkg_t *p = pkgs->data[i];

		fprintf(log, "%c %s\n", how, p->NEVR);
	}
}

static bool
dbdiff_write_headers(const char *diff_base, const pkgarray_t *pkgs)
{
	unsigned int i;

	for (i = 0; i < pkgs->count; ++i) {
		pkg_t *p = pkgs->data[i];
		char hpath[PATH_MAX];

		snprintf(hpath, sizeof(hpath), "%s/%s", diff_base, p->NEVR);
		if (!pkg_write(p, hpath))
			return false;
	}

	return true;
}

bool
dbdiff_write(dbdiff_t *diff, const char *path)
{
	char logpath[PATH_MAX];
	FILE *log;

	if (mkdir(path, 0755) < 0 && errno != EEXIST) {
		log_error("Cannot create %s: %m", path);
		return false;
	}

	snprintf(logpath, sizeof(logpath), "%s/changes", path);
	if (!(log = fopen(logpath, "w"))) {
		log_error("Unable to open %s: %m", logpath);
		return false;
	}

	dbdiff_write_set(log, &diff->added, 'a');
	dbdiff_write_set(log, &diff->removed, 'r');
	dbdiff_write_set(log, &diff->upgraded, 'u');
	dbdiff_write_set(log, &diff->downgraded, 'u');
	fclose(log);

	if (!dbdiff_write_headers(path, &diff->added)
	 || !dbdiff_write_headers(path, &diff->removed)
	 || !dbdiff_write_headers(path, &diff->upgraded)
	 || !dbdiff_write_headers(path, &diff->downgraded))
		return false;

	return true;
}

void
dbdiff_add_file(dbdiff_t *diff, const pkg_t *pkg)
{
	struct pkgdb_open_file *of;

	of = calloc(1, sizeof(*of));
	of->pkg = pkg;

	of->next = diff->fdcache;
	diff->fdcache = of;
}

static struct pkgdb_open_file *
dbdiff_filecache_lookup(dbdiff_t *diff, pkg_t *p)
{
	struct pkgdb_open_file *of;

	for (of = diff->fdcache; of; of = of->next) {
		if (of->pkg == p)
			return of;
	}

	log_error("Cannot find a file for the given header object");
	return NULL;
}

static FD_t
dbdiff_open_file(dbdiff_t *diff, pkg_t *p)
{
	struct pkgdb_open_file *of;

	if (!(of = dbdiff_filecache_lookup(diff, p)))
		return NULL;

	if (of->rpmfd == NULL
	 && (of->rpmfd = Fopen(p->header_path, "r")) == NULL)
		log_error("Unable to open %s: %m", p->header_path);
	return of->rpmfd;
}

static void
dbdiff_close_file(dbdiff_t *diff, pkg_t *p)
{
	struct pkgdb_open_file *of;

	if (!(of = dbdiff_filecache_lookup(diff, p)))
		return;

	if (of->rpmfd) {
		Fclose(of->rpmfd);
		of->rpmfd = NULL;
	}
}

dbdiff_t *
dbdiff_read(const char *path)
{
	char logpath[PATH_MAX], linebuf[256];
	dbdiff_t *diff;
	FILE *log;

	snprintf(logpath, sizeof(logpath), "%s/changes", path);
	if (!(log = fopen(logpath, "r"))) {
		log_error("Unable to open %s: %m", logpath);
		return false;
	}

	diff = dbdiff_new();

	while (fgets(linebuf, sizeof(linebuf), log) != NULL) {
		char headerpath[PATH_MAX];
		char *how, *filename;
		pkg_t *p;

		how = strtok(linebuf, " ");
		filename = strtok(NULL, "\n");
		if (how == NULL || filename == NULL) {
			log_error("Failed to parse %s", logpath);
			return false;
		}

		snprintf(headerpath, sizeof(headerpath), "%s/%s", path, filename);
		if (!(p = pkg_read(headerpath)))
			return false;

		if (how[0] == 'a')
			pkgarray_add(&diff->added, p);
		else if (how[0] == 'r')
			pkgarray_add(&diff->removed, p);
		else if (how[0] == 'u')
			pkgarray_add(&diff->upgraded, p);
		else if (how[0] == 'd')
			pkgarray_add(&diff->downgraded, p);

		dbdiff_add_file(diff, p);
	}
	fclose(log);

	return diff;
}

/*
 * Open the RPM package DB
 */
static bool
pkgdb_open(pkgdb_t *db, const char *mode)
{
	int oflags;

	if (mode[0] == 'w')
		oflags = O_RDWR;
	else
		oflags = O_RDONLY;

	if (db->path)
		rpmPushMacro(NULL, "_dbpath", NULL, db->path, -1);
	if (rpmtsOpenDB(db->ts, oflags) != 0) {
		log_error("failed to open rpmdb at %s", db->path);
		rpmPopMacro(NULL, "_dbpath");
		return false;
	}
	rpmPopMacro(NULL, "_dbpath");

	db->td_name = rpmtdNew();
	db->td_epoch = rpmtdNew();
	db->td_version = rpmtdNew();
	db->td_release = rpmtdNew();

	return true;
}

bool
pkgdb_create(pkgdb_t *db)
{
	const char *root = rpmtsRootDir(db->ts), *dbpath;

	trace("%s()", __func__);

	if (root != NULL && mkdir(root, 0755) < 0 && errno != EEXIST) {
		log_error("Cannot create directory %s: %m", root);
		return false;
	}

	dbpath = db->fullpath;
	if (mkdir(dbpath, 0755) < 0) {
		log_error("Cannot create package DB directory at %s: %m", dbpath);
		return false;
	}

	rpmPushMacro(NULL, "_rpmlock_path", NULL, "/.rpm.lock", -1);

	trace("Creating RPM database at %s", dbpath);
	if (db->path)
		rpmPushMacro(NULL, "_dbpath", NULL, db->path, -1);
	if (rpmtsInitDB(db->ts, 0755) != 0) {
		log_error("failed to init rpmdb at %s", db->path);
		rpmPopMacro(NULL, "_dbpath");
		return false;
	}
	rpmPopMacro(NULL, "_rpmlock_path");
	rpmPopMacro(NULL, "_dbpath");

	db->td_name = rpmtdNew();
	db->td_epoch = rpmtdNew();
	db->td_version = rpmtdNew();
	db->td_release = rpmtdNew();

	return true;
}

void
pkgdb_free(pkgdb_t *db)
{
	if (db->zap_on_close)
		pkgdb_zap(db);

	drop_string(&db->path);
	drop_string(&db->root);
	drop_string(&db->fullpath);

	if (db->ts) {
		rpmtsFree(db->ts);
		db->ts = NULL;
	}

	rpmtdFreeData(db->td_name);
	rpmtdFreeData(db->td_epoch);
	rpmtdFreeData(db->td_version);
	rpmtdFreeData(db->td_release);
}

static pkg_t *
pkg_new(const char *name, const char *epoch, const char *version, const char *release)
{
	char buffer[512];
	pkg_t *p;

	p = calloc(1, sizeof(*p));
	p->name = strdup(name);
	p->epoch = epoch? strdup(epoch) : NULL;
	p->version = strdup(version);
	p->release = strdup(release);

	if (p->epoch)
		snprintf(buffer, sizeof(buffer), "%s-%s:%s-%s",
				p->name,
				p->epoch,
				p->version,
				p->release);
	else
		snprintf(buffer, sizeof(buffer), "%s-%s-%s",
				p->name,
				p->version,
				p->release);
	p->NEVR = strdup(buffer);

	return p;
}

static pkg_t *
pkg_from_hdr(Header h)
{
	static rpmtd td_name, td_epoch, td_version, td_release;
	static bool initialized = false;
	pkg_t *p;

	if (!initialized) {
		td_name = rpmtdNew();
		td_epoch = rpmtdNew();
		td_version = rpmtdNew();
		td_release = rpmtdNew();
		initialized = true;
	}

	h = headerCopy(h);
	headerGet(h, RPMTAG_NAME,	td_name,	HEADERGET_EXT);
	headerGet(h, RPMTAG_EPOCH,	td_epoch,	HEADERGET_EXT);
	headerGet(h, RPMTAG_VERSION,	td_version,	HEADERGET_EXT);
	headerGet(h, RPMTAG_RELEASE,	td_release,	HEADERGET_EXT);

	p = pkg_new(
		rpmtdGetString(td_name),
		rpmtdGetString(td_epoch),
		rpmtdGetString(td_version),
		rpmtdGetString(td_release));

	p->h = h;
	return p;
}

int
pkg_compare(const pkg_t *pa, const pkg_t *pb, unsigned int *degree_p)
{
	unsigned int degree = 0;
	int res = 0;

	res = strcmp(pa->name, pb->name);

	if (res)
		goto out;
	degree += 1;

	if (pa->epoch || pb->epoch) {
		if (pa->epoch == NULL)
			res = 1;
		else if (pb->epoch == NULL)
			res = -1;
		else
			res = strcmp(pa->epoch, pb->epoch);
		if (res)
			goto out;
	}
	degree += 1;

	if ((res = strcmp(pa->version, pb->version)) != 0)
		goto out;
	degree += 1;

	if ((res = strcmp(pa->release, pb->release)) != 0)
		goto out;
	degree += 1;

out:
	if (degree_p)
		*degree_p = degree;

	return res;
}

pkg_t *
pkg_read(const char *path)
{
	FD_t rpmfd = NULL;
	Header h, sigh;
	pkg_t *pkg;
	unsigned char lead[RPMLEAD_SIZE];
	char *errmsg = NULL;

	if (!(rpmfd = Fopen(path, "r"))) {
		log_error("Unable to open %s: %m", path);
		return NULL;
	}

	if (Fread(lead, sizeof(lead), 1, rpmfd) != sizeof(lead)
	 || !rpmLeadOK(lead, sizeof(lead))) {
		log_error("unable to load %s: %s", path, errmsg);
		free(errmsg);
		goto failed;
	}

	sigh = headerRead(rpmfd, 1);

	unsigned int pad = (8 - (headerSizeof(sigh, 1) % 8)) % 8;
	if (pad)
		Fseek(rpmfd, pad, SEEK_CUR);

	h = headerRead(rpmfd, 1);
	Fclose(rpmfd);

	if (h == NULL) {
		log_error("Unable to load RPM header from %s", path);
		return NULL;
	}

	pkg = pkg_from_hdr(h);
	if (pkg)
		pkg->header_path = strdup(path);
	return pkg;

failed:
	if (rpmfd)
		Fclose(rpmfd);
	return false;
}

/*
 * Routines for writing the RPM meta info - the files we write are essentially RPMs#
 * with all the relevant headers, minus the payload, and minus any crypto signatures.
 * We do include SHA1 header digests, though.
 */
struct sigheader_state {
	char *		sha1;
	char *		sha256;
	uint8_t *	md5;

	off_t		sig_offset;
};

static void
sigheader_state_init(struct sigheader_state *sigs, Header h)
{
	unsigned int i;

	memset(sigs, 0, sizeof(*sigs));

	/* Strip everything useless out of the original header. */
	for (i = RPMTAG_SIG_BASE; i < RPMTAG_SIG_BASE + 32; ++i)
		headerDel(h, i);

	/* Don't know why we need to do this, but if we leave it in,
	 * rpm will whine. */
	headerDel(h, RPMTAG_ARCHIVESIZE);

	/* The rpm lib recomputes these and adds them to the header.
	 * If we don't remove the existing ones here, we end up with
	 * duplicate entries, and rpm -qV will complain */
	headerDel(h, RPMTAG_FILESTATES);
}

static void
sigheader_state_destroy(struct sigheader_state *sigs)
{
	drop_string(&sigs->sha1);
	drop_string(&sigs->sha256);
}

static inline bool
pkg_update_sigheader(struct sigheader_state *sigs, FD_t rpmfd)
{
	if (Fseek(rpmfd, sigs->sig_offset, SEEK_SET) < 0) {
		log_error("Fseek: %m");
		return false;
	}

	if (rpmGenerateSignature(sigs->sha256, sigs->sha1, sigs->md5, 0, 0, rpmfd))
		return false;

	return true;
}

static bool
pkg_write_sigheader0(struct sigheader_state *sigs, FD_t rpmfd)
{
	set_string(&sigs->sha1, "0000000000000000000000000000000000000000");

	sigs->sig_offset = Ftell(rpmfd);
	if (!pkg_update_sigheader(sigs, rpmfd))
		return false;

	fdInitDigest(rpmfd, PGPHASHALGO_SHA1, 0);

	return true;
}

static bool
pkg_write_sigheader1(struct sigheader_state *sigs, FD_t rpmfd)
{
	char *sha1 = NULL;

	fdFiniDigest(rpmfd, PGPHASHALGO_SHA1, (void **) &sha1, NULL, 1);
	if (sha1 == NULL) {
		log_error("Could not get SHA1 header digest");
		return false;
	}
	set_string(&sigs->sha1, sha1);

	return pkg_update_sigheader(sigs, rpmfd);
}

static inline bool
pkg_write_lead(Header h, FD_t rpmfd)
{
	unsigned char lead_buf[128];
	int lead_len;

	if ((lead_len = rpmLeadBuild(h, lead_buf, sizeof(lead_buf))) < 0) {
		log_error("failed to build package header");
		return false;
	}

	if (Fwrite(lead_buf, lead_len, 1, rpmfd) < 0)
		return false;

	return true;
}

bool
pkg_write(pkg_t *p, const char * path)
{
	Header h = NULL;
	struct sigheader_state sigs;
	FD_t rpmfd = NULL;
	bool okay = false;

	h = headerCopy(p->h);

	sigheader_state_init(&sigs, h);

	h = headerReload(h, RPMTAG_HEADERIMMUTABLE);

	if (!(rpmfd = Fopen(path, "w"))) {
		log_error("%s: %m", path);
		goto out;
	}

	if (!pkg_write_lead(h, rpmfd))
		goto failed;

	if (!pkg_write_sigheader0(&sigs, rpmfd))
		goto failed;

	if (headerWrite(rpmfd, h, 1) != RPMRC_OK)
		goto failed;

	if (!pkg_write_sigheader1(&sigs, rpmfd))
		goto failed;

	okay = true;

out:
	if (h)
		headerFree(h);

	if (rpmfd)
		Fclose(rpmfd);
	sigheader_state_destroy(&sigs);
	return okay;

failed:
	log_error("%s: failed to write header", path);
	goto out;
}

void
pkg_free(pkg_t *p)
{
	drop_string(&p->name);
	drop_string(&p->epoch);
	drop_string(&p->version);
	drop_string(&p->release);
	drop_string(&p->NEVR);
	drop_string(&p->header_path);
	if (p->h) {
		headerFree(p->h);
		p->h = NULL;
	}

	free(p);
}

static void
pkgdb_add_pkg(pkgdb_t *db, pkg_t *p)
{
	pkgarray_add(&db->pkgs, p);
}

static void
pkgdb_add_from_hdr(pkgdb_t *db, Header h)
{
	pkg_t *p;

	h = headerLink(h);
	headerGet(h, RPMTAG_NAME,	db->td_name,	HEADERGET_EXT);
	headerGet(h, RPMTAG_EPOCH,	db->td_epoch,	HEADERGET_EXT);
	headerGet(h, RPMTAG_VERSION,	db->td_version,	HEADERGET_EXT);
	headerGet(h, RPMTAG_RELEASE,	db->td_release,	HEADERGET_EXT);

	p = pkg_new(
		rpmtdGetString(db->td_name),
		rpmtdGetString(db->td_epoch),
		rpmtdGetString(db->td_version),
		rpmtdGetString(db->td_release));

	p->h = h;

	trace2("%s-%s-%s", p->name, p->version, p->release);

	pkgdb_add_pkg(db, p);
}

static int
__pkg_compare(const void *a, const void *b)
{
	const pkg_t *pa = *(const pkg_t **) a;
	const pkg_t *pb = *(const pkg_t **) b;

	return pkg_compare(pa, pb, NULL);
#if 0
	int res = 0;

	res = strcmp(pa->name, pb->name);
	if (res == 0 && (pa->epoch || pb->epoch)) {
		if (pa->epoch == NULL)
			return 1;
		if (pb->epoch == NULL)
			return -1;
		res = strcmp(pa->epoch, pb->epoch);
	}
	if (res == 0)
		res = strcmp(pa->version, pb->version);
	if (res == 0)
		res = strcmp(pa->release, pb->release);

	return res;
#endif
}

bool
pkgdb_read(pkgdb_t *db)
{
	rpmdbMatchIterator mi;
	Header h;

	if (!pkgdb_open(db, "r"))
		return false;

	mi = rpmtsInitIterator(db->ts, RPMDBI_PACKAGES, NULL, 0);
	if (mi == NULL) {
		log_error("Cannot iterate over %s", db->path);
		return false;
	}

	while ((h = rpmdbNextIterator(mi)) != NULL) {
		pkgdb_add_from_hdr(db, h);
	}
	rpmdbFreeIterator(mi);

	trace("%s: found %u packages", db->fullpath, db->pkgs.count);

	pkgarray_sort(&db->pkgs, __pkg_compare);

	return true;
}

static const char *
rpm_callback_name(unsigned int what)
{
	static char buf[16];

	switch (what) {
	case RPMCALLBACK_TRANS_START:
		return "trans-start";
	case RPMCALLBACK_TRANS_STOP:
		return "trans-stop";
	case RPMCALLBACK_TRANS_PROGRESS:
		return "trans-progress";
	case RPMCALLBACK_INST_START:
		return "inst-progress";
	case RPMCALLBACK_INST_PROGRESS:
		return "inst-progress";
	case RPMCALLBACK_INST_OPEN_FILE:
		return "inst-open-file";
	case RPMCALLBACK_INST_CLOSE_FILE:
		return "inst-close-file";
	case RPMCALLBACK_UNINST_PROGRESS:
		return "uninst-progress";
	case RPMCALLBACK_UNINST_START:
		return "uninst-start";
	case RPMCALLBACK_UNINST_STOP:
		return "uninst-stop";
	case RPMCALLBACK_UNPACK_ERROR:
		return "unpack-error";
	case RPMCALLBACK_CPIO_ERROR:
		return "cpio-error";
	case RPMCALLBACK_SCRIPT_ERROR:
		return "script-error";
	case RPMCALLBACK_SCRIPT_START:
		return "script-start";
	case RPMCALLBACK_SCRIPT_STOP:
		return "script-stop";
	case RPMCALLBACK_INST_STOP:
		return "inst-stop";
	case RPMCALLBACK_ELEM_PROGRESS:
		return "elem-progress";
	case RPMCALLBACK_VERIFY_PROGRESS:
		return "verify-progress";
	case RPMCALLBACK_VERIFY_START:
		return "verify-start";
	case RPMCALLBACK_VERIFY_STOP:
		return "verify-stop";
	default:
		break;
	}

	snprintf(buf, sizeof(buf), "0x%x", what);
	return buf;
}

static void *
__pkgdb_apply_notify(const void *h,
                const rpmCallbackType what,
                const rpm_loff_t amount,
                const rpm_loff_t total,
                fnpyKey key,
                rpmCallbackData data)
{
	pkg_t *p = (pkg_t *) key;
	dbdiff_t *diff = data;

	if (0)
	trace("%s(%p, %s, %u%%)", __func__, h, rpm_callback_name(what), total? (100 * amount / total) : 0);

	if (what == RPMCALLBACK_INST_OPEN_FILE) {
		diff->current_element = p;
		return dbdiff_open_file(diff, p);
	}
	if (what == RPMCALLBACK_INST_CLOSE_FILE) {
		if (diff->current_element == p) {
			diff->current_element = NULL;
			printf("%-20s %3u%%\n", p->name, 100);
		}
		dbdiff_close_file(diff, p);
	}
	if (what == RPMCALLBACK_ELEM_PROGRESS && p && diff->current_element == p) {
		printf("%-20s %3u%%\r", p->name, (int)(100 * amount / total));
		fflush(stdout);
	}

	return NULL;
}

enum {
	PKG_INSTALL = 0,
	PKG_UPGRADE,
	PKG_DOWNGRADE,
	PKG_ERASE,
};

static bool
pkgdb_add_transaction(pkgdb_t *db, rpmts ts, const pkgarray_t *array, int op)
{
	/* Order of verbs must match the values of PKG_* enum */
	static const char *verbs[] = {
		"install", "upgrade", "downgrade", "erase"
	};
	const char *op_verb;
	pkgiter_t iter;
	pkg_t *p;

	op_verb = verbs[op];

	pkgiter_init(&iter, array);
	while ((p = pkgiter_next(&iter)) != NULL) {
		pkg_t *to_erase;
		int rc;

		trace("Transaction: %s %s", op_verb, p->NEVR);
		switch (op) {
		case PKG_INSTALL:
			rc = rpmtsAddInstallElement(ts, p->h, (fnpyKey) p, 0, NULL);
			break;

		case PKG_UPGRADE:
		case PKG_DOWNGRADE:
			rc = rpmtsAddInstallElement(ts, p->h, (fnpyKey) p, 1, NULL);
			break;

		case PKG_ERASE:
			to_erase = pkgdb_find_best_match(db, p);
			if (to_erase == NULL) {
				log_info("erase %s: not installed; skipping", p->NEVR);
				continue;
			}
			rc = rpmtsAddEraseElement(ts, to_erase->h, 0);
			break;
		}
		
		if (rc != RPMRC_OK) {
			log_error("Could not add %s %s to transaction", op_verb, p->name);
			return false;
		}
	}

	return true;
}

bool
pkgdb_apply(pkgdb_t *db, dbdiff_t *diff)
{
	rpmts ts = NULL;
	int rc;
	bool okay = false;

	if (db->path)
		rpmPushMacro(NULL, "_dbpath", NULL, db->path, -1);

	ts = rpmtsCreate();
	if (db->root)
		rpmtsSetRootDir(ts, db->root);
	rpmtsSetVSFlags(db->ts, _RPMVSF_NOSIGNATURES);

	rpmtsSetFlags(ts, RPMTRANS_FLAG_JUSTDB
			| RPMTRANS_FLAG_NOSCRIPTS
			| RPMTRANS_FLAG_NOTRIGGERS
			| _noTransScripts
			| _noTransTriggers
			);
	rpmtsSetNotifyCallback(ts, __pkgdb_apply_notify, diff);

	if (!pkgdb_add_transaction(db, ts, &diff->added, PKG_INSTALL)
	 || !pkgdb_add_transaction(db, ts, &diff->upgraded, PKG_UPGRADE)
	 || !pkgdb_add_transaction(db, ts, &diff->downgraded, PKG_DOWNGRADE)
	 || !pkgdb_add_transaction(db, ts, &diff->removed, PKG_ERASE))
		goto out;

	rpmtsClean(ts);
	rpmtsOrder(ts);

	rc = rpmtsRun(ts, 0, RPMPROB_FILTER_IGNOREARCH | RPMPROB_FILTER_IGNOREOS | RPMPROB_FILTER_VERIFY);
	if (rc > 0) {
		rpmps ps;

		ps = rpmtsProblems(ts);
		log_error("Unable to apply patch due to the following problems");
		rpmpsPrint(stderr, ps);
		goto out;
	}
	if (rc) {
		log_error("rpmtsRun() = %d\n", rc);
		goto out;
	}

	trace("success");
	okay = true;

out:
	rpmPopMacro(NULL, "_dbpath");
	if (ts)
		rpmtsFree(ts);
	return okay;
}

static dbdiff_t *
rpmhack_diff(pkgdb_t *dba, pkgdb_t *dbb)
{
	pkgiter_t iter_a, iter_b;
	dbdiff_t *diff;
	pkg_t *pa = NULL, *pb = NULL;

	diff = dbdiff_new();
	pkgiter_init(&iter_a, &dba->pkgs);
	pkgiter_init(&iter_b, &dbb->pkgs);

	trace("About to diff");
	while (true) {
		int c;

		if (pa == NULL && (pa = pkgiter_next(&iter_a)) == NULL)
			break;

		if (pb == NULL && (pb = pkgiter_next(&iter_b)) == NULL)
			break;

		c = __pkg_compare(&pa, &pb);
		if (c == 0) {
			dbdiff_same(diff, pa);
			pa = pb = NULL;
		} else
		if (!strcmp(pa->name, pb->name)) {
			if (c < 0)
				dbdiff_upgraded(diff, pb);
			else
				dbdiff_downgraded(diff, pb);
			pa = pb = NULL;
		} else
		{
			if (c < 0) {
				dbdiff_removed(diff, pa);
				pa = NULL;
			} else
			if (c > 0) {
				dbdiff_added(diff, pb);
				pb = NULL;
			}
		}
	}

	while (pa) {
		dbdiff_removed(diff, pa);
		pa = pkgiter_next(&iter_a);
	}

	while (pb) {
		dbdiff_added(diff, pb);
		pb = pkgiter_next(&iter_b);
	}

	trace("Found %u same; %u removed; %u added",
			diff->same.count,
			diff->removed.count,
			diff->added.count);

	return diff;
}

struct option 	options[] = {
	{ "debug",	no_argument,		NULL,		'd' },
	{ "patch-path",	required_argument,	NULL,		'P' },
	{ "orig-root",	required_argument,	NULL,		'O' },
	{ "validate",	no_argument,		NULL,		'V' },
	{ NULL }
};

struct rpmhack_ctx {
	char *		opt_orig_root;
	char *		opt_diff_path;
	bool		validate;

	const char *	image_root;
};

static int
perform_diff(struct rpmhack_ctx *ctx)
{
	pkgdb_t *orig_pkgs, *new_pkgs;
	dbdiff_t *diff;
	int rc;

	orig_pkgs = pkgdb_new(ctx->opt_orig_root, NULL);
	new_pkgs = pkgdb_new(ctx->image_root, NULL);

	if (!pkgdb_read(orig_pkgs)
	 || !pkgdb_read(new_pkgs))
		return 1;

	diff = rpmhack_diff(orig_pkgs, new_pkgs);

	if (!dbdiff_write(diff, ctx->opt_diff_path))
		return 1;

	log_info("Wrote package DB diff to %s", ctx->opt_diff_path);
	DROP(diff, dbdiff_free);

	/* So far, so good */
	rc = 0;

	DROP(new_pkgs, pkgdb_free);

	if (ctx->validate) {
		new_pkgs = pkgdb_clone_tmp(orig_pkgs, ctx->image_root);

		log_info("Validating newly created DB patch");
		if (!(diff = dbdiff_read(ctx->opt_diff_path))
		 || !pkgdb_read(new_pkgs)
		 || !pkgdb_apply(new_pkgs, diff)) {
			log_error("The patch does not apply cleanly");
			rc = 1;
		} else {
			/* perform additional checks, like "rpm -V" on the installed packages? */
			log_info("The patch seems to apply cleanly");
		}

		DROP(new_pkgs, pkgdb_free);
		DROP(diff, dbdiff_free);
	}

	DROP(orig_pkgs, pkgdb_free);
	return rc;
}

static int
perform_patch(struct rpmhack_ctx *ctx)
{
	pkgdb_t *tgt_pkgs;
	dbdiff_t *diff;

	tgt_pkgs = pkgdb_new(ctx->image_root, DEFAULT_RPMDB_PATH);
	if (!pkgdb_read(tgt_pkgs))
		return 1;

	if (!(diff = dbdiff_read(ctx->opt_diff_path)))
		return 1;

	/* FIXME: optionally clone tgt_pkgs to a new location and patch that. */

	pkgdb_apply(tgt_pkgs, diff);
	pkgdb_free(tgt_pkgs);

	return 0;
}

int
main(int argc, char **argv)
{
	struct rpmhack_ctx ctx;
	const char *operation;
	int (*perform)(struct rpmhack_ctx *);
	int c;

	memset(&ctx, 0, sizeof(ctx));
	ctx.opt_orig_root = "/";

	(void) rpmReadConfigFiles(NULL, NULL);

	while ((c = getopt_long(argc, argv, "dO:P:V", options, NULL)) != -1) {
		switch (c) {
		case 'd':
			tracing_increment_level();
			break;

		case 'P':
			ctx.opt_diff_path = optarg;
			break;

		case 'O':
			ctx.opt_orig_root = optarg;
			break;

		case 'V':
			ctx.validate = true;
			break;

		default:
			log_error("Unsupported command line option");
			return 1;
		}
	}

	if (tracing_level > 3)
		rpmSetVerbosity(RPMLOG_DEBUG);

	if (optind >= argc) {
		log_error("Don't know what to do. Please specify a valid action");
		/* usage(); */
		return 1;
	}

	operation = argv[optind++];

	if (!strcmp(operation, "diff"))
		perform = perform_diff;
	else
	if (!strcmp(operation, "patch"))
		perform = perform_patch;
	else {
		log_error("Unsupported operation \"%s\"", operation);
		return 1;
	}

	if (optind >= argc) {
		log_error("Please specify the root directory of the image");
		/* usage(); */
		return 1;
	}

	ctx.image_root = argv[optind++];

	if (ctx.opt_diff_path == NULL) {
		ctx.opt_diff_path = malloc(PATH_MAX);
		snprintf(ctx.opt_diff_path, PATH_MAX, "%s%s.diff", ctx.image_root, DEFAULT_RPMDB_PATH);
	}

	return perform(&ctx);
}
