
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>

#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmmacro.h>
#include <rpm/rpmdb.h>
#include <rpm/header.h>
#include <rpm/rpmlog.h>

#include "rpmhack.h"
#include "tracing.h"

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

	struct pkgdb_open_file *fdcache;
} dbdiff_t;



extern void		pkg_free(pkg_t *p);
extern pkg_t *		pkg_read(const char *path);
extern bool		pkg_write(pkg_t *p, const char * path);

pkgdb_t *
pkgdb_new(const char *root, const char *path)
{
	int vsflags = _RPMVSF_NOSIGNATURES|_RPMVSF_NODIGESTS;
	pkgdb_t *db;

	db = calloc(1, sizeof(*db));
	db->path = path? strdup(path) : NULL;

	db->ts = rpmtsCreate();

	if (root)
		rpmtsSetRootDir(db->ts, root);

	rpmtsSetVSFlags(db->ts, vsflags);

	return db;
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
packagedb_open(pkgdb_t *db, const char *mode)
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
packagedb_create(pkgdb_t *db)
{
	const char *root = rpmtsRootDir(db->ts), *dbpath;
	char fullpath[PATH_MAX];

	trace("%s()", __func__);
	if (root == NULL) {
		dbpath = db->path;
	} else {
		if (mkdir(root, 0755) < 0 && errno != EEXIST) {
			log_error("Cannot create directory %s: %m", root);
			return false;
		}
		snprintf(fullpath, sizeof(fullpath), "%s%s", root, db->path);
		dbpath = fullpath;
	}

	if (mkdir(dbpath, 0755) < 0) {
		log_error("Cannot create package DB directory at %s: %m", dbpath);
		return false;
	}

	rpmPushMacro(NULL, "_rpmlock_path", NULL, "/.rpm.lock", -1);

	trace("Creating RPM database at %s", fullpath);
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
packagedb_free(pkgdb_t *db)
{
	free(db->path);

	rpmtdFreeData(db->td_name);
	rpmtdFreeData(db->td_epoch);
	rpmtdFreeData(db->td_version);
	rpmtdFreeData(db->td_release);
}

bool
pkgdb_add_header(pkgdb_t *db, pkg_t *p)
{
	int rc;

	if (db->path)
		rpmPushMacro(NULL, "_dbpath", NULL, db->path, -1);

	rc = rpmtsAddInstallElement(db->ts, p->h, (fnpyKey) p, 0, NULL);
	rpmPopMacro(NULL, "_dbpath");

	if (rc != 0)
		trace("Could not add %s to rpm transaction", p->name);
	return true;
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

typedef struct entryInfo_s * entryInfo;
struct entryInfo_s {
    rpm_tag_t tag;              /*!< Tag identifier. */
    rpm_tagtype_t type;         /*!< Tag data type. */
    int32_t offset;             /*!< Offset into data segment (ondisk only). */
    rpm_count_t count;          /*!< Number of tag elements. */
};

typedef struct indexEntry_s * indexEntry;
struct indexEntry_s {
    struct entryInfo_s info;    /*!< Description of tag data. */
    rpm_data_t data;            /*!< Location of tag data. */
    int length;                 /*!< No. bytes of data. */
    int rdlen;                  /*!< No. bytes of data in region. */
};

struct H {
	void * blob;                /*!< Header region blob. */
	indexEntry index;           /*!< Array of tags. */
	int indexUsed;              /*!< Current size of tag array. */
	int indexAlloced;           /*!< Allocated size of tag array. */
	unsigned int instance;      /*!< Rpmdb instance (offset) */
	uint32_t flags;
	int sorted;                 /*!< Current sort method */
	int nrefs;
};

bool
pkg_write(pkg_t *p, const char * path)
{
	unsigned char lead_buf[128];
	Header h = NULL, sigh = NULL;
	int lead_len;
	FD_t rpmfd = NULL;
	bool okay = false;

	h = headerCopy(p->h);
	{
		unsigned int i;

		for (i = RPMTAG_SIG_BASE; i < RPMTAG_SIG_BASE + 32; ++i)
			headerDel(h, i);
		h = headerCopy(h);
	}

	sigh = headerNew();
	headerPutString(sigh, RPMTAG_SHA1HEADER, "0000000000000000000000000000000000000000");

	if (0) {
		struct H *hh = (struct H *) h;
		unsigned int i, count = hh->indexUsed;
		for (i = 0; i < count; ++i) {
			indexEntry e = hh->index + i;
			entryInfo ei = &(e->info);

			trace("tag %5u type %u", ei->tag, ei->type);
		}
		trace("found %u tags total", hh->indexUsed);
	}

	if ((lead_len = rpmLeadBuild(h, lead_buf, sizeof(lead_buf))) < 0) {
		log_error("%s: failed to build package header", path);
		return false;
	}

	if (!(rpmfd = Fopen(path, "w"))) {
		log_error("%s: %m", path);
		goto out;
	}

	if (Fwrite(lead_buf, lead_len, 1, rpmfd) < 0)
		goto failed;

	if (headerWrite(rpmfd, sigh, 1))
		goto failed;

	unsigned int pad = (8 - (headerSizeof(sigh, 1) % 8)) % 8;
	if (pad) {
		static unsigned char zeros[8];

		if (Fwrite(zeros, sizeof(zeros[0]), pad, rpmfd) != pad)
			goto failed;
	}

	if (headerWrite(rpmfd, h, 1))
		goto failed;

	okay = true;

out:
	if (h)
		headerFree(h);
	if (sigh)
		headerFree(sigh);

	if (rpmfd)
		Fclose(rpmfd);
	return okay;

failed:
	log_error("%s: failed to write header", path);
	goto out;
}

void
pkg_free(pkg_t *p)
{
	/* TBD */
}

static void
packagedb_add_pkg(pkgdb_t *db, pkg_t *p)
{
	pkgarray_add(&db->pkgs, p);
}

static void
packagedb_add_from_hdr(pkgdb_t *db, Header h)
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

	packagedb_add_pkg(db, p);
}

static int
__pkg_compare(const void *a, const void *b)
{
	const pkg_t *pa = *(const pkg_t **) a;
	const pkg_t *pb = *(const pkg_t **) b;
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
}

bool
packagedb_read(pkgdb_t *db)
{
	rpmdbMatchIterator mi;
	Header h;

	if (!packagedb_open(db, "r"))
		return false;

	mi = rpmtsInitIterator(db->ts, RPMDBI_PACKAGES, NULL, 0);
	if (mi == NULL) {
		log_error("Cannot iterate over %s", db->path);
		return false;
	}

	while ((h = rpmdbNextIterator(mi)) != NULL) {
		packagedb_add_from_hdr(db, h);
	}
	rpmdbFreeIterator(mi);

	trace("%s: found %u packages", db->path, db->pkgs.count);

	pkgarray_sort(&db->pkgs, __pkg_compare);

	return true;
}

static void *
__packagedb_apply_notify(const void *h,
                const rpmCallbackType what,
                const rpm_loff_t amount,
                const rpm_loff_t total,
                fnpyKey key,
                rpmCallbackData data)
{
	pkg_t *p = (pkg_t *) key;
	dbdiff_t *diff = data;
	const char *desc = NULL;

	switch (what) {
	case RPMCALLBACK_TRANS_START:
		desc = "trans-start"; break;
	case RPMCALLBACK_TRANS_STOP:
		desc = "trans-stop"; break;
	case RPMCALLBACK_TRANS_PROGRESS:
		desc = "trans-progress"; break;
	case RPMCALLBACK_INST_START:
		desc = "inst-progress"; break;
	case RPMCALLBACK_INST_PROGRESS:
		desc = "inst-progress"; break;
	case RPMCALLBACK_INST_OPEN_FILE:
		desc = "inst-open-file"; break;
	case RPMCALLBACK_INST_CLOSE_FILE:
		desc = "inst-close-file"; break;
	default:
		break;
	}

	if (0) {
		if (desc == NULL)
			trace("%s(%p, what=%u)", __func__, h, what);
		else
			trace("%s(%p, %s)", __func__, h, desc);
	}

	if (what == RPMCALLBACK_INST_OPEN_FILE)
		return dbdiff_open_file(diff, p);
	if (what == RPMCALLBACK_INST_CLOSE_FILE)
		dbdiff_close_file(diff, p);

	return NULL;
}


bool
packagedb_apply(pkgdb_t *db, dbdiff_t *diff)
{
	pkgiter_t iter;
	pkg_t *p;

	rpmtsSetFlags(db->ts, RPMTRANS_FLAG_JUSTDB
			| RPMTRANS_FLAG_NOSCRIPTS
			| RPMTRANS_FLAG_NOTRIGGERS
			| RPMTRANS_FLAG_TEST
			| _noTransScripts
			| _noTransTriggers
			);
	rpmtsSetNotifyCallback(db->ts, __packagedb_apply_notify, diff);

	pkgiter_init(&iter, &diff->added);
	while ((p = pkgiter_next(&iter)) != NULL) {
		trace("Trying to apply %s", p->name);
		if (!pkgdb_add_header(db, p))
			return false;
	}

	if (db->path)
		rpmPushMacro(NULL, "_dbpath", NULL, db->path, -1);
	rpmtsClean(db->ts);
	{
		int rc;

		rc = rpmtsRun(db->ts, 0, RPMPROB_FILTER_IGNOREARCH | RPMPROB_FILTER_IGNOREOS | RPMPROB_FILTER_VERIFY);
		if (rc > 0) {
			rpmps ps;

			ps = rpmtsProblems(db->ts);
			log_error("Found problems");
			rpmpsPrint(stderr, ps);
			return false;
		}
		if (rc) {
			log_error("rpmtsRun() = %d\n", rc);
			return false;
		}
	}
	rpmPopMacro(NULL, "_dbpath");

	trace("success");
	return true;
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

int
main(int argc, char **argv)
{
	pkgdb_t *orig_pkgs, *new_pkgs;
	pkgdb_t *delta;
	const char *orig_root, *layer_root;
	char *opt_diff_path = NULL;
	dbdiff_t *diff;
	int optind = 1;

	tracing_set_level(1);

	if (argc - optind != 1) {
		log_error("bad number of args");
		return 1;
	}

	orig_root = "/";
	layer_root = argv[optind++];

	orig_pkgs = pkgdb_new(orig_root, "/usr/lib/sysimage/rpm");
	new_pkgs = pkgdb_new(layer_root, "/usr/lib/sysimage/rpm");

	if (opt_diff_path == NULL) {
		opt_diff_path = malloc(PATH_MAX);
		snprintf(opt_diff_path, PATH_MAX, "%s/usr/lib/sysimage/rpm.diff", layer_root);
	}

	(void) rpmReadConfigFiles(NULL, NULL);

#if 0
	if (!packagedb_create(delta))
		return 1;
#endif

	if (!packagedb_read(orig_pkgs)
	 || !packagedb_read(new_pkgs))
		return 1;

	diff = rpmhack_diff(orig_pkgs, new_pkgs);

	// packagedb_apply(delta, diff);
	if (!dbdiff_write(diff, opt_diff_path))
		return 1;

	dbdiff_free(diff);

	if (!(diff = dbdiff_read(opt_diff_path)))
		return 1;

	system("rm -rf /tmp/build-layer/image/usr/lib/sysimage/rpm.new");
	system("cp -a /usr/lib/sysimage/rpm /tmp/build-layer/image/usr/lib/sysimage/rpm.new");
	delta = pkgdb_new(layer_root, "/usr/lib/sysimage/rpm.new");

	rpmSetVerbosity(RPMLOG_DEBUG);
	packagedb_apply(delta, diff);

	return 0;
}
