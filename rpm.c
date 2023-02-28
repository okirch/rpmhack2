
#include <netinet/in.h>

#include <rpm/header.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmpgp.h>
#include "rpmhack.h"
#include "tracing.h"

/* A long time ago in a galaxy far far away, signatures were not in a header */
static unsigned char const lead_magic[] = {
	0xed, 0xab, 0xee, 0xdb
};

struct rpmlead_s {
	unsigned char	magic[4];
	unsigned char	major;
	unsigned char	minor;
	short		type;
	short		archnum;
	char		name[66];
	short		osnum;
	short		signature_type;
	char		reserved[16];
};

int
rpmLeadBuild(Header h, unsigned char *buf, size_t size)
{
        char *nevr;
	struct rpmlead_s lead;
	int archnum, osnum;

	if (size < sizeof(lead))
		return -1;

	memset(&lead, 0, sizeof(lead));
	memset(buf, 0, size);

        rpmGetArchInfo(NULL, &archnum);
        rpmGetOsInfo(NULL, &osnum);

        lead.major = 3;
        lead.minor = 0;
        lead.archnum = htons(archnum);
        lead.osnum = htons(osnum);
        lead.signature_type = htons(5);
        lead.type = htons((headerIsSource(h) ? 1 : 0));

        memcpy(lead.magic, lead_magic, sizeof(lead.magic));

	nevr = headerGetAsString(h, RPMTAG_NEVR);
        rstrlcpy(lead.name, nevr, sizeof(lead.name));
        free(nevr);

	memcpy(buf, &lead, sizeof(lead));
	return RPMLEAD_SIZE;
}

bool
rpmLeadOK(const unsigned char *buf, size_t size)
{
	struct rpmlead_s lead;

	if (size != RPMLEAD_SIZE)
		return false;

	memcpy(&lead, buf, size);
        lead.archnum = ntohs(lead.archnum);
        lead.osnum = ntohs(lead.osnum);
        lead.signature_type = ntohs(lead.signature_type);
        lead.type = ntohs(lead.type);


	if (memcmp(lead.magic, lead_magic, sizeof(lead_magic))) {
		log_error("doesn't look like an rpm");
		return false;
	}

	if (lead.signature_type != 5) {
		log_error("unexpected rpm signature type");
		return false;
	}

	if (lead.major < 3 || lead.major > 4) {
		log_error("rpm package version %u.%u not supported", lead.major, lead.minor);
		return false;
	}
	return true;
}
