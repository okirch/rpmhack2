

#ifndef RPMHACK_H
#define RPMHACK_H

#include <stdbool.h>

#define RPMLEAD_SIZE	96

extern int	rpmLeadBuild(Header h, unsigned char *buf, size_t size);
extern bool	rpmLeadOK(const unsigned char *buf, size_t size);

extern rpmRC	rpmLeadRead(FD_t fd, char **emsg);
extern rpmRC	rpmGenerateSignature(char *SHA256, char *SHA1, uint8_t *MD5,
                        rpm_loff_t size, rpm_loff_t payloadSize, FD_t fd);


#endif /* RPMHACK_H */
