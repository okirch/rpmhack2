BINDIR		= /usr/bin
SBINDIR		= /usr/sbin

COPT		= -g
CFLAGS		= -Wall -D_GNU_SOURCE $(COPT)
RPMHACK		= rpmhack
RPMHACK_SRCS	= rpmhack.c \
		  rpm.c \
		  tracing.c
RPMHACK_OBJS	= $(RPMHACK_SRCS:.c=.o)
LINK		= -lrpm -lrpmio

all: $(RPMHACK)

clean:
	rm -f $(RPMHACK)
	rm -f *.o *.a

install: $(RPMHACK)
	@case "$(DESTDIR)" in \
	""|/*) ;; \
	*) echo "DESTDIR is a relative path, no workie" >&2; exit 2;; \
	esac
	install -m 755 -d $(DESTDIR)$(BINDIR)
	install -m 555 $(RPMHACK) $(DESTDIR)$(BINDIR)

$(RPMHACK): $(RPMHACK_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $@ $(RPMHACK_OBJS) $(LINK)

ifeq ($(wildcard .depend), .depend)
include .depend
endif

depend:
	gcc $(CFLAGS) -MM *.c >.depend
