DESTDIR    =
PREFIX     = /usr/local
BINDIR     = $(PREFIX)/bin
export ASAN_OPTIONS=detect_leaks=0

CC ?= gcc
LD = $(CC)

ifeq ($(MODSEC_INC),)
#MODSEC_INC := ModSecurity-v3.0.5/INSTALL/usr/local/modsecurity/include
MODSEC_INC := /usr/local/modsecurity/include
endif

ifeq ($(MODSEC_LIB),)
#MODSEC_LIB := ModSecurity-v3.0.5/INSTALL/usr/local/modsecurity/lib
MODSEC_LIB := /usr/local/modsecurity/lib
endif

ifeq ($(LIBXML_INC),)
LIBXML_INC := /usr/include/libxml2
endif

ifeq ($(EVENT_LIB),)
EVENT_LIB := -levent
endif

ifeq ($(EVENT_INC),)
EVENT_INC := /usr/include
endif

#CFLAGS  += -Wall -Werror -pthread -O2 -g -fsanitize=address -fno-omit-frame-pointer
CFLAGS  += -Wall -Werror -pthread -O2 -g -fno-omit-frame-pointer
# For ASAN, change to clang, replace -O3 with -O0 -g and add -lasan to LIBS
# -fsanitize=address -fno-omit-frame-pointer
INCS += -Iinclude -I$(MODSEC_INC) -I$(LIBXML_INC) -I$(EVENT_INC)
LIBS += -lasan -lpthread  $(EVENT_LIB) -levent_pthreads

OBJS = spoa.o modsec_wrapper.o

modsecurity: $(OBJS)
	$(LD) $(LDFLAGS) -o $@ $^ $(LIBS) $(MODSEC_LIB)/libmodsecurity.so

install: modsecurity
	install modsecurity $(DESTDIR)$(BINDIR)

clean:
	rm -f modsecurity $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) $(INCS) -c -o $@ $<

all: modsecurity
