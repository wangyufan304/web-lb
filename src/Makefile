TARGET := wlb


CFLAGS += -g -O0
LDFLAGS += -g

ifneq ("$(wildcard VERSION)","")
    VERSION_STRING := $(shell ./VERSION)
else
    VERSION_STRING := $(shell git describe --tags --always)
endif

DATE_STRING := $(shell date +%Y.%m.%d.%H:%M:%S)

# same path of THIS Makefile
SRCDIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

# Addtional libs below are needed when using dynamic link.
LIBS += -lpthread -lnuma -lrt -lm -ldl -lcrypto

ifeq ($(shell pkg-config --exists libssl && echo 0),0)
CFLAGS += $(shell pkg-config --cflags libssl)
LIBS += $(shell pkg-config --static --libs libssl)
endif

include $(SRCDIR)/dpdk.mk

INCDIRS += -I $(SRCDIR)/../include

# for dpvs main program.
CFLAGS += -D __DPVS__ -DDPVS_VERSION=\"$(VERSION_STRING)\" -DDPVS_BUILD_DATE=\"$(DATE_STRING)\"

CFLAGS += -Wall  -Wstrict-prototypes -Wmissing-prototypes -mcmodel=medium 
# -Werror
ifeq ($(shell test $(GCC_VERSION) -ge 70 && echo 1), 1)
	CFLAGS += -Wno-format-truncation
	CFLAGS += -Wno-stringop-truncation
	CFLAGS += -Wno-address-of-packed-member
	CFLAGS += -Wstringop-overflow=0
endif

ifneq ($(CONFIG_DEBUG), y)
	CFLAGS += -O3
else
	CFLAGS += -g -O0 -D DEBUG
	CFLAGS += -rdynamic
endif


CFLAGS += $(INCDIRS)

OBJS := $(shell find $(SRCDIR) -name '*.c' | sort)
OBJS := $(patsubst %.c,%.o,$(OBJS))

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "  $(notdir $@)"
	$(Q)$(CC) $(CFLAGS) $^ $(LIBS) -o $@

%.o: %.c
	@echo "  $(notdir $@)"
	$(Q)$(CC) -c $(CFLAGS) $< -o $@

clean:
	find $(SRCDIR) -name '*.o' | xargs rm -f
	rm -f ./$(TARGET)

install:
	install -m 744 $(TARGET) $(INSDIR)

