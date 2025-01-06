MAKE	= make
CC 		= gcc
LD 		= ld
RM		= rm

SUBDIRS = src

INSDIR  = $(PWD)/bin
export INSDIR

export KERNEL   = $(shell /bin/uname -r)


all:
	for i in $(SUBDIRS); do $(MAKE) -C $$i || exit 1; done

clean:
	for i in $(SUBDIRS); do $(MAKE) -C $$i clean || exit 1; done

install:all
	-mkdir -p $(INSDIR)
	for i in $(SUBDIRS); do $(MAKE) -C $$i install || exit 1; done

uninstall:
	-$(RM) -f $(TARGET) $(INSDIR)/*
