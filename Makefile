#
# Makefile
#
# Copyright (C) 2010 Creytiv.com
#

PROJECT	  := reicec
VERSION   := 0.4.1

LIBRE_MK  := $(shell [ -f ../re/mk/re.mk ] && \
	echo "../re/mk/re.mk")
ifeq ($(LIBRE_MK),)
LIBRE_MK  := $(shell [ -f /usr/share/re/re.mk ] && \
	echo "/usr/share/re/re.mk")
endif
ifeq ($(LIBRE_MK),)
LIBRE_MK  := $(shell [ -f /usr/local/share/re/re.mk ] && \
	echo "/usr/local/share/re/re.mk")
endif

include $(LIBRE_MK)

INSTALL := install
ifeq ($(DESTDIR),)
PREFIX  := /usr/local
else
PREFIX  := /usr
endif
BINDIR	:= $(PREFIX)/bin
CFLAGS	+= -I$(LIBRE_INC) -Iinclude
CFLAGS	+= -I$(SYSROOT)/local/include/rew
LIBS	+= -lrew
BIN	:= $(PROJECT)$(BIN_SUFFIX)
APP_MK	:= src/srcs.mk

include $(APP_MK)

OBJS	?= $(patsubst %.c,$(BUILD)/src/%.o,$(SRCS))

all: $(BIN)

-include $(OBJS:.o=.d)

$(BIN): $(OBJS)
	@echo "  LD      $@"
	@$(LD) $(LFLAGS) $^ -L$(LIBRE_SO) -lre $(LIBS) -o $@

$(BUILD)/%.o: %.c $(BUILD) Makefile $(APP_MK)
	@echo "  CC      $@"
	@$(CC) $(CFLAGS) -o $@ -c $< $(DFLAGS)

$(BUILD): Makefile
	@mkdir -p $(BUILD)/src
	@touch $@

clean:
	@rm -rf $(BIN) $(BUILD)

install: $(BIN)
	@mkdir -p $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 $(BIN) $(DESTDIR)$(BINDIR)
