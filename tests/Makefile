# SPDX-License-Identifier: MIT
# Copyright © 2019 William Budd

PRELOAD_NAME = rs_preload_sham_io
PRELOAD_SRC = $(PRELOAD_NAME).c
PRELOAD_SONAME = $(PRELOAD_NAME).so

APP_NAME = rs_test_app_stress
APP_SRC = $(APP_NAME).c
APP_SONAME = $(APP_NAME).so

RS_CACHE_LINE_SIZE := $(shell getconf LEVEL1_DCACHE_LINESIZE)

CC = gcc
FLAGS = -Wall -Wextra -Wpedantic -std=c11 -O3 -fpic -shared \
	-Wl,-z,relro,-z,now -DRS_CACHE_LINE_SIZE=$(RS_CACHE_LINE_SIZE)

.PHONY: all
all: preload app

.PHONY: preload
preload: $(PRELOAD_SONAME)

$(PRELOAD_SONAME):
	$(CC) $(FLAGS) -o $(PRELOAD_SONAME) $(PRELOAD_SRC)

.PHONY: app
app: $(APP_SONAME)

$(APP_SONAME):
	$(CC) $(FLAGS) -o $(APP_SONAME) $(APP_SRC)


.PHONY: clean
clean:
	rm -rf $(PRELOAD_SONAME) $(APP_SONAME)
