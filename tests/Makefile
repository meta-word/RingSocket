# SPDX-License-Identifier: MIT
# Copyright © 2021 MetaWord Inc
# Copyright © 2019-2021 William Budd

PRELOAD_NAME = rst_preload_sham_io
PRELOAD_SRC = $(PRELOAD_NAME).c
PRELOAD_SONAME = $(PRELOAD_NAME).so

CLIENT_ECHO_NAME = rst_client_echo
CLIENT_ECHO_SRC = $(CLIENT_ECHO_NAME).c
CLIENT_ECHO_LIBS = -ljgrandson

APP_ECHO_NAME = rst_app_echo
APP_ECHO_SRC = $(APP_ECHO_NAME).c
APP_ECHO_SONAME = $(APP_ECHO_NAME).so

APP_STRESS_NAME = rst_app_stress
APP_STRESS_SRC = $(APP_STRESS_NAME).c
APP_STRESS_SONAME = $(APP_STRESS_NAME).so

RS_CACHE_LINE_SIZE := $(shell getconf LEVEL1_DCACHE_LINESIZE)

CC = gcc
FLAGS = -Wall -Wextra -Wpedantic -std=c17 -O3
FLAGS_SO = -fpic -shared -Wl,-z,relro,-z,now -DRS_CACHE_LINE_SIZE=$(RS_CACHE_LINE_SIZE)

.PHONY: all
all: preload client_echo app_echo app_stress

.PHONY: preload
preload: $(PRELOAD_SONAME)

$(PRELOAD_SONAME):
	$(CC) $(FLAGS) $(FLAGS_SO) -o $(PRELOAD_SONAME) $(PRELOAD_SRC)

.PHONY: client_echo
client_echo: $(CLIENT_ECHO_NAME)

$(CLIENT_ECHO_NAME):
	$(CC) $(FLAGS) -o $(CLIENT_ECHO_NAME) $(CLIENT_ECHO_SRC) $(CLIENT_ECHO_LIBS)

.PHONY: app_echo
app_echo: $(APP_ECHO_SONAME)

$(APP_ECHO_SONAME):
	$(CC) $(FLAGS) $(FLAGS_SO) -o $(APP_ECHO_SONAME) $(APP_ECHO_SRC)

.PHONY: app_stress
app_stress: $(APP_STRESS_SONAME)

$(APP_STRESS_SONAME):
	$(CC) $(FLAGS) $(FLAGS_SO) -o $(APP_STRESS_SONAME) $(APP_STRESS_SRC)

.PHONY: clean
clean:
	rm -rf $(CLIENT_ECHO_NAME) $(PRELOAD_SONAME) $(APP_ECHO_SONAME) $(APP_STRESS_SONAME)
