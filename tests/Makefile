# SPDX-License-Identifier: MIT
# Copyright © 2019 William Budd

CLIENT_NAME = rs_test_client
CLIENT_SRC = $(CLIENT_NAME).c
CLIENT_LIBS = -ljgrandson

PRELOAD_NAME = rs_preload_sham_io
PRELOAD_SRC = $(PRELOAD_NAME).c
PRELOAD_SONAME = $(PRELOAD_NAME).so

APP_ECHO_NAME = rs_test_app_echo
APP_ECHO_SRC = $(APP_ECHO_NAME).c
APP_ECHO_SONAME = $(APP_ECHO_NAME).so

APP_STRESS_NAME = rs_test_app_stress
APP_STRESS_SRC = $(APP_STRESS_NAME).c
APP_STRESS_SONAME = $(APP_STRESS_NAME).so

RS_CACHE_LINE_SIZE := $(shell getconf LEVEL1_DCACHE_LINESIZE)

CC = gcc
FLAGS = -Wall -Wextra -Wpedantic -std=c11 -O3
FLAGS_SO = -fpic -shared -Wl,-z,relro,-z,now -DRS_CACHE_LINE_SIZE=$(RS_CACHE_LINE_SIZE)

.PHONY: all
all: client preload echo stress

.PHONY: client
client: $(CLIENT_NAME)

$(CLIENT_NAME):
	$(CC) $(FLAGS) $(CLIENT_LIBS) -o $(CLIENT_NAME) $(CLIENT_SRC)

.PHONY: preload
preload: $(PRELOAD_SONAME)

$(PRELOAD_SONAME):
	$(CC) $(FLAGS) $(FLAGS_SO) -o $(PRELOAD_SONAME) $(PRELOAD_SRC)

.PHONY: echo
echo: $(APP_ECHO_SONAME)

$(APP_ECHO_SONAME):
	$(CC) $(FLAGS) $(FLAGS_SO) -o $(APP_ECHO_SONAME) $(APP_ECHO_SRC)

.PHONY: stress
stress: $(APP_STRESS_SONAME)

$(APP_STRESS_SONAME):
	$(CC) $(FLAGS) $(FLAGS_SO) -o $(APP_STRESS_SONAME) $(APP_STRESS_SRC)

.PHONY: clean
clean:
	rm -rf $(CLIENT_NAME) $(PRELOAD_SONAME) $(APP_ECHO_SONAME) $(APP_STRESS_SONAME)
