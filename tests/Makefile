# SPDX-License-Identifier: MIT
# Copyright © 2019 William Budd

SHAM_NAME = rs_sham_io
SHAM_SRC = $(SHAM_NAME).c
SHAM_SONAME = $(SHAM_NAME).so

APP_NAME = rs_test_app_traffic
APP_SRC = $(APP_NAME).c
APP_SONAME = $(APP_NAME).so

CC = gcc
FLAGS = -Wall -Wextra -Wpedantic -std=c11 -O3 -fpic -shared -Wl,-z,relro,-z,now

.PHONY: all
all: sham app

.PHONY: sham
sham: $(SHAM_SONAME)

$(SHAM_SONAME):
	$(CC) $(FLAGS) -o $(SHAM_SONAME) $(SHAM_SRC)

.PHONY: app
app: $(APP_SONAME)

$(APP_SONAME):
	$(CC) $(FLAGS) -o $(APP_SONAME) $(APP_SRC)


.PHONY: clean
clean:
	rm -rf $(SHAM_SONAME) $(APP_SONAME)
