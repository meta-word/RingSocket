# SPDX-License-Identifier: MIT
# Copyright © 2019 William Budd

NAME = ringsocket
NAME_PREFIX = rs_
SYSTEM_HEADERS = ringsocket*.h

BIN_DIR = /usr/bin
INCLUDE_DIR = /usr/include

RS_CACHELINE_SIZE := $(shell getconf LEVEL1_DCACHE_LINESIZE)
ifeq ($(RS_CACHELINE_SIZE), 0)
	RS_CACHELINE_SIZE = 64
endif

CC = gcc
CFLAGS = -Wall -Wextra -Wpedantic -Wshadow -std=c11 -isystem src \
	-DRS_CACHELINE_SIZE=$(RS_CACHELINE_SIZE)
CFLAGS_OPTIM = -O3 -flto -fuse-linker-plugin
LFLAGS_OPTIM = -flto -fuse-linker-plugin -fuse-ld=gold
LFLAGS_LIB = -lcap -lckv -lcrypto -ldl -lssl -pthread

SRC_DIR = src
SRC_PATHS := $(wildcard $(SRC_DIR)/$(NAME_PREFIX)*.c)
SRC_NAMES = $(SRC_PATHS:$(SRC_DIR)/%=%)

OBJ_DIR = .objects
OBJ_NAMES = $(SRC_NAMES:.c=.o)
OBJ_PATHS = $(addprefix $(OBJ_DIR)/, $(OBJ_NAMES))

.PHONY: optimized
optimized: $(NAME)

$(NAME): $(OBJ_PATHS)
	$(CC) $(LFLAGS_OPTIM) $(LFLAGS_LIB) $(OBJ_PATHS) -o $(NAME)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) $(CFLAGS_OPTIM) -c $< -o $@

$(OBJ_DIR):
	mkdir $(OBJ_DIR)

.PHONY: clean
clean:
	rm -rf $(NAME) $(OBJ_DIR)

.PHONY: install
install:
	cp $(NAME) $(BIN_DIR)/ && \
		cp $(SRC_DIR)/$(SYSTEM_HEADERS) $(INCLUDE_DIR)/ && \
		(useradd --system --shell $(BIN_DIR)/false ringsocket || true)
