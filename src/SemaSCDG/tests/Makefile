# Makefile for compiling tests

# TODO sudo apt-get install gcc-multilib if 32 bits problems

# Set the directories
SRC_DIR := binaries
BUILD_DIR := compiled_binaries

# Find all source files in the source directory
SRCS := $(wildcard $(SRC_DIR)/*/*.c)

# Generate the corresponding binary file names in the build directory
BINS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%,$(SRCS))

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -g -m32 -static -O0 

# Target: build all tests
all: $(BUILD_DIR) $(BINS)

# Rule to build binary files from source files
$(BUILD_DIR)/%: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@

# Create the build directory if it doesn't exist
$(BUILD_DIR):
	mkdir -p $(dir $(BINS))

# Target: clean
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
