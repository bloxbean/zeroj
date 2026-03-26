GNARK_VERSION := $(shell cat GNARK_VERSION | tr -d '[:space:]')
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Linux)
    LIB_EXT := so
    PLATFORM := linux
else ifeq ($(UNAME_S),Darwin)
    LIB_EXT := dylib
    PLATFORM := macos
else
    $(error Unsupported OS: $(UNAME_S))
endif

ifeq ($(UNAME_M),x86_64)
    ARCH := x86_64
else ifeq ($(UNAME_M),aarch64)
    ARCH := arm64
else ifeq ($(UNAME_M),arm64)
    ARCH := arm64
else
    $(error Unsupported architecture: $(UNAME_M))
endif

OUTPUT_DIR := ../src/main/resources/native/$(PLATFORM)-$(ARCH)
OUTPUT_LIB := $(OUTPUT_DIR)/libzeroj_gnark.$(LIB_EXT)

.PHONY: build clean version check-go

check-go:
	@which go > /dev/null 2>&1 || (echo "Error: Go is required. Install from https://golang.org/dl/" && exit 1)
	@echo "Go version: $$(go version)"

version:
	@echo "gnark version: $(GNARK_VERSION)"
	@echo "Platform: $(PLATFORM)-$(ARCH)"
	@echo "Output: $(OUTPUT_LIB)"

build: check-go
	@echo "Building zeroj-gnark wrapper with gnark $(GNARK_VERSION) for $(PLATFORM)-$(ARCH)..."
	@mkdir -p $(OUTPUT_DIR)
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(OUTPUT_LIB) .
	@echo "Built: $(OUTPUT_LIB)"
	@ls -la $(OUTPUT_LIB)

tidy:
	go mod tidy

clean:
	rm -f $(OUTPUT_LIB)
	rm -f $(OUTPUT_DIR)/libzeroj_gnark.h
