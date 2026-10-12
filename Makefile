.PHONY: all build clean test asan

BUILD_DIR ?= build

all: build

build:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake .. && cmake --build . -j

asan:
	mkdir -p $(BUILD_DIR)_asan
	cd $(BUILD_DIR)_asan && cmake -DKVM_ENABLE_ASAN=ON .. && cmake --build . -j

test: build
	ctest --test-dir $(BUILD_DIR) --output-on-failure

clean:
	rm -rf build build_asan
