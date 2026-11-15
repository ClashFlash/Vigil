.PHONY: all debug release test clean run showcase test-features demo simulate diagrams

BUILD_DIR_DEBUG   := build/debug
BUILD_DIR_RELEASE := build/release
CORES             := $(shell nproc)

all: debug

debug:
	cmake -B $(BUILD_DIR_DEBUG)   -DCMAKE_BUILD_TYPE=Debug   -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
	cmake --build $(BUILD_DIR_DEBUG)   -j$(CORES)
	@echo "\n✓ Debug build: $(BUILD_DIR_DEBUG)/vigil"

release:
	cmake -B $(BUILD_DIR_RELEASE) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR_RELEASE) -j$(CORES)
	@echo "\n✓ Release build: $(BUILD_DIR_RELEASE)/vigil"

test: debug
	cd $(BUILD_DIR_DEBUG) && ctest --output-on-failure -j$(CORES)

showcase: release
	./$(BUILD_DIR_RELEASE)/tests/showcase_features

test-features: release
	./test_features.py

demo: release
	./simulate_events.py

simulate: demo

diagrams:
	python3 scripts/generate_diagrams.py

run: debug
	./$(BUILD_DIR_DEBUG)/vigil

clean:
	rm -rf build/
	@echo "✓ Cleaned build directories"
