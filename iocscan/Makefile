CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wpedantic -Iinclude
LDFLAGS  ?= -pthread

LIB_SRC := src/sha256.cpp src/scanner.cpp
BUILD   := build

all: $(BUILD)/iocscan

$(BUILD)/iocscan: src/main.cpp $(LIB_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/test_runner: tests/test_main.cpp $(LIB_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

test: $(BUILD)/test_runner
	./$(BUILD)/test_runner

# Same tests under AddressSanitizer + UBSan: catches memory errors and undefined behaviour
sanitize: tests/test_main.cpp $(LIB_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) -O1 -g -fsanitize=address,undefined $^ -o $(BUILD)/test_asan $(LDFLAGS)
	./$(BUILD)/test_asan

# ThreadSanitizer: verifies the worker pool has no data races
tsan: tests/test_main.cpp $(LIB_SRC) | $(BUILD)
	$(CXX) $(CXXFLAGS) -O1 -g -fsanitize=thread $^ -o $(BUILD)/test_tsan $(LDFLAGS)
	./$(BUILD)/test_tsan

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)

.PHONY: all test sanitize tsan clean
