CXX      = c++
STD      = -std=c++20
OPT      = -O3 -fno-omit-frame-pointer -g

BOTAN_CFLAGS = $(shell pkg-config --cflags botan-3)
BOTAN_LIBS   = $(shell pkg-config --libs botan-3)

BENCH_DIR    = vendor/benchmark
BENCH_CFLAGS = -I$(BENCH_DIR)/include
BENCH_LIBS   = $(BENCH_DIR)/build/src/libbenchmark.a \
               $(BENCH_DIR)/build/src/libbenchmark_main.a

CXXFLAGS = $(STD) $(OPT) $(BOTAN_CFLAGS) $(BENCH_CFLAGS)
LDFLAGS  = $(BOTAN_LIBS) $(BENCH_LIBS) -lpthread

# -----------------------------------------------------------------------
# Targets
# -----------------------------------------------------------------------

.PHONY: all bench_aes run-aesni run-ssse3 run-bitsliced run-compare run-all clean

all: bench_aes main

# Compile my-aes.cpp as a library unit (no main, exports BitslicedDirect wrappers)
my-aes-bench.o: my-aes.cpp
	$(CXX) $(STD) $(OPT) -DBENCH_DIRECT -c $< -o $@

# Compile my-aes-ni.cpp with AES-NI intrinsics enabled
my-aes-ni.o: my-aes-ni.cpp
	$(CXX) $(STD) $(OPT) -maes -msse4.1 -c $< -o $@

bench_aes: bench_aes.cpp my-aes-bench.o my-aes-ni.o
	$(CXX) $(CXXFLAGS) bench_aes.cpp my-aes-bench.o my-aes-ni.o -o $@ $(LDFLAGS)

main: my-aes.cpp
	$(CXX) $(STD) $(OPT) $< -o $@

# -----------------------------------------------------------------------
# Benchmark runs — each selects a different backend
# -----------------------------------------------------------------------

BENCH_FLAGS = --benchmark_time_unit=ns --benchmark_counters_tabular=true

run-aesni: bench_aes
	@echo "========================================================"
	@echo "  Backend: AES-NI (hardware)"
	@echo "========================================================"
	./bench_aes $(BENCH_FLAGS)

run-ssse3: bench_aes
	@echo "========================================================"
	@echo "  Backend: SSSE3 VPERM  (BOTAN_CLEAR_CPUID=aes_ni)"
	@echo "========================================================"
	BOTAN_CLEAR_CPUID=aes_ni ./bench_aes $(BENCH_FLAGS)

run-bitsliced: bench_aes
	@echo "========================================================"
	@echo "  Backend: Bitsliced  (BOTAN_CLEAR_CPUID=aes_ni,ssse3)"
	@echo "========================================================"
	BOTAN_CLEAR_CPUID=aes_ni,ssse3 ./bench_aes $(BENCH_FLAGS)

run-compare: bench_aes
	@echo "========================================================"
	@echo "  Botan bitsliced vs my-aes.cpp (оба — base бэкенд)"
	@echo "========================================================"
	BOTAN_CLEAR_CPUID=aes_ni,ssse3 ./bench_aes $(BENCH_FLAGS)

run-all: bench_aes
	@echo ""
	@$(MAKE) --no-print-directory run-aesni
	@echo ""
	@$(MAKE) --no-print-directory run-ssse3
	@echo ""
	@$(MAKE) --no-print-directory run-bitsliced

clean:
	rm -f bench_aes main my-aes-bench.o my-aes-ni.o
