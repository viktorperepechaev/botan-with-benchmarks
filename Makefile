CXX      = c++
STD      = -std=c++20
OPT      = -O3

BOTAN_SRC = /Users/viktor/MIPT/spring2026/projects/botan
BOTAN_INC = $(BOTAN_SRC)/build/include/public
BOTAN_LIB = $(BOTAN_SRC)/libbotan-3.dylib

BENCH_INC = /opt/homebrew/Cellar/google-benchmark/1.9.5/include
BENCH_LIB = /opt/homebrew/Cellar/google-benchmark/1.9.5/lib/libbenchmark.a \
            /opt/homebrew/Cellar/google-benchmark/1.9.5/lib/libbenchmark_main.a

CXXFLAGS = $(STD) $(OPT) -I$(BOTAN_INC) -I$(BENCH_INC)
LDFLAGS  = $(BOTAN_LIB) $(BENCH_LIB) -lpthread

# -----------------------------------------------------------------------
# Targets
# -----------------------------------------------------------------------

.PHONY: all bench_aes run-armv8 run-vperm run-bitsliced run-compare run-all clean

all: bench_aes main

# Compile my-aes.cpp as a library unit (no main, exports BitslicedDirect wrappers)
my-aes-bench.o: my-aes.cpp
	$(CXX) $(STD) $(OPT) -DBENCH_DIRECT -c $< -o $@

bench_aes: bench_aes.cpp my-aes-bench.o
	$(CXX) $(CXXFLAGS) bench_aes.cpp my-aes-bench.o -o $@ $(LDFLAGS)

main: my-aes.cpp
	$(CXX) $(STD) $(OPT) $< -o $@

# -----------------------------------------------------------------------
# Benchmark runs — each selects a different backend
# -----------------------------------------------------------------------

BENCH_FLAGS = --benchmark_time_unit=ns --benchmark_counters_tabular=true

run-armv8: bench_aes
	@echo "========================================================"
	@echo "  Backend: ARMv8 hardware AES  (vaeseq_u8 / vaesmcq_u8)"
	@echo "========================================================"
	./bench_aes $(BENCH_FLAGS)

run-vperm: bench_aes
	@echo "========================================================"
	@echo "  Backend: VPERM / NEON  (BOTAN_CLEAR_CPUID=armv8aes)"
	@echo "========================================================"
	BOTAN_CLEAR_CPUID=armv8aes ./bench_aes $(BENCH_FLAGS)

run-bitsliced: bench_aes
	@echo "========================================================"
	@echo "  Backend: Bitsliced  (BOTAN_CLEAR_CPUID=armv8aes,neon)"
	@echo "========================================================"
	BOTAN_CLEAR_CPUID=armv8aes,neon ./bench_aes $(BENCH_FLAGS)

run-compare: bench_aes
	@echo "========================================================"
	@echo "  Botan bitsliced vs my-aes.cpp (оба — base бэкенд)"
	@echo "========================================================"
	BOTAN_CLEAR_CPUID=armv8aes,neon ./bench_aes $(BENCH_FLAGS)

run-all: bench_aes
	@echo ""
	@$(MAKE) --no-print-directory run-armv8
	@echo ""
	@$(MAKE) --no-print-directory run-vperm
	@echo ""
	@$(MAKE) --no-print-directory run-bitsliced

clean:
	rm -f bench_aes main
