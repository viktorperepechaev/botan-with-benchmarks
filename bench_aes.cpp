/*
 * Benchmark: AES-128 encrypt/decrypt/key-schedule
 *
 * Three Botan backends via BOTAN_CLEAR_CPUID env var:
 *   (nothing)              -> ARMv8 hardware AES  (vaeseq_u8 / vaesmcq_u8)
 *   armv8aes               -> VPERM / NEON         (vector permute, Mike Hamburg CHES 2009)
 *   armv8aes,neon          -> Bitsliced (Botan)     (scalar, 2 blocks parallel)
 *
 * Plus BM_Direct_* benchmarks that call the bitsliced functions from my-aes.cpp
 * directly — no virtual dispatch, no BlockCipher class overhead.
 *
 * Build:
 *   make bench_aes
 * Run:
 *   make run-all
 */

#include <benchmark/benchmark.h>
#include <botan/block_cipher.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <vector>

// Forward declarations for BitslicedDirect wrappers defined in my-aes.cpp
// (compiled with -DBENCH_DIRECT, without main())
namespace BitslicedDirect {
    void key_schedule(const uint8_t* key, size_t len,
                      std::vector<uint32_t>& EK, std::vector<uint32_t>& DK);
    void encrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
                   const std::vector<uint32_t>& EK);
    void decrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
                   const std::vector<uint32_t>& DK);
}

// Forward declarations for AES-NI wrappers defined in my-aes-ni.cpp
namespace AesNiDirect {
    void key_schedule(const uint8_t* key, size_t len,
                      std::vector<uint32_t>& EK, std::vector<uint32_t>& DK);
    void encrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
                   const std::vector<uint32_t>& EK);
    void decrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
                   const std::vector<uint32_t>& DK);
}

// -----------------------------------------------------------------------
// Shared test data  (FIPS-197 Appendix C.1)
// -----------------------------------------------------------------------
static constexpr uint8_t KEY128[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};

// -----------------------------------------------------------------------
// Helper: make a flat buffer of `blocks` AES blocks, filled with 0xAB
// -----------------------------------------------------------------------
static std::vector<uint8_t> make_buf(size_t blocks) {
    return std::vector<uint8_t>(blocks * 16, 0xAB);
}

// -----------------------------------------------------------------------
// BM_Botan_Encrypt  –  AES-128 encrypt, parameterised by block count
// -----------------------------------------------------------------------
static void BM_Botan_Encrypt(benchmark::State& state) {
    const size_t nblocks = static_cast<size_t>(state.range(0));

    auto cipher = Botan::BlockCipher::create_or_throw("AES-128");
    cipher->set_key(KEY128, 16);

    auto in  = make_buf(nblocks);
    auto out = make_buf(nblocks);

    for (auto _ : state) {
        cipher->encrypt_n(in.data(), out.data(), nblocks);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(nblocks * 16));
    state.SetLabel(cipher->provider());
}

// -----------------------------------------------------------------------
// BM_Botan_Decrypt  –  AES-128 decrypt, parameterised by block count
// -----------------------------------------------------------------------
static void BM_Botan_Decrypt(benchmark::State& state) {
    const size_t nblocks = static_cast<size_t>(state.range(0));

    auto cipher = Botan::BlockCipher::create_or_throw("AES-128");
    cipher->set_key(KEY128, 16);

    auto in  = make_buf(nblocks);
    auto out = make_buf(nblocks);

    for (auto _ : state) {
        cipher->decrypt_n(in.data(), out.data(), nblocks);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(nblocks * 16));
    state.SetLabel(cipher->provider());
}

// -----------------------------------------------------------------------
// BM_Botan_KeySchedule  –  only measure set_key (key expansion)
// -----------------------------------------------------------------------
static void BM_Botan_KeySchedule(benchmark::State& state) {
    auto cipher = Botan::BlockCipher::create_or_throw("AES-128");

    for (auto _ : state) {
        cipher->set_key(KEY128, 16);
        benchmark::DoNotOptimize(cipher.get());
        benchmark::ClobberMemory();
    }

    state.SetLabel(cipher->provider());
}

// block counts: 1 (latency), 2 (bitsliced native), 4 (HW parallel), 64, 1024 (throughput)
BENCHMARK(BM_Botan_Encrypt)->Arg(1)->Arg(2)->Arg(4)->Arg(64)->Arg(1024);
BENCHMARK(BM_Botan_Decrypt)->Arg(1)->Arg(2)->Arg(4)->Arg(64)->Arg(1024);
BENCHMARK(BM_Botan_KeySchedule);

// -----------------------------------------------------------------------
// BM_Direct_*  –  direct calls into BitslicedDirect (my-aes.cpp funcs),
// bypassing Botan's BlockCipher class hierarchy entirely.
// These always use the bitsliced backend regardless of BOTAN_CLEAR_CPUID.
// -----------------------------------------------------------------------
static void BM_Direct_Encrypt(benchmark::State& state) {
    const size_t nblocks = static_cast<size_t>(state.range(0));

    std::vector<uint32_t> EK, DK;
    BitslicedDirect::key_schedule(KEY128, 16, EK, DK);

    auto in  = make_buf(nblocks);
    auto out = make_buf(nblocks);

    for (auto _ : state) {
        BitslicedDirect::encrypt_n(in.data(), out.data(), nblocks, EK);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(nblocks * 16));
}

static void BM_Direct_Decrypt(benchmark::State& state) {
    const size_t nblocks = static_cast<size_t>(state.range(0));

    std::vector<uint32_t> EK, DK;
    BitslicedDirect::key_schedule(KEY128, 16, EK, DK);

    auto in  = make_buf(nblocks);
    auto out = make_buf(nblocks);

    for (auto _ : state) {
        BitslicedDirect::decrypt_n(in.data(), out.data(), nblocks, DK);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(nblocks * 16));
}

static void BM_Direct_KeySchedule(benchmark::State& state) {
    std::vector<uint32_t> EK, DK;

    for (auto _ : state) {
        BitslicedDirect::key_schedule(KEY128, 16, EK, DK);
        benchmark::DoNotOptimize(EK.data());
        benchmark::ClobberMemory();
    }
}

BENCHMARK(BM_Direct_Encrypt)->Arg(1)->Arg(2)->Arg(4)->Arg(64)->Arg(1024);
BENCHMARK(BM_Direct_Decrypt)->Arg(1)->Arg(2)->Arg(4)->Arg(64)->Arg(1024);
BENCHMARK(BM_Direct_KeySchedule);

// -----------------------------------------------------------------------
// BM_AesNi_*  –  direct calls into AesNiDirect (my-aes-ni.cpp),
// using AES-NI hardware intrinsics, no Botan class overhead.
// -----------------------------------------------------------------------
static void BM_AesNi_Encrypt(benchmark::State& state) {
    const size_t nblocks = static_cast<size_t>(state.range(0));

    std::vector<uint32_t> EK, DK;
    AesNiDirect::key_schedule(KEY128, 16, EK, DK);

    auto in  = make_buf(nblocks);
    auto out = make_buf(nblocks);

    for (auto _ : state) {
        AesNiDirect::encrypt_n(in.data(), out.data(), nblocks, EK);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(nblocks * 16));
}

static void BM_AesNi_Decrypt(benchmark::State& state) {
    const size_t nblocks = static_cast<size_t>(state.range(0));

    std::vector<uint32_t> EK, DK;
    AesNiDirect::key_schedule(KEY128, 16, EK, DK);

    auto in  = make_buf(nblocks);
    auto out = make_buf(nblocks);

    for (auto _ : state) {
        AesNiDirect::decrypt_n(in.data(), out.data(), nblocks, DK);
        benchmark::DoNotOptimize(out.data());
        benchmark::ClobberMemory();
    }

    state.SetBytesProcessed(
        static_cast<int64_t>(state.iterations()) * static_cast<int64_t>(nblocks * 16));
}

static void BM_AesNi_KeySchedule(benchmark::State& state) {
    std::vector<uint32_t> EK, DK;

    for (auto _ : state) {
        AesNiDirect::key_schedule(KEY128, 16, EK, DK);
        benchmark::DoNotOptimize(EK.data());
        benchmark::ClobberMemory();
    }
}

BENCHMARK(BM_AesNi_Encrypt)->Arg(1)->Arg(2)->Arg(4)->Arg(64)->Arg(1024);
BENCHMARK(BM_AesNi_Decrypt)->Arg(1)->Arg(2)->Arg(4)->Arg(64)->Arg(1024);
BENCHMARK(BM_AesNi_KeySchedule);

BENCHMARK_MAIN();
