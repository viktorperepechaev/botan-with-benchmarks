/*
 * AES-128 implementation using AES-NI intrinsics.
 * Based on the approach from Botan 3.10.0 (aes_ni.cpp), stripped of the
 * class hierarchy and SIMD_4x32 wrapper — uses raw __m128i directly.
 *
 * Compile with: -maes -msse4.1
 */

#include <cstdint>
#include <cstring>
#include <vector>
#include <wmmintrin.h>  // AES-NI
#include <smmintrin.h>  // SSE4.1

namespace AesNiDirect {

// -----------------------------------------------------------------------
// Key expansion helpers (from Botan)
// -----------------------------------------------------------------------

template <uint8_t RC>
__attribute__((target("aes")))
static inline __m128i aes_128_key_expansion(__m128i key, __m128i key_getting_rcon) {
    __m128i key_with_rcon = _mm_aeskeygenassist_si128(key_getting_rcon, RC);
    key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3, 3, 3, 3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, key_with_rcon);
}

// -----------------------------------------------------------------------
// Key schedule: produces 11 round keys for AES-128 (encrypt + decrypt)
// Stored as 44 uint32_t each (little-endian, native AES-NI format)
// -----------------------------------------------------------------------

__attribute__((target("aes")))
void key_schedule(const uint8_t* key, size_t /*len*/,
                  std::vector<uint32_t>& EK,
                  std::vector<uint32_t>& DK) {
    EK.resize(44);
    DK.resize(44);

    const __m128i K0  = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    const __m128i K1  = aes_128_key_expansion<0x01>(K0, K0);
    const __m128i K2  = aes_128_key_expansion<0x02>(K1, K1);
    const __m128i K3  = aes_128_key_expansion<0x04>(K2, K2);
    const __m128i K4  = aes_128_key_expansion<0x08>(K3, K3);
    const __m128i K5  = aes_128_key_expansion<0x10>(K4, K4);
    const __m128i K6  = aes_128_key_expansion<0x20>(K5, K5);
    const __m128i K7  = aes_128_key_expansion<0x40>(K6, K6);
    const __m128i K8  = aes_128_key_expansion<0x80>(K7, K7);
    const __m128i K9  = aes_128_key_expansion<0x1B>(K8, K8);
    const __m128i K10 = aes_128_key_expansion<0x36>(K9, K9);

    __m128i* EK_mm = reinterpret_cast<__m128i*>(EK.data());
    _mm_storeu_si128(EK_mm + 0,  K0);
    _mm_storeu_si128(EK_mm + 1,  K1);
    _mm_storeu_si128(EK_mm + 2,  K2);
    _mm_storeu_si128(EK_mm + 3,  K3);
    _mm_storeu_si128(EK_mm + 4,  K4);
    _mm_storeu_si128(EK_mm + 5,  K5);
    _mm_storeu_si128(EK_mm + 6,  K6);
    _mm_storeu_si128(EK_mm + 7,  K7);
    _mm_storeu_si128(EK_mm + 8,  K8);
    _mm_storeu_si128(EK_mm + 9,  K9);
    _mm_storeu_si128(EK_mm + 10, K10);

    // Decryption keys: reverse order + InvMixColumns on middle keys
    __m128i* DK_mm = reinterpret_cast<__m128i*>(DK.data());
    _mm_storeu_si128(DK_mm + 0,  K10);
    _mm_storeu_si128(DK_mm + 1,  _mm_aesimc_si128(K9));
    _mm_storeu_si128(DK_mm + 2,  _mm_aesimc_si128(K8));
    _mm_storeu_si128(DK_mm + 3,  _mm_aesimc_si128(K7));
    _mm_storeu_si128(DK_mm + 4,  _mm_aesimc_si128(K6));
    _mm_storeu_si128(DK_mm + 5,  _mm_aesimc_si128(K5));
    _mm_storeu_si128(DK_mm + 6,  _mm_aesimc_si128(K4));
    _mm_storeu_si128(DK_mm + 7,  _mm_aesimc_si128(K3));
    _mm_storeu_si128(DK_mm + 8,  _mm_aesimc_si128(K2));
    _mm_storeu_si128(DK_mm + 9,  _mm_aesimc_si128(K1));
    _mm_storeu_si128(DK_mm + 10, K0);
}

// -----------------------------------------------------------------------
// Encrypt N blocks using AES-NI.  Processes 4 blocks at a time for
// maximum pipeline utilisation, then handles the remainder one-by-one.
// -----------------------------------------------------------------------

__attribute__((target("aes")))
void encrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
               const std::vector<uint32_t>& EK) {

    const __m128i* RK = reinterpret_cast<const __m128i*>(EK.data());
    const __m128i K0  = _mm_loadu_si128(RK + 0);
    const __m128i K1  = _mm_loadu_si128(RK + 1);
    const __m128i K2  = _mm_loadu_si128(RK + 2);
    const __m128i K3  = _mm_loadu_si128(RK + 3);
    const __m128i K4  = _mm_loadu_si128(RK + 4);
    const __m128i K5  = _mm_loadu_si128(RK + 5);
    const __m128i K6  = _mm_loadu_si128(RK + 6);
    const __m128i K7  = _mm_loadu_si128(RK + 7);
    const __m128i K8  = _mm_loadu_si128(RK + 8);
    const __m128i K9  = _mm_loadu_si128(RK + 9);
    const __m128i K10 = _mm_loadu_si128(RK + 10);

    // 4-block pipeline
    while (blocks >= 4) {
        __m128i B0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 0));
        __m128i B1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
        __m128i B2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
        __m128i B3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));

        B0 = _mm_xor_si128(B0, K0); B1 = _mm_xor_si128(B1, K0);
        B2 = _mm_xor_si128(B2, K0); B3 = _mm_xor_si128(B3, K0);

        #define AESENC4(K) \
            B0 = _mm_aesenc_si128(B0, K); B1 = _mm_aesenc_si128(B1, K); \
            B2 = _mm_aesenc_si128(B2, K); B3 = _mm_aesenc_si128(B3, K)

        AESENC4(K1); AESENC4(K2); AESENC4(K3); AESENC4(K4); AESENC4(K5);
        AESENC4(K6); AESENC4(K7); AESENC4(K8); AESENC4(K9);

        #undef AESENC4

        B0 = _mm_aesenclast_si128(B0, K10); B1 = _mm_aesenclast_si128(B1, K10);
        B2 = _mm_aesenclast_si128(B2, K10); B3 = _mm_aesenclast_si128(B3, K10);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 0),  B0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16), B1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32), B2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48), B3);

        blocks -= 4; in += 64; out += 64;
    }

    // Remainder
    for (size_t i = 0; i < blocks; ++i) {
        __m128i B = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16 * i));
        B = _mm_xor_si128(B, K0);
        B = _mm_aesenc_si128(B, K1); B = _mm_aesenc_si128(B, K2);
        B = _mm_aesenc_si128(B, K3); B = _mm_aesenc_si128(B, K4);
        B = _mm_aesenc_si128(B, K5); B = _mm_aesenc_si128(B, K6);
        B = _mm_aesenc_si128(B, K7); B = _mm_aesenc_si128(B, K8);
        B = _mm_aesenc_si128(B, K9);
        B = _mm_aesenclast_si128(B, K10);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16 * i), B);
    }
}

// -----------------------------------------------------------------------
// Decrypt N blocks using AES-NI (same 4-block pipeline approach)
// -----------------------------------------------------------------------

__attribute__((target("aes")))
void decrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
               const std::vector<uint32_t>& DK) {

    const __m128i* RK = reinterpret_cast<const __m128i*>(DK.data());
    const __m128i K0  = _mm_loadu_si128(RK + 0);
    const __m128i K1  = _mm_loadu_si128(RK + 1);
    const __m128i K2  = _mm_loadu_si128(RK + 2);
    const __m128i K3  = _mm_loadu_si128(RK + 3);
    const __m128i K4  = _mm_loadu_si128(RK + 4);
    const __m128i K5  = _mm_loadu_si128(RK + 5);
    const __m128i K6  = _mm_loadu_si128(RK + 6);
    const __m128i K7  = _mm_loadu_si128(RK + 7);
    const __m128i K8  = _mm_loadu_si128(RK + 8);
    const __m128i K9  = _mm_loadu_si128(RK + 9);
    const __m128i K10 = _mm_loadu_si128(RK + 10);

    while (blocks >= 4) {
        __m128i B0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 0));
        __m128i B1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16));
        __m128i B2 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 32));
        __m128i B3 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 48));

        B0 = _mm_xor_si128(B0, K0); B1 = _mm_xor_si128(B1, K0);
        B2 = _mm_xor_si128(B2, K0); B3 = _mm_xor_si128(B3, K0);

        #define AESDEC4(K) \
            B0 = _mm_aesdec_si128(B0, K); B1 = _mm_aesdec_si128(B1, K); \
            B2 = _mm_aesdec_si128(B2, K); B3 = _mm_aesdec_si128(B3, K)

        AESDEC4(K1); AESDEC4(K2); AESDEC4(K3); AESDEC4(K4); AESDEC4(K5);
        AESDEC4(K6); AESDEC4(K7); AESDEC4(K8); AESDEC4(K9);

        #undef AESDEC4

        B0 = _mm_aesdeclast_si128(B0, K10); B1 = _mm_aesdeclast_si128(B1, K10);
        B2 = _mm_aesdeclast_si128(B2, K10); B3 = _mm_aesdeclast_si128(B3, K10);

        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 0),  B0);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16), B1);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 32), B2);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 48), B3);

        blocks -= 4; in += 64; out += 64;
    }

    for (size_t i = 0; i < blocks; ++i) {
        __m128i B = _mm_loadu_si128(reinterpret_cast<const __m128i*>(in + 16 * i));
        B = _mm_xor_si128(B, K0);
        B = _mm_aesdec_si128(B, K1); B = _mm_aesdec_si128(B, K2);
        B = _mm_aesdec_si128(B, K3); B = _mm_aesdec_si128(B, K4);
        B = _mm_aesdec_si128(B, K5); B = _mm_aesdec_si128(B, K6);
        B = _mm_aesdec_si128(B, K7); B = _mm_aesdec_si128(B, K8);
        B = _mm_aesdec_si128(B, K9);
        B = _mm_aesdeclast_si128(B, K10);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(out + 16 * i), B);
    }
}

}  // namespace AesNiDirect
