/*
* (C) 1999-2010,2015,2017,2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <algorithm>
#include <cstdint>
#include <concepts>
#include <iomanip>
#include <span>
#include <vector>
#include <cstring>

namespace Botan {

/*
* One of three AES implementation strategies are used to get a constant time
* implementation which is immune to common cache/timing based side channels:
*
* - If AES hardware support is available (AES-NI, POWER8, Aarch64) use that
*
* - If 128-bit SIMD with byte shuffles are available (SSSE3, NEON, or Altivec),
*   use the vperm technique published by Mike Hamburg at CHES 2009.
*
* - If no hardware or SIMD support, fall back to a constant time bitsliced
*   implementation. This uses 32-bit words resulting in 2 blocks being processed
*   in parallel. Moving to 4 blocks (with 64-bit words) would approximately
*   double performance on 64-bit CPUs. Likewise moving to 128 bit SIMD would
*   again approximately double performance vs 64-bit. However the assumption is
*   that most 64-bit CPUs either have hardware AES or SIMD shuffle support and
*   that the majority of users falling back to this code will be 32-bit cores.
*   If this assumption proves to be unsound, the bitsliced code can easily be
*   extended to operate on either 32 or 64 bit words depending on the native
*   wordsize of the target processor.
*
* Useful references
*
* - "Accelerating AES with Vector Permute Instructions" Mike Hamburg
*   https://www.shiftleft.org/papers/vector_aes/vector_aes.pdf
*
* - "Faster and Timing-Attack Resistant AES-GCM" Käsper and Schwabe
*   https://eprint.iacr.org/2009/129.pdf
*
* - "A new combinational logic minimization technique with applications to cryptology."
*   Boyar and Peralta https://eprint.iacr.org/2009/191.pdf
*
* - "A depth-16 circuit for the AES S-box" Boyar and Peralta
*    https://eprint.iacr.org/2011/332.pdf
*
* - "A Very Compact S-box for AES" Canright
*   https://www.iacr.org/archive/ches2005/032.pdf
*   https://core.ac.uk/download/pdf/36694529.pdf (extended)
*/

namespace {

/*
This is an AES sbox circuit which can execute in bitsliced mode up to 32x in
parallel.

The circuit is from the "Circuit Minimization Team" group
http://www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
http://www.cs.yale.edu/homes/peralta/CircuitStuff/SLP_AES_113.txt

This circuit has size 113 and depth 27. In software it is much faster than
circuits which are considered faster for hardware purposes (where circuit depth
is the critical constraint), because unlike in hardware, on common CPUs we can
only execute - at best - 3 or 4 logic operations per cycle. So a smaller circuit
is superior. On an x86-64 machine this circuit is about 15% faster than the
circuit of size 128 and depth 16 given in "A depth-16 circuit for the AES S-box".

Another circuit for AES Sbox of size 102 and depth 24 is describted in "New
Circuit Minimization Techniques for Smaller and Faster AES SBoxes"
[https://eprint.iacr.org/2019/802] however it relies on "non-standard" gates
like MUX, NOR, NAND, etc and so in practice in bitsliced software, its size is
actually a bit larger than this circuit, as few CPUs have such instructions and
otherwise they must be emulated using a sequence of available bit operations.
*/
void AES_SBOX(uint32_t V[8]) {
   const uint32_t U0 = V[0];
   const uint32_t U1 = V[1];
   const uint32_t U2 = V[2];
   const uint32_t U3 = V[3];
   const uint32_t U4 = V[4];
   const uint32_t U5 = V[5];
   const uint32_t U6 = V[6];
   const uint32_t U7 = V[7];

   const uint32_t y14 = U3 ^ U5;
   const uint32_t y13 = U0 ^ U6;
   const uint32_t y9 = U0 ^ U3;
   const uint32_t y8 = U0 ^ U5;
   const uint32_t t0 = U1 ^ U2;
   const uint32_t y1 = t0 ^ U7;
   const uint32_t y4 = y1 ^ U3;
   const uint32_t y12 = y13 ^ y14;
   const uint32_t y2 = y1 ^ U0;
   const uint32_t y5 = y1 ^ U6;
   const uint32_t y3 = y5 ^ y8;
   const uint32_t t1 = U4 ^ y12;
   const uint32_t y15 = t1 ^ U5;
   const uint32_t y20 = t1 ^ U1;
   const uint32_t y6 = y15 ^ U7;
   const uint32_t y10 = y15 ^ t0;
   const uint32_t y11 = y20 ^ y9;
   const uint32_t y7 = U7 ^ y11;
   const uint32_t y17 = y10 ^ y11;
   const uint32_t y19 = y10 ^ y8;
   const uint32_t y16 = t0 ^ y11;
   const uint32_t y21 = y13 ^ y16;
   const uint32_t y18 = U0 ^ y16;
   const uint32_t t2 = y12 & y15;
   const uint32_t t3 = y3 & y6;
   const uint32_t t4 = t3 ^ t2;
   const uint32_t t5 = y4 & U7;
   const uint32_t t6 = t5 ^ t2;
   const uint32_t t7 = y13 & y16;
   const uint32_t t8 = y5 & y1;
   const uint32_t t9 = t8 ^ t7;
   const uint32_t t10 = y2 & y7;
   const uint32_t t11 = t10 ^ t7;
   const uint32_t t12 = y9 & y11;
   const uint32_t t13 = y14 & y17;
   const uint32_t t14 = t13 ^ t12;
   const uint32_t t15 = y8 & y10;
   const uint32_t t16 = t15 ^ t12;
   const uint32_t t17 = t4 ^ y20;
   const uint32_t t18 = t6 ^ t16;
   const uint32_t t19 = t9 ^ t14;
   const uint32_t t20 = t11 ^ t16;
   const uint32_t t21 = t17 ^ t14;
   const uint32_t t22 = t18 ^ y19;
   const uint32_t t23 = t19 ^ y21;
   const uint32_t t24 = t20 ^ y18;
   const uint32_t t25 = t21 ^ t22;
   const uint32_t t26 = t21 & t23;
   const uint32_t t27 = t24 ^ t26;
   const uint32_t t28 = t25 & t27;
   const uint32_t t29 = t28 ^ t22;
   const uint32_t t30 = t23 ^ t24;
   const uint32_t t31 = t22 ^ t26;
   const uint32_t t32 = t31 & t30;
   const uint32_t t33 = t32 ^ t24;
   const uint32_t t34 = t23 ^ t33;
   const uint32_t t35 = t27 ^ t33;
   const uint32_t t36 = t24 & t35;
   const uint32_t t37 = t36 ^ t34;
   const uint32_t t38 = t27 ^ t36;
   const uint32_t t39 = t29 & t38;
   const uint32_t t40 = t25 ^ t39;
   const uint32_t t41 = t40 ^ t37;
   const uint32_t t42 = t29 ^ t33;
   const uint32_t t43 = t29 ^ t40;
   const uint32_t t44 = t33 ^ t37;
   const uint32_t t45 = t42 ^ t41;
   const uint32_t z0 = t44 & y15;
   const uint32_t z1 = t37 & y6;
   const uint32_t z2 = t33 & U7;
   const uint32_t z3 = t43 & y16;
   const uint32_t z4 = t40 & y1;
   const uint32_t z5 = t29 & y7;
   const uint32_t z6 = t42 & y11;
   const uint32_t z7 = t45 & y17;
   const uint32_t z8 = t41 & y10;
   const uint32_t z9 = t44 & y12;
   const uint32_t z10 = t37 & y3;
   const uint32_t z11 = t33 & y4;
   const uint32_t z12 = t43 & y13;
   const uint32_t z13 = t40 & y5;
   const uint32_t z14 = t29 & y2;
   const uint32_t z15 = t42 & y9;
   const uint32_t z16 = t45 & y14;
   const uint32_t z17 = t41 & y8;
   const uint32_t tc1 = z15 ^ z16;
   const uint32_t tc2 = z10 ^ tc1;
   const uint32_t tc3 = z9 ^ tc2;
   const uint32_t tc4 = z0 ^ z2;
   const uint32_t tc5 = z1 ^ z0;
   const uint32_t tc6 = z3 ^ z4;
   const uint32_t tc7 = z12 ^ tc4;
   const uint32_t tc8 = z7 ^ tc6;
   const uint32_t tc9 = z8 ^ tc7;
   const uint32_t tc10 = tc8 ^ tc9;
   const uint32_t tc11 = tc6 ^ tc5;
   const uint32_t tc12 = z3 ^ z5;
   const uint32_t tc13 = z13 ^ tc1;
   const uint32_t tc14 = tc4 ^ tc12;
   const uint32_t S3 = tc3 ^ tc11;
   const uint32_t tc16 = z6 ^ tc8;
   const uint32_t tc17 = z14 ^ tc10;
   const uint32_t tc18 = ~tc13 ^ tc14;
   const uint32_t S7 = z12 ^ tc18;
   const uint32_t tc20 = z15 ^ tc16;
   const uint32_t tc21 = tc2 ^ z11;
   const uint32_t S0 = tc3 ^ tc16;
   const uint32_t S6 = tc10 ^ tc18;
   const uint32_t S4 = tc14 ^ S3;
   const uint32_t S1 = ~(S3 ^ tc16);
   const uint32_t tc26 = tc17 ^ tc20;
   const uint32_t S2 = ~(tc26 ^ z17);
   const uint32_t S5 = tc21 ^ tc17;

   V[0] = S0;
   V[1] = S1;
   V[2] = S2;
   V[3] = S3;
   V[4] = S4;
   V[5] = S5;
   V[6] = S6;
   V[7] = S7;
}

/*
A circuit for inverse AES Sbox of size 121 and depth 21 from
http://www.cs.yale.edu/homes/peralta/CircuitStuff/CMT.html
http://www.cs.yale.edu/homes/peralta/CircuitStuff/Sinv.txt
*/
void AES_INV_SBOX(uint32_t V[8]) {
   const uint32_t U0 = V[0];
   const uint32_t U1 = V[1];
   const uint32_t U2 = V[2];
   const uint32_t U3 = V[3];
   const uint32_t U4 = V[4];
   const uint32_t U5 = V[5];
   const uint32_t U6 = V[6];
   const uint32_t U7 = V[7];

   const uint32_t Y0 = U0 ^ U3;
   const uint32_t Y2 = ~(U1 ^ U3);
   const uint32_t Y4 = U0 ^ Y2;
   const uint32_t RTL0 = U6 ^ U7;
   const uint32_t Y1 = Y2 ^ RTL0;
   const uint32_t Y7 = ~(U2 ^ Y1);
   const uint32_t RTL1 = U3 ^ U4;
   const uint32_t Y6 = ~(U7 ^ RTL1);
   const uint32_t Y3 = Y1 ^ RTL1;
   const uint32_t RTL2 = ~(U0 ^ U2);
   const uint32_t Y5 = U5 ^ RTL2;
   const uint32_t sa1 = Y0 ^ Y2;
   const uint32_t sa0 = Y1 ^ Y3;
   const uint32_t sb1 = Y4 ^ Y6;
   const uint32_t sb0 = Y5 ^ Y7;
   const uint32_t ah = Y0 ^ Y1;
   const uint32_t al = Y2 ^ Y3;
   const uint32_t aa = sa0 ^ sa1;
   const uint32_t bh = Y4 ^ Y5;
   const uint32_t bl = Y6 ^ Y7;
   const uint32_t bb = sb0 ^ sb1;
   const uint32_t ab20 = sa0 ^ sb0;
   const uint32_t ab22 = al ^ bl;
   const uint32_t ab23 = Y3 ^ Y7;
   const uint32_t ab21 = sa1 ^ sb1;
   const uint32_t abcd1 = ah & bh;
   const uint32_t rr1 = Y0 & Y4;
   const uint32_t ph11 = ab20 ^ abcd1;
   const uint32_t t01 = Y1 & Y5;
   const uint32_t ph01 = t01 ^ abcd1;
   const uint32_t abcd2 = al & bl;
   const uint32_t r1 = Y2 & Y6;
   const uint32_t pl11 = ab22 ^ abcd2;
   const uint32_t r2 = Y3 & Y7;
   const uint32_t pl01 = r2 ^ abcd2;
   const uint32_t r3 = sa0 & sb0;
   const uint32_t vr1 = aa & bb;
   const uint32_t pr1 = vr1 ^ r3;
   const uint32_t wr1 = sa1 & sb1;
   const uint32_t qr1 = wr1 ^ r3;
   const uint32_t ab0 = ph11 ^ rr1;
   const uint32_t ab1 = ph01 ^ ab21;
   const uint32_t ab2 = pl11 ^ r1;
   const uint32_t ab3 = pl01 ^ qr1;
   const uint32_t cp1 = ab0 ^ pr1;
   const uint32_t cp2 = ab1 ^ qr1;
   const uint32_t cp3 = ab2 ^ pr1;
   const uint32_t cp4 = ab3 ^ ab23;
   const uint32_t tinv1 = cp3 ^ cp4;
   const uint32_t tinv2 = cp3 & cp1;
   const uint32_t tinv3 = cp2 ^ tinv2;
   const uint32_t tinv4 = cp1 ^ cp2;
   const uint32_t tinv5 = cp4 ^ tinv2;
   const uint32_t tinv6 = tinv5 & tinv4;
   const uint32_t tinv7 = tinv3 & tinv1;
   const uint32_t d2 = cp4 ^ tinv7;
   const uint32_t d0 = cp2 ^ tinv6;
   const uint32_t tinv8 = cp1 & cp4;
   const uint32_t tinv9 = tinv4 & tinv8;
   const uint32_t tinv10 = tinv4 ^ tinv2;
   const uint32_t d1 = tinv9 ^ tinv10;
   const uint32_t tinv11 = cp2 & cp3;
   const uint32_t tinv12 = tinv1 & tinv11;
   const uint32_t tinv13 = tinv1 ^ tinv2;
   const uint32_t d3 = tinv12 ^ tinv13;
   const uint32_t sd1 = d1 ^ d3;
   const uint32_t sd0 = d0 ^ d2;
   const uint32_t dl = d0 ^ d1;  // NOLINT(misc-confusable-identifiers)
   const uint32_t dh = d2 ^ d3;
   const uint32_t dd = sd0 ^ sd1;
   const uint32_t abcd3 = dh & bh;
   const uint32_t rr2 = d3 & Y4;
   const uint32_t t02 = d2 & Y5;
   const uint32_t abcd4 = dl & bl;
   const uint32_t r4 = d1 & Y6;
   const uint32_t r5 = d0 & Y7;
   const uint32_t r6 = sd0 & sb0;
   const uint32_t vr2 = dd & bb;
   const uint32_t wr2 = sd1 & sb1;
   const uint32_t abcd5 = dh & ah;
   const uint32_t r7 = d3 & Y0;
   const uint32_t r8 = d2 & Y1;
   const uint32_t abcd6 = dl & al;
   const uint32_t r9 = d1 & Y2;
   const uint32_t r10 = d0 & Y3;
   const uint32_t r11 = sd0 & sa0;
   const uint32_t vr3 = dd & aa;
   const uint32_t wr3 = sd1 & sa1;
   const uint32_t ph12 = rr2 ^ abcd3;
   const uint32_t ph02 = t02 ^ abcd3;
   const uint32_t pl12 = r4 ^ abcd4;
   const uint32_t pl02 = r5 ^ abcd4;
   const uint32_t pr2 = vr2 ^ r6;
   const uint32_t qr2 = wr2 ^ r6;
   const uint32_t p0 = ph12 ^ pr2;
   const uint32_t p1 = ph02 ^ qr2;
   const uint32_t p2 = pl12 ^ pr2;
   const uint32_t p3 = pl02 ^ qr2;
   const uint32_t ph13 = r7 ^ abcd5;
   const uint32_t ph03 = r8 ^ abcd5;
   const uint32_t pl13 = r9 ^ abcd6;
   const uint32_t pl03 = r10 ^ abcd6;
   const uint32_t pr3 = vr3 ^ r11;
   const uint32_t qr3 = wr3 ^ r11;
   const uint32_t p4 = ph13 ^ pr3;
   const uint32_t S7 = ph03 ^ qr3;
   const uint32_t p6 = pl13 ^ pr3;
   const uint32_t p7 = pl03 ^ qr3;
   const uint32_t S3 = p1 ^ p6;
   const uint32_t S6 = p2 ^ p6;
   const uint32_t S0 = p3 ^ p6;
   const uint32_t X11 = p0 ^ p2;
   const uint32_t S5 = S0 ^ X11;
   const uint32_t X13 = p4 ^ p7;
   const uint32_t X14 = X11 ^ X13;
   const uint32_t S1 = S3 ^ X14;
   const uint32_t X16 = p1 ^ S7;
   const uint32_t S2 = X14 ^ X16;
   const uint32_t X18 = p0 ^ p4;
   const uint32_t X19 = S5 ^ X16;
   const uint32_t S4 = X18 ^ X19;

   V[0] = S0;
   V[1] = S1;
   V[2] = S2;
   V[3] = S3;
   V[4] = S4;
   V[5] = S5;
   V[6] = S6;
   V[7] = S7;
}


template <std::unsigned_integral T>
[[gnu::always_inline]] inline constexpr void swap_bits(T& x, T& y, T mask, size_t shift) { // !!! В botan тут force inline
   const T swap = ((x >> shift) ^ y) & mask;
   x ^= swap << shift;
   y ^= swap;
}

template <std::unsigned_integral T>
[[gnu::always_inline]] inline constexpr T bit_permute_step(T x, T mask, size_t shift) { // !!! В botan тут force inline
   /*
   See https://reflectionsonsecurity.wordpress.com/2014/05/11/efficient-bit-permutation-using-delta-swaps/
   and http://programming.sirrida.de/bit_perm.html
   */
   const T swap = ((x >> shift) ^ x) & mask;
   return (x ^ swap) ^ (swap << shift);
}

/**
* Bit rotation right by a compile-time constant amount
* @param input the input word
* @return input rotated right by ROT bits
*/
template <size_t ROT, std::unsigned_integral T>
[[gnu::always_inline]] inline constexpr T rotr(T input) // !!!
   requires(ROT > 0 && ROT < 8 * sizeof(T))
{
   return static_cast<T>((input >> ROT) | (input << (8 * sizeof(T) - ROT)));
}

/**
* Bit rotation left by a compile-time constant amount
* @param input the input word
* @return input rotated left by ROT bits
*/
template <size_t ROT, std::unsigned_integral T>
[[gnu::always_inline]] inline constexpr T rotl(T input)
   requires(ROT > 0 && ROT < 8 * sizeof(T))
{
   return static_cast<T>((input << ROT) | (input >> (8 * sizeof(T) - ROT)));
}


namespace CT {
/**
* Mark variable as unused.
*
* Takes any number of arguments and marks all as unused, for instance
* BOTAN_UNUSED(a); or BOTAN_UNUSED(x, y, z);
*/
template <typename... T>
constexpr void ignore_params([[maybe_unused]] const T&... args) {}

#define BOTAN_UNUSED ignore_params

template <typename T>
constexpr inline void unpoison(const T* p, size_t n) {
   BOTAN_UNUSED(p, n);
}

template <typename T>
constexpr inline void poison(const T* p, size_t n) {
#if defined(BOTAN_HAS_VALGRIND)
   if(!std::is_constant_evaluated()) {
      VALGRIND_MAKE_MEM_UNDEFINED(p, n * sizeof(T));
   }
#endif

   BOTAN_UNUSED(p, n);
}
};

/**
 * Swap the byte order of an unsigned integer
 */
template <std::unsigned_integral T>
   requires(sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8)
inline constexpr T reverse_bytes(T x) {
   if constexpr(sizeof(T) == 1) {
      return x;
   } else if constexpr(sizeof(T) == 2) {
      return static_cast<T>((x << 8) | (x >> 8));
   } else if constexpr(sizeof(T) == 4) {
      return static_cast<T>(((x & 0x000000FF) << 24) | ((x & 0x0000FF00) << 8) | ((x & 0x00FF0000) >> 8) |
                            ((x & 0xFF000000) >> 24));
   } else if constexpr(sizeof(T) == 8) {
      uint32_t hi = static_cast<uint32_t>(x >> 32);
      uint32_t lo = static_cast<uint32_t>(x);

      hi = reverse_bytes(hi);
      lo = reverse_bytes(lo);

      return (static_cast<T>(lo) << 32) | hi;
   }
}

// void* allocate_memory(size_t elems, size_t elem_size) {
//    if(elems == 0 || elem_size == 0) {
//       return nullptr;
//    }

//    void* ptr = std::calloc(elems, elem_size);  // NOLINT(*-no-malloc,*-owning-memory)

//    return ptr;
// }

// void secure_scrub_memory(void* ptr, size_t n) {
//    /*
//    * Call memset through a static volatile pointer, which the compiler should
//    * not elide. This construct should be safe in conforming compilers, but who
//    * knows. This has been checked to generate the expected code, which saves the
//    * memset address in the data segment and unconditionally loads and jumps to
//    * that address, with the following targets:
//    *
//    * x86-64: Clang 19, GCC 6, 11, 13, 14
//    * riscv64: GCC 14
//    * aarch64: GCC 14
//    * armv7: GCC 14
//    *
//    * Actually all of them generated the expected jump even without marking the
//    * function pointer as volatile. However this seems worth including as an
//    * additional precaution.
//    */
//    static void* (*const volatile memset_ptr)(void*, int, size_t) = std::memset;
//    (memset_ptr)(ptr, 0, n);
// }

// void deallocate_memory(void* p, size_t elems, size_t elem_size) {
//    if(p == nullptr) {
//       [[unlikely]] return;
//    }

//    secure_scrub_memory(p, elems * elem_size);

//    std::free(p);  // NOLINT(*-no-malloc,*-owning-memory)
// }

// void initialize_allocator() {
// #if defined(BOTAN_HAS_LOCKING_ALLOCATOR)
//    mlock_allocator::instance();
// #endif
// }


// template <typename T>
// class secure_allocator {

//    public:
//       typedef T value_type;
//       typedef std::size_t size_type;

//       secure_allocator() noexcept = default;
//       secure_allocator(const secure_allocator&) noexcept = default;
//       secure_allocator& operator=(const secure_allocator&) noexcept = default;
//       secure_allocator(secure_allocator&&) noexcept = default;
//       secure_allocator& operator=(secure_allocator&&) noexcept = default;

//       ~secure_allocator() noexcept = default;

//       template <typename U>
//       explicit secure_allocator(const secure_allocator<U>& /*other*/) noexcept {}

//       T* allocate(std::size_t n) { return static_cast<T*>(allocate_memory(n, sizeof(T))); }

//       void deallocate(T* p, std::size_t n) { deallocate_memory(p, n, sizeof(T)); }
// };

// template <typename T, typename U>
// inline bool operator==(const secure_allocator<T>& /*a*/, const secure_allocator<U>& /*b*/) {
//    return true;
// }

// template <typename T, typename U>
// inline bool operator!=(const secure_allocator<T>& /*a*/, const secure_allocator<U>& /*b*/) {
//    return false;
// }

// template <typename T>
// using secure_vector = std::vector<T, secure_allocator<T>>;

#define secure_vector std::vector

struct AutoDetect {
      constexpr AutoDetect() = delete;
};

#include <cstdint>
#include <cstddef>

inline void load_be(uint32_t* out, const uint8_t* in, size_t words) {
    for (size_t i = 0; i < words; ++i) {
        out[i] = (static_cast<uint32_t>(in[4 * i    ]) << 24) |
                 (static_cast<uint32_t>(in[4 * i + 1]) << 16) |
                 (static_cast<uint32_t>(in[4 * i + 2]) <<  8) |
                 (static_cast<uint32_t>(in[4 * i + 3])      );
    }
}

inline void copy_out_be(uint8_t* out, const uint32_t* in, size_t words) {
    for (size_t i = 0; i < words; ++i) {
        out[4 * i    ] = static_cast<uint8_t>(in[i] >> 24);
        out[4 * i + 1] = static_cast<uint8_t>(in[i] >> 16);
        out[4 * i + 2] = static_cast<uint8_t>(in[i] >>  8);
        out[4 * i + 3] = static_cast<uint8_t>(in[i]      );
    }
}


inline void bit_transpose(uint32_t B[8]) {
   swap_bits<uint32_t>(B[1], B[0], 0x55555555, 1);
   swap_bits<uint32_t>(B[3], B[2], 0x55555555, 1);
   swap_bits<uint32_t>(B[5], B[4], 0x55555555, 1);
   swap_bits<uint32_t>(B[7], B[6], 0x55555555, 1);

   swap_bits<uint32_t>(B[2], B[0], 0x33333333, 2);
   swap_bits<uint32_t>(B[3], B[1], 0x33333333, 2);
   swap_bits<uint32_t>(B[6], B[4], 0x33333333, 2);
   swap_bits<uint32_t>(B[7], B[5], 0x33333333, 2);

   swap_bits<uint32_t>(B[4], B[0], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[5], B[1], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[6], B[2], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[7], B[3], 0x0F0F0F0F, 4);
}

inline void ks_expand(uint32_t B[8], const uint32_t K[], size_t r) {
   /*
   This is bit_transpose of K[r..r+4] || K[r..r+4], we can save some computation
   due to knowing the first and second halves are the same data.
   */
   for(size_t i = 0; i != 4; ++i) {
      B[i] = K[r + i];
   }

   swap_bits<uint32_t>(B[1], B[0], 0x55555555, 1);
   swap_bits<uint32_t>(B[3], B[2], 0x55555555, 1);

   swap_bits<uint32_t>(B[2], B[0], 0x33333333, 2);
   swap_bits<uint32_t>(B[3], B[1], 0x33333333, 2);

   B[4] = B[0];
   B[5] = B[1];
   B[6] = B[2];
   B[7] = B[3];

   swap_bits<uint32_t>(B[4], B[0], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[5], B[1], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[6], B[2], 0x0F0F0F0F, 4);
   swap_bits<uint32_t>(B[7], B[3], 0x0F0F0F0F, 4);
}

inline void shift_rows(uint32_t B[8]) {
   // 3 0 1 2 7 4 5 6 10 11 8 9 14 15 12 13 17 18 19 16 21 22 23 20 24 25 26 27 28 29 30 31
  // if constexpr(HasNative64BitRegisters) {
  //    for(size_t i = 0; i != 8; i += 2) {
  //       uint64_t x = (static_cast<uint64_t>(B[i]) << 32) | B[i + 1];
  //       x = bit_permute_step<uint64_t>(x, 0x0022331100223311, 2);
  //       x = bit_permute_step<uint64_t>(x, 0x0055005500550055, 1);
  //       B[i] = static_cast<uint32_t>(x >> 32);
  //       B[i + 1] = static_cast<uint32_t>(x);
  //    }
  // } else {
      for(size_t i = 0; i != 8; ++i) {
         uint32_t x = B[i];
         x = bit_permute_step<uint32_t>(x, 0x00223311, 2);
         x = bit_permute_step<uint32_t>(x, 0x00550055, 1);
         B[i] = x;
      }
   //}
}

inline void inv_shift_rows(uint32_t B[8]) {
   // Inverse of shift_rows, just inverting the steps

  // if constexpr(HasNative64BitRegisters) {
  //    for(size_t i = 0; i != 8; i += 2) {
  //       uint64_t x = (static_cast<uint64_t>(B[i]) << 32) | B[i + 1];
  //       x = bit_permute_step<uint64_t>(x, 0x0055005500550055, 1);
  //       x = bit_permute_step<uint64_t>(x, 0x0022331100223311, 2);
  //       B[i] = static_cast<uint32_t>(x >> 32);
  //       B[i + 1] = static_cast<uint32_t>(x);
  //    }
  // } else {
      for(size_t i = 0; i != 8; ++i) {
         uint32_t x = B[i];
         x = bit_permute_step<uint32_t>(x, 0x00550055, 1);
         x = bit_permute_step<uint32_t>(x, 0x00223311, 2);
         B[i] = x;
      }
   //}
}

inline void mix_columns(uint32_t B[8]) {
   // carry high bits in B[0] to positions in 0x1b == 0b11011
   const uint32_t X2[8] = {
      B[1],
      B[2],
      B[3],
      B[4] ^ B[0],
      B[5] ^ B[0],
      B[6],
      B[7] ^ B[0],
      B[0],
   };

   for(size_t i = 0; i != 8; i++) {
      const uint32_t X3 = B[i] ^ X2[i];
      B[i] = X2[i] ^ rotr<8>(B[i]) ^ rotr<16>(B[i]) ^ rotr<24>(X3);
   }
}

void inv_mix_columns(uint32_t B[8]) {
   /*
   OpenSSL's bsaes implementation credits Jussi Kivilinna with the lovely
   matrix decomposition

   | 0e 0b 0d 09 |   | 02 03 01 01 |   | 05 00 04 00 |
   | 09 0e 0b 0d | = | 01 02 03 01 | x | 00 05 00 04 |
   | 0d 09 0e 0b |   | 01 01 02 03 |   | 04 00 05 00 |
   | 0b 0d 09 0e |   | 03 01 01 02 |   | 00 04 00 05 |

   Notice the first component is simply the MixColumns matrix. So we can
   multiply first by (05,00,04,00) then perform MixColumns to get the equivalent
   of InvMixColumn.
   */
   const uint32_t X4[8] = {
      B[2],
      B[3],
      B[4] ^ B[0],
      B[5] ^ B[0] ^ B[1],
      B[6] ^ B[1],
      B[7] ^ B[0],
      B[0] ^ B[1],
      B[1],
   };

   for(size_t i = 0; i != 8; i++) {
      const uint32_t X5 = X4[i] ^ B[i];
      B[i] = X5 ^ rotr<16>(X4[i]);
   }

   mix_columns(B);
}

/*
* AES Encryption
*/
void aes_encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, const secure_vector<uint32_t>& EK) {
   const size_t rounds = (EK.size() - 4) / 4;

   uint32_t KS[13 * 8] = {0};  // actual maximum is (rounds - 1) * 8
   for(size_t i = 0; i < rounds - 1; i += 1) {
      ks_expand(&KS[8 * i], EK.data(), 4 * i + 4);
   }

   const size_t BLOCK_SIZE = 16;
   const size_t BITSLICED_BLOCKS = 8 * sizeof(uint32_t) / BLOCK_SIZE;

   while(blocks > 0) {
      const size_t this_loop = std::min(blocks, BITSLICED_BLOCKS);

      uint32_t B[8] = {0};

      load_be(B, in, this_loop * 4);

      CT::poison(B, 8);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= EK[i % 4];
      }

      bit_transpose(B);

      for(size_t r = 0; r != rounds - 1; ++r) {
         AES_SBOX(B);
         shift_rows(B);
         mix_columns(B);

         for(size_t i = 0; i != 8; ++i) {
            B[i] ^= KS[8 * r + i];
         }
      }

      // Final round:
      AES_SBOX(B);
      shift_rows(B);
      bit_transpose(B);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= EK[4 * rounds + i % 4];
      }

      CT::unpoison(B, 8);
      copy_out_be(out, B, this_loop * 4);

      // copy_out_be(std::span(out, this_loop * 4 * sizeof(uint32_t)), B);

      in += this_loop * BLOCK_SIZE;
      out += this_loop * BLOCK_SIZE;
      blocks -= this_loop;
   }
}

/*
* AES Decryption
*/
void aes_decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks, const secure_vector<uint32_t>& DK) {
   const size_t rounds = (DK.size() - 4) / 4;

   uint32_t KS[13 * 8] = {0};  // actual maximum is (rounds - 1) * 8
   for(size_t i = 0; i < rounds - 1; i += 1) {
      ks_expand(&KS[8 * i], DK.data(), 4 * i + 4);
   }

   const size_t BLOCK_SIZE = 16;
   const size_t BITSLICED_BLOCKS = 8 * sizeof(uint32_t) / BLOCK_SIZE;

   while(blocks > 0) {
      const size_t this_loop = std::min(blocks, BITSLICED_BLOCKS);

      uint32_t B[8] = {0};

      CT::poison(B, 8);

      load_be(B, in, this_loop * 4);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= DK[i % 4];
      }

      bit_transpose(B);

      for(size_t r = 0; r != rounds - 1; ++r) {
         AES_INV_SBOX(B);
         inv_shift_rows(B);
         inv_mix_columns(B);

         for(size_t i = 0; i != 8; ++i) {
            B[i] ^= KS[8 * r + i];
         }
      }

      // Final round:
      AES_INV_SBOX(B);
      inv_shift_rows(B);
      bit_transpose(B);

      for(size_t i = 0; i != 8; ++i) {
         B[i] ^= DK[4 * rounds + i % 4];
      }

      CT::unpoison(B, 8);

      copy_out_be(out, B, this_loop * 4);

      // copy_out_be(std::span(out, this_loop * 4 * sizeof(uint32_t)), B);

      in += this_loop * BLOCK_SIZE;
      out += this_loop * BLOCK_SIZE;
      blocks -= this_loop;
   }
}

inline uint32_t xtime32(uint32_t s) {
   const uint32_t lo_bit = 0x01010101;
   const uint32_t mask = 0x7F7F7F7F;
   const uint32_t poly = 0x1B;

   return ((s & mask) << 1) ^ (((s >> 7) & lo_bit) * poly);
}

inline uint32_t InvMixColumn(uint32_t s1) {
   const uint32_t s2 = xtime32(s1);
   const uint32_t s4 = xtime32(s2);
   const uint32_t s8 = xtime32(s4);
   const uint32_t s9 = s8 ^ s1;
   const uint32_t s11 = s9 ^ s2;
   const uint32_t s13 = s9 ^ s4;
   const uint32_t s14 = s8 ^ s4 ^ s2;

   return s14 ^ rotr<8>(s9) ^ rotr<16>(s13) ^ rotr<24>(s11);
}

void InvMixColumn_x4(uint32_t x[4]) {
   x[0] = InvMixColumn(x[0]);
   x[1] = InvMixColumn(x[1]);
   x[2] = InvMixColumn(x[2]);
   x[3] = InvMixColumn(x[3]);
}

uint32_t SE_word(uint32_t x) {
   uint32_t I[8] = {0};

   for(size_t i = 0; i != 8; ++i) {
      I[i] = (x >> (7 - i)) & 0x01010101;
   }

   AES_SBOX(I);

   x = 0;

   for(size_t i = 0; i != 8; ++i) {
      x |= ((I[i] & 0x01010101) << (7 - i));
   }

   return x;
}

void aes_key_schedule(const uint8_t key[],
                      size_t length,
                      secure_vector<uint32_t>& EK,
                      secure_vector<uint32_t>& DK,
                      bool bswap_keys = false) {
   static const uint32_t RC[10] = {0x01000000,
                                   0x02000000,
                                   0x04000000,
                                   0x08000000,
                                   0x10000000,
                                   0x20000000,
                                   0x40000000,
                                   0x80000000,
                                   0x1B000000,
                                   0x36000000};

   const size_t X = length / 4;
   const size_t rounds = (length / 4) + 6;
   CT::poison(key, length);

   const size_t KS_len = length + 28;
   EK.resize(KS_len);
   DK.resize(KS_len);

   load_be(EK.data(), key, X);


   //for(size_t i = 0; i != X; ++i) {
   //   EK[i] = load_be<uint32_t>(key, i);
   //}

   for(size_t i = X; i < 4 * (rounds + 1); i += X) {
      EK[i] = EK[i - X] ^ RC[(i - X) / X] ^ rotl<8>(SE_word(EK[i - 1]));

      for(size_t j = 1; j != X && (i + j) < EK.size(); ++j) {
         EK[i + j] = EK[i + j - X];

         if(X == 8 && j == 4) {
            EK[i + j] ^= SE_word(EK[i + j - 1]);
         } else {
            EK[i + j] ^= EK[i + j - 1];
         }
      }
   }

   for(size_t i = 0; i != 4 * (rounds + 1); i += 4) {
      DK[i] = EK[4 * rounds - i];
      DK[i + 1] = EK[4 * rounds - i + 1];
      DK[i + 2] = EK[4 * rounds - i + 2];
      DK[i + 3] = EK[4 * rounds - i + 3];
   }

   for(size_t i = 4; i != 4 * rounds; i += 4) {
      InvMixColumn_x4(&DK[i]);
   }

   if(bswap_keys) {
      // HW AES on little endian needs the subkeys to be byte reversed
      for(size_t i = 0; i != KS_len; ++i) {
         EK[i] = reverse_bytes(EK[i]);
         DK[i] = reverse_bytes(DK[i]);
      }
   }

   CT::unpoison(EK.data(), EK.size());
   CT::unpoison(DK.data(), DK.size());
   CT::unpoison(key, length);
}

size_t aes_parallelism() {
   // bitsliced:
   return 2;
}

std::string aes_provider() {
   return "base";
}

}  // namespace

/*

std::string AES_128::provider() const {
   return aes_provider();
}

std::string AES_192::provider() const {
   return aes_provider();
}

std::string AES_256::provider() const {
   return aes_provider();
}

size_t AES_128::parallelism() const {
   return aes_parallelism();
}

size_t AES_192::parallelism() const {
   return aes_parallelism();
}

size_t AES_256::parallelism() const {
   return aes_parallelism();
}

bool AES_128::has_keying_material() const {
   return !m_EK.empty();
}

bool AES_192::has_keying_material() const {
   return !m_EK.empty();
}

bool AES_256::has_keying_material() const {
   return !m_EK.empty();
}

void AES_128::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();
   aes_encrypt_n(in, out, blocks, m_EK);
}

void AES_128::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();
   aes_decrypt_n(in, out, blocks, m_DK);
}

void AES_128::key_schedule(std::span<const uint8_t> key) {
   aes_key_schedule(key.data(), key.size(), m_EK, m_DK);
}

void AES_128::clear() {
   zap(m_EK);
   zap(m_DK);
}

void AES_192::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   aes_encrypt_n(in, out, blocks, m_EK);
}

void AES_192::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();
   aes_decrypt_n(in, out, blocks, m_DK);
}

void AES_192::key_schedule(std::span<const uint8_t> key) {
   aes_key_schedule(key.data(), key.size(), m_EK, m_DK);
}

void AES_192::clear() {
   zap(m_EK);
   zap(m_DK);
}

void AES_256::encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();
   aes_encrypt_n(in, out, blocks, m_EK);
}

void AES_256::decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const {
   assert_key_material_set();

   aes_decrypt_n(in, out, blocks, m_DK);
}

void AES_256::key_schedule(std::span<const uint8_t> key) {
   aes_key_schedule(key.data(), key.size(), m_EK, m_DK);
}

void AES_256::clear() {
   zap(m_EK);
   zap(m_DK);
}
   */

}  // namespace Botan

using namespace Botan;

// ---------------------------------------------------------------------------
// Direct wrappers: expose bitsliced functions with external linkage so they
// can be called from bench_aes.cpp. Accessible here because we're in the
// same TU as the anonymous-namespace definitions (after `using namespace Botan`).
// ---------------------------------------------------------------------------
#ifdef BENCH_DIRECT
namespace BitslicedDirect {
    void key_schedule(const uint8_t* key, size_t len,
                      std::vector<uint32_t>& EK, std::vector<uint32_t>& DK) {
        aes_key_schedule(key, len, EK, DK);
    }
    void encrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
                   const std::vector<uint32_t>& EK) {
        aes_encrypt_n(in, out, blocks, EK);
    }
    void decrypt_n(const uint8_t* in, uint8_t* out, size_t blocks,
                   const std::vector<uint32_t>& DK) {
        aes_decrypt_n(in, out, blocks, DK);
    }
}
#endif

#include <iostream>

using namespace std;

#ifndef BENCH_DIRECT

void print_hex(const std::string& label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; ++i)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    std::cout << std::dec << "\n";
}

// Проверяет шифрование и дешифрование одного блока, выводит результат
bool check_block(const char* label,
                 const uint8_t* key, size_t key_len,
                 const uint8_t* pt, const uint8_t* expected_ct) {
    std::vector<uint32_t> EK, DK;
    aes_key_schedule(key, key_len, EK, DK);

    uint8_t ct[16] = {}, dt[16] = {};
    aes_encrypt_n(pt, ct, 1, EK);
    aes_decrypt_n(ct, dt, 1, DK);

    bool enc_ok = std::memcmp(ct, expected_ct, 16) == 0;
    bool dec_ok = std::memcmp(dt, pt,          16) == 0;

    std::cout << label << "\n";
    print_hex("  Got      ", ct, 16);
    print_hex("  Expected ", expected_ct, 16);
    print_hex("  Decrypted", dt, 16);
    std::cout << "  Encrypt: " << (enc_ok ? "OK" : "FAIL")
              << "  Decrypt: " << (dec_ok ? "OK" : "FAIL") << "\n\n";
    return enc_ok && dec_ok;
}

// Печатает EK (раундовые ключи) и сравнивает с эталоном
void check_key_expansion(const char* label,
                         const uint8_t* key, size_t key_len,
                         const uint32_t* expected_ek, size_t ek_words) {
    std::vector<uint32_t> EK, DK;
    aes_key_schedule(key, key_len, EK, DK);

    std::cout << label << "\n";
    bool all_ok = true;
    for (size_t i = 0; i < ek_words; ++i) {
        bool ok = (EK[i] == expected_ek[i]);
        if (!ok) all_ok = false;
        std::cout << "  w[" << std::setw(2) << i << "] = "
                  << std::hex << std::setw(8) << std::setfill('0') << EK[i]
                  << "  expected " << std::setw(8) << std::setfill('0') << expected_ek[i]
                  << (ok ? "" : "  <-- MISMATCH") << "\n";
    }
    std::cout << std::dec;
    std::cout << "  Key expansion: " << (all_ok ? "OK" : "FAIL") << "\n\n";
}

int main() {
    int failures = 0;

    // ------------------------------------------------------------------
    // TEST 1: FIPS-197 Appendix C.1 — AES-128
    // ------------------------------------------------------------------
    {
        const uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                               0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        const uint8_t pt[]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        const uint8_t exp[] = {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
                               0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
        if (!check_block("=== TEST 1: FIPS-197 Appendix C.1 (AES-128) ===",
                         key, 16, pt, exp)) ++failures;
    }

    // ------------------------------------------------------------------
    // TEST 2: FIPS-197 Appendix C.2 — AES-192
    // ------------------------------------------------------------------
    {
        const uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                               0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                               0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
        const uint8_t pt[]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        const uint8_t exp[] = {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,
                               0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91};
        if (!check_block("=== TEST 2: FIPS-197 Appendix C.2 (AES-192) ===",
                         key, 24, pt, exp)) ++failures;
    }

    // ------------------------------------------------------------------
    // TEST 3: FIPS-197 Appendix C.3 — AES-256
    // (это также "учебный пример из документации Botan": src/examples/aes.cpp,
    //  первое шифрование — тот же ключ и открытый текст)
    // ------------------------------------------------------------------
    {
        const uint8_t key[] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                               0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                               0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                               0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
        const uint8_t pt[]  = {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                               0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
        // FIPS-197 C.3 == Botan src/examples/aes.cpp первый вывод
        const uint8_t exp[] = {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
                               0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
        if (!check_block("=== TEST 3: FIPS-197 Appendix C.3 / Botan examples/aes.cpp (AES-256) ===",
                         key, 32, pt, exp)) ++failures;
    }

    // ------------------------------------------------------------------
    // TEST 4: FIPS-197 Appendix B — AES-128 (другой ключ)
    // ------------------------------------------------------------------
    {
        const uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                               0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        const uint8_t pt[]  = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                               0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
        const uint8_t exp[] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                               0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
        if (!check_block("=== TEST 4: FIPS-197 Appendix B (AES-128) ===",
                         key, 16, pt, exp)) ++failures;
    }

    // ------------------------------------------------------------------
    // TEST 5: Botan aes.vec NIST CAVP — несколько векторов AES-128
    // Источник: botan/src/tests/data/block/aes.vec
    // ------------------------------------------------------------------
    {
        struct Vec { uint8_t key[16]; uint8_t pt[16]; uint8_t ct[16]; };
        const Vec vecs[] = {
            { {0x00,0x01,0x02,0x03,0x05,0x06,0x07,0x08,0x0a,0x0b,0x0c,0x0d,0x0f,0x10,0x11,0x12},
              {0x50,0x68,0x12,0xa4,0x5f,0x08,0xc8,0x89,0xb9,0x7f,0x59,0x80,0x03,0x8b,0x83,0x59},
              {0xd8,0xf5,0x32,0x53,0x82,0x89,0xef,0x7d,0x06,0xb5,0x06,0xa4,0xfd,0x5b,0xe9,0xc9} },
            { {0x14,0x15,0x16,0x17,0x19,0x1a,0x1b,0x1c,0x1e,0x1f,0x20,0x21,0x23,0x24,0x25,0x26},
              {0x5c,0x6d,0x71,0xca,0x30,0xde,0x8b,0x8b,0x00,0x54,0x99,0x84,0xd2,0xec,0x7d,0x4b},
              {0x59,0xab,0x30,0xf4,0xd4,0xee,0x6e,0x4f,0xf9,0x90,0x7e,0xf6,0x5b,0x1f,0xb6,0x8c} },
            { {0x28,0x29,0x2a,0x2b,0x2d,0x2e,0x2f,0x30,0x32,0x33,0x34,0x35,0x37,0x38,0x39,0x3a},
              {0x53,0xf3,0xf4,0xc6,0x4f,0x86,0x16,0xe4,0xe7,0xc5,0x61,0x99,0xf4,0x8f,0x21,0xf6},
              {0xbf,0x1e,0xd2,0xfc,0xb2,0xaf,0x3f,0xd4,0x14,0x43,0xb5,0x6d,0x85,0x02,0x5c,0xb1} },
        };
        std::cout << "=== TEST 5: Botan aes.vec (NIST CAVP, AES-128) ===\n";
        bool all_ok = true;
        for (size_t i = 0; i < 3; ++i) {
            std::vector<uint32_t> EK, DK;
            aes_key_schedule(vecs[i].key, 16, EK, DK);
            uint8_t ct[16] = {}, dt[16] = {};
            aes_encrypt_n(vecs[i].pt, ct, 1, EK);
            aes_decrypt_n(ct, dt, 1, DK);
            bool enc_ok = std::memcmp(ct, vecs[i].ct, 16) == 0;
            bool dec_ok = std::memcmp(dt, vecs[i].pt,  16) == 0;
            if (!enc_ok || !dec_ok) { all_ok = false; ++failures; }
            std::cout << "  vec[" << i << "]: encrypt=" << (enc_ok?"OK":"FAIL")
                      << " decrypt=" << (dec_ok?"OK":"FAIL") << "\n";
        }
        std::cout << "  Overall: " << (all_ok ? "OK" : "FAIL") << "\n\n";
    }

    // ------------------------------------------------------------------
    // TEST 6: Key expansion — FIPS-197 Appendix A.1 (AES-128)
    // Ключ: 2b7e151628aed2a6abf7158809cf4f3c  →  w[0..43]
    // ------------------------------------------------------------------
    {
        const uint8_t key[] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                               0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        // FIPS-197 Table 11 (Appendix A.1)
        const uint32_t expected_ek[44] = {
            0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c,
            0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605,
            0xf2c295f2, 0x7a96b943, 0x5935807a, 0x7359f67f,
            0x3d80477d, 0x4716fe3e, 0x1e237e44, 0x6d7a883b,
            0xef44a541, 0xa8525b7f, 0xb671253b, 0xdb0bad00,
            0xd4d1c6f8, 0x7c839d87, 0xcaf2b8bc, 0x11f915bc,
            0x6d88a37a, 0x110b3efd, 0xdbf98641, 0xca0093fd,
            0x4e54f70e, 0x5f5fc9f3, 0x84a64fb2, 0x4ea6dc4f,
            0xead27321, 0xb58dbad2, 0x312bf560, 0x7f8d292f,
            0xac7766f3, 0x19fadc21, 0x28d12941, 0x575c006e,
            0xd014f9a8, 0xc9ee2589, 0xe13f0cc8, 0xb6630ca6,
        };
        check_key_expansion(
            "=== TEST 6: Key Expansion — FIPS-197 Appendix A.1 (AES-128) ===",
            key, 16, expected_ek, 44);
    }

    // ------------------------------------------------------------------
    // Итог
    // ------------------------------------------------------------------
    std::cout << "==========================================\n";
    if (failures == 0)
        std::cout << "ALL TESTS PASSED\n";
    else
        std::cout << failures << " TEST(S) FAILED\n";
    std::cout << "==========================================\n";
    return failures;
}

#endif // BENCH_DIRECT