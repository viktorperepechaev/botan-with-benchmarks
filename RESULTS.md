# Результаты тестирования и бенчмарков AES-128

**Дата:** 2026-05-10
**CPU:** Intel Core i7-8650U @ 1.90 GHz (Kaby Lake-R, max 4.2 GHz, 8 threads)
**Кэш:** L1d 32 KiB ×4, L1i 32 KiB ×4, L2 256 KiB ×4, L3 8 MiB
**Компилятор:** GCC 15.2.1, `-O3 -fno-omit-frame-pointer -g`
**Условия:** `taskset -c 0`, `--benchmark_repetitions=5`
**Замечание:** `cpufreq governor = powersave` (не `performance`) — отсюда заметный шум (`cv` до ~10%).

---

## 1. Тесты корректности (FIPS-197 / NIST CAVP)

```
=== TEST 1: FIPS-197 Appendix C.1 (AES-128) ===     OK
=== TEST 2: FIPS-197 Appendix C.2 (AES-192) ===     OK
=== TEST 3: FIPS-197 Appendix C.3 (AES-256) ===     OK
=== TEST 4: FIPS-197 Appendix B   (AES-128) ===     OK
=== TEST 5: Botan aes.vec (NIST CAVP, AES-128) ===  3/3 OK
=== TEST 6: Key Expansion FIPS-197 A.1 (AES-128) ── OK (44/44 слов)

==========================================
ALL TESTS PASSED
==========================================
```

---

## 2. Бенчмарки

Три реализации:
- **Botan** — Botan `BlockCipher` API, бэкенд `aesni` (выбран автоматически)
- **Direct (bitsliced)** — наша `BitslicedDirect::*` из `my-aes.cpp` (constant-time, 2 блока параллельно)
- **AesNi (intrinsics)** — наша `AesNiDirect::*` из `my-aes-ni.cpp` (4 блока параллельно через `_mm_aesenc_si128`)

Все числа — **median** из 5 повторов.

### 2.1 Encrypt (median, throughput)

| N блоков | Botan         | Direct (bitsliced) | AesNi (наш)   |
|---------:|--------------:|-------------------:|--------------:|
|        1 | 38.7 ns       | 1550 ns            | **14.6 ns**   |
|        2 | 38.9 ns       | 1660 ns            | **21.0 ns**   |
|        4 | 51.5 ns       | 3075 ns            | **38.5 ns**   |
|       64 | 616 ns        | 45286 ns           | **616 ns**    |
|     1024 | 10303 ns      | 693023 ns          | **9725 ns**   |

**Throughput на 1024 блока (16 KB):**

| Реализация         | bytes/sec      | Относительно bitsliced |
|--------------------|---------------:|-----------------------:|
| Direct (bitsliced) | 22.8 Mi/s      | 1× (baseline)          |
| Botan (aesni)      | 1.49 Gi/s      | ~67×                   |
| **AesNi (наш)**    | **1.57 Gi/s**  | **~70×**               |

### 2.2 Decrypt (median, throughput)

| N блоков | Botan         | Direct (bitsliced) | AesNi (наш)   |
|---------:|--------------:|-------------------:|--------------:|
|        1 | 36.4 ns       | 1762 ns            | **14.5 ns**   |
|        2 | 35.1 ns       | 1715 ns            | **21.8 ns**   |
|        4 | 53.0 ns       | 3263 ns            | **37.6 ns**   |
|       64 | 609 ns        | 50328 ns           | **629 ns**    |
|     1024 | 9749 ns       | 779046 ns          | **9980 ns**   |

**Throughput на 1024 блока:**

| Реализация         | bytes/sec      |
|--------------------|---------------:|
| Direct (bitsliced) | 20.2 Mi/s      |
| Botan (aesni)      | 1.57 Gi/s      |
| AesNi (наш)        | 1.54 Gi/s      |

### 2.3 Key Schedule

| Реализация         | Время (median) |
|--------------------|---------------:|
| Direct (bitsliced) | 1603 ns        |
| Botan (aesni)      | 234 ns         |
| **AesNi (наш)**    | **170 ns**     |

---

## 3. Наблюдения

1. **AES-NI быстрее bitsliced в ~70 раз** на потоке 1024 блока. Это ожидаемо — одна `AESENC` инструкция выполняет работу всех S-box + ShiftRows + MixColumns за один cycle.

2. **На малых N (1 блок) наш AesNi быстрее Botan в ~2.6×** (14.6 ns vs 38.7 ns). Разница — overhead от `BlockCipher` virtual dispatch в Botan; на длинных потоках амортизируется и Botan догоняет.

3. **На N=1024 наш AesNi и Botan сравнимы** (9.7 vs 10.3 µs) — обе используют 4-block pipeline с теми же AES-NI инструкциями. ~5% разница в пределах шума (cv 1-6%).

4. **Bitsliced на 2 блоках практически не быстрее, чем на 1** (1660 vs 1550 ns) — нативный параллелизм работает: 2 блока обрабатываются за один проход через bit-transposed представление.

5. **Key schedule на AES-NI в ~9× быстрее bitsliced** (170 ns vs 1603 ns) благодаря инструкции `_mm_aeskeygenassist_si128` и `_mm_aesimc_si128`.

---

## 4. Шум измерений (cv = stddev/mean)

| Бенчмарк            | cv (Encrypt/1024) |
|---------------------|------------------:|
| Botan               | 6.36%             |
| Direct (bitsliced)  | 2.13%             |
| AesNi (наш)         | 1.50%             |

Шум выше у Botan скорее всего из-за вариативности cache-эффектов от virtual dispatch.
Для более стабильных чисел нужно `cpupower frequency-set -g performance` и отключить Turbo.
