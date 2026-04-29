# Бенчмарки AES

## Сборка

```bash
make bench_aes   # бенчмарк
make main        # тесты (задание 2)
make all         # оба
```

## Запуск

```bash
# ARMv8 hardware AES (vaeseq_u8 / vaesmcq_u8) — дефолт на M1
make run-armv8

# VPERM / NEON (vector permute, Mike Hamburg CHES 2009)
make run-vperm

# Bitsliced (скалярный, 2 блока параллельно)
make run-bitsliced

# Сравнение my-aes.cpp с Botan bitsliced (оба base бэкенд, один прогон)
make run-compare

# Все три подряд
make run-all
```

## Как работает переключение бэкендов

Botan читает `BOTAN_CLEAR_CPUID` при старте и вычёркивает указанные фичи из детектированного CPUID.
Бинарник один и тот же — меняется только окружение.

```
(ничего)               → armv8aes  (HW AES)
BOTAN_CLEAR_CPUID=armv8aes          → neon     (VPERM)
BOTAN_CLEAR_CPUID=armv8aes,neon     → base     (bitsliced)
```

## Что измеряется

| Бенчмарк | Описание |
|----------|----------|
| `BM_Botan_Encrypt/N` | Шифрование N блоков через `BlockCipher` API Botan |
| `BM_Botan_Decrypt/N` | Дешифрование N блоков через `BlockCipher` API Botan |
| `BM_Botan_KeySchedule` | Только `set_key()` (развёртка ключа) |
| `BM_Direct_Encrypt/N` | Шифрование напрямую через функции из `my-aes.cpp` (без class hierarchy) |
| `BM_Direct_Decrypt/N` | То же для дешифрования |
| `BM_Direct_KeySchedule` | То же для развёртки ключа |

N = 1 (латентность), 2 (нативный параллелизм bitsliced), 4 (нативный параллелизм HW AES), 64, 1024 (пропускная способность).
