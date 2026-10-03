# Payload blobs

These are the two aarch64 shellcode blobs checkm8 uploads into the bootrom.
They are **not** written by us and they are **not** compiled here.

## Provenance

| File | Source | Licence |
|---|---|---|
| `payload_A9.bin` | [gaster](https://github.com/0x7ff/gaster) by 0x7ff | Apache-2.0 |
| `payload_handle_checkm8_request.bin` | same | Apache-2.0 |

Apache-2.0 permits redistribution and modification provided the licence and
attribution are preserved. See the repository `LICENSE` and `NOTICE`.

SHA-256, so a swapped blob cannot go unnoticed:

```
A698045FAE09ACDC5BFAFC26EF3FE7848F1454B8CE8847FDC45396CC18A532B2  payload_A9.bin                      280 bytes
C0C213047A8902186392396CB7E57C096626B4812B61E07C2CF7CF6B99A9889C  payload_handle_checkm8_request.bin  248 bytes
```

## Layout, and why the sizes matter

Both blobs are `machine code || literal pool`, and the literal pool is a
**placeholder** that gets thrown away and rebuilt at runtime:

```
payload_A9.bin                       280 bytes
  0x000 - 0x0AF   code               176 bytes
  0x0B0 - 0x0BF   " PWND:[checkm8]\0"  16 bytes  <- this IS the struct's pwnd field
  0x0C0 - 0x117   11 x u64            88 bytes  <- placeholder pool, 0x7FFFFFF0..0x7FFFFFFA

payload_handle_checkm8_request.bin   248 bytes
  0x000 - 0x0BF   code               192 bytes
  0x0C0 - 0x0F7   7 x u64             56 bytes  <- placeholder pool, 0x7FFFFFF0..0x7FFFFFF6
```

The `ldr x0, =payload_dest` style instructions in the assembly are PC-relative
loads out of that pool. The pool holds nonsense addresses (`0x7FFFFFF0`) purely
so the assembler has something to encode. At runtime the pool is replaced by a
real struct of the same byte length, so every load resolves to a real field.

That is why `sizeof(A9) == 104` and `sizeof(handle_checkm8_request) == 56` are
load-bearing constants rather than trivia: get one wrong and the appended struct
lands at the wrong offset, every PC-relative load reads the wrong field, and the
payload jumps somewhere invalid. Both are asserted in `src/checkm8.rs` against
the blob lengths, and they were confirmed by decoding the actual instructions
(`0x580005e0` at offset `0x04` is `LDR X0, [PC, #188]`, which lands on `0xC0`).

## Licence note

The assembly sources live in the research tree, not here. Only the compiled
blobs are vendored, because their exact bytes are what the exploit depends on
and rebuilding them needs an aarch64 assembler this project does not ship.
