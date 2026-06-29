# RemoteThreat

Header-only C library for remote code injection without the creation of threads on Windows (x86/x64), with WOW64 cross-architecture support.

Callable from C11 and later, and directly from C++ (the header is fully `extern "C"` guarded).

## Methods

| Method | Description |
|---|---|
| `RT_Hijack` | Suspends an existing thread, redirects execution via context hijack |
| `RT_APC` | Queues a special user APC via `NtQueueApcThreadEx2` |
| `RT_ProcessInformationCallback` | Installs a process instrumentation callback (PICI), fires on next syscall return |

### Target architecture support

The rows are the **injector** build; the columns are the **target** process.

| Method | x64 → x64 | x64 → x86 (WoW64) | x86 → x86 |
|---|:---:|:---:|:---:|
| `RT_Hijack` | ✅ | ✅ | ✅ |
| `RT_APC` | ✅ | ✅ | ✅ |
| `RT_ProcessInformationCallback` | ✅ | ⚠️ | ❌ |

> **PICI / x64→x86 (⚠️)**: Requires `SeSystemEnvironmentPrivilege`, which is only present in a SYSTEM-level token. Not usable from a normal administrator process.
>
> **x86 injector → x64 target**: Not supported by any method — a 32-bit process cannot obtain `PROCESS_ALL_ACCESS` on a 64-bit process.

## Usage (C)

```c
#include "remotethreat.h"

HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

RemoteThreat exec = CreateRemoteThreat(hProcess, startAddress, lParam, RT_Hijack);
if (!RT_IsValid(&exec)) { /* handle failure */ }

RT_Wait(&exec, INFINITE);   // block until the remote code has run
RT_Close(&exec);            // mark execution as invalid
```

`RT_Create` returns a `RemoteThreat` struct. The remote stub allocation is intentionally not freed by `RT_Close` — the target process may still execute it asynchronously. Free it with `VirtualFreeEx` once you are certain execution has completed.

### Polling instead of blocking

```c
while (!RT_IsDone(&exec))
    Sleep(10);
RT_Close(&exec);
```

## Requirements

- Windows x86 or x64
- Run as administrator when targeting privileged processes
- C11 or later (C++ callers: include `remotethreat.h` directly)

## License

[MIT](LICENSE)
