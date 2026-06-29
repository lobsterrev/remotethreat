# RemoteThreat

Header-only C library for remote thread injection on Windows (x86/x64), with WOW64 cross-architecture support.

Callable from C11 and later, or from C++ via the bundled `remotethreat.hpp` wrapper which restores a RAII `RT::Execution` class.

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

RT_Execution exec = RT_Create(hProcess, startAddress, lParam, RT_Hijack);
if (!RT_IsValid(&exec)) { /* handle failure */ }

RT_Wait(&exec, INFINITE);   // block until the remote code has run
RT_Close(&exec);            // mark execution as invalid
```

`RT_Create` returns an `RT_Execution` struct. The remote stub allocation is intentionally not freed by `RT_Close` — the target process may still execute it asynchronously. Free it with `VirtualFreeEx` once you are certain execution has completed.

### Polling instead of blocking

```c
while (!RT_IsDone(&exec))
    Sleep(10);
RT_Close(&exec);
```

## Usage (C++ wrapper)

```cpp
#include "remotethreat.hpp"  // optional RAII wrapper

HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

RT::Execution exec = RT::Create(hProcess, startAddress, lParam, RT::Hijack);
if (!exec) { /* handle failure */ }

exec.Wait();    // blocks until completion; RT_Close called automatically on destruction
```

## Requirements

- Windows x86 or x64
- Run as administrator when targeting privileged processes
- C11 or later (C++ callers: C++11 or later via `remotethreat.hpp`)

## License

[MIT](LICENSE)
