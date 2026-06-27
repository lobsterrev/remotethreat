# RemoteThreat

Header-only C++ library for remote thread injection on Windows (x86/x64), with WOW64 cross-architecture support.

## Methods

| Method | Description |
|---|---|
| `RT::NtCreateThread` | Creates a new remote thread via `NtCreateThreadEx` |
| `RT::Hijack` | Suspends an existing thread, redirects execution via context hijack |
| `RT::APC` | Queues a special user APC via `NtQueueApcThreadEx2` |
| `RT::ProcessInformationCallback` | Installs a process instrumentation callback (PICI), fires on next syscall return |

## Usage

```cpp
#include "remotethreat.h"

HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

LPVOID remoteStub = nullptr;
HANDLE hThread = RT::Create(hProcess, startAddress, lParam, RT::Hijack, &remoteStub);

// Free the remote stub once you know execution has completed
if (remoteStub)
    VirtualFreeEx(hProcess, remoteStub, 0, MEM_RELEASE);
```

`outRemoteStub` is optional — pass `nullptr` if you don't need to free the stub manually.

## Requirements

- Windows x86 or x64
- Run as administrator when targeting privileged processes
- C++11 or later

## License

[MIT](LICENSE)
