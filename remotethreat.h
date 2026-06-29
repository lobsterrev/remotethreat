#pragma once
#include "rt_apc.h"
#include "rt_hijack.h"
#include "rt_pici.h"

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
    #error RemoteThreat only supports x86 and x64 systems.
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RT_Method {
    RT_Hijack,
    RT_APC,
    RT_PICI
} RT_Method;

// Tracks a remote execution request created by RT_Create.
// Completion is detected by reading the flag byte at the start of the remote
// stub allocation (set by the stub when the payload returns).
// Memory ownership:
//   - hProcess is non-owning (the caller owns it)
//   - stub is intentionally leaked (the target may still execute it
//     asynchronously; freeing it before then would crash the target)
typedef struct RT_Execution {
    HANDLE hProcess; // non-owning
    LPVOID stub;     // remote allocation; intentionally leaked
    int    valid;
} RT_Execution;

static RT_Execution RT_Create(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, RT_Method method) {
    RT_Execution e;
    LPVOID stub = NULL;

    e.hProcess = hProcess;
    e.stub = NULL;
    e.valid = 0;

    switch (method) {
        case RT_APC:
            QueueAPC(hProcess, startAddress, lParam, &stub);
            break;
        case RT_PICI:
            SetProcessCallback(hProcess, startAddress, lParam, &stub);
            break;
        case RT_Hijack: {
            HANDLE hHijacked = HijackThread(hProcess, startAddress, lParam, &stub);
            if (hHijacked && hHijacked != INVALID_HANDLE_VALUE)
                CloseHandle(hHijacked);
            break;
        }
    }

    if (stub) {
        e.stub = stub;
        e.valid = 1;
    }
    return e;
}

static int RT_IsValid(const RT_Execution* e) {
    return e && e->valid;
}

// Non-blocking: returns nonzero once the injected code has run.
static int RT_IsDone(const RT_Execution* e) {
    BYTE flag = 0;
    if (!e || !e->valid) return 0;
    ReadProcessMemory(e->hProcess, e->stub, &flag, 1, NULL);
    return flag != 0;
}

// Blocks until the injected code has run, or until timeoutMs elapses.
// Returns nonzero on completion, 0 on timeout / invalid execution.
static int RT_Wait(const RT_Execution* e, DWORD timeoutMs) {
    ULONGLONG start;
    if (!e || !e->valid) return 0;
    start = GetTickCount64();
    while (!RT_IsDone(e)) {
        if (timeoutMs != INFINITE && GetTickCount64() - start >= timeoutMs)
            return 0;
        Sleep(1);
    }
    return 1;
}

// Marks the execution as closed. Safe to call multiple times.
// Does NOT free the remote stub allocation — see note on RT_Execution.
static void RT_Close(RT_Execution* e) {
    if (!e) return;
    e->valid = 0;
}

#ifdef __cplusplus
}
#endif