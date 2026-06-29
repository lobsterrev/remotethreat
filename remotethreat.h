#pragma once
#include "rt_threadex.h"
#include "rt_apc.h"
#include "rt_hijack.h"
#include "rt_asm.h"
#include "rt_pici.h"

#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
    #error RemoteThreat only supports x86 and x64 systems.
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RT_Method {
    RT_NtCreateThread,
    RT_Hijack,
    RT_APC,
    RT_ProcessInformationCallback
} RT_Method;

// Tracks a remote execution request created by RT_Create.
// For stub-based methods (APC / Hijack / PICI) completion is detected by reading
// the flag byte at the start of the remote stub allocation.
// For NtCreateThread, completion is detected via the thread's signaled state.
// Memory ownership:
//   - hProcess is non-owning (the caller owns it)
//   - stub is intentionally leaked (the target may execute it asynchronously;
//     freeing it before then would crash the target)
//   - hThread is owned: callers must call RT_Close to release it
typedef struct RT_Execution {
    HANDLE hProcess; // non-owning
    LPVOID stub;     // remote allocation; intentionally leaked
    HANDLE hThread;  // owned (NtCreateThread path only); NULL for other methods
    int    valid;
} RT_Execution;

static RT_Execution RT_Create(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, RT_Method method) {
    RT_Execution e;
    LPVOID stub = NULL;
    HANDLE hThread = NULL;

    e.hProcess = hProcess;
    e.stub = NULL;
    e.hThread = NULL;
    e.valid = 0;

    switch (method) {
        case RT_APC:
            QueueAPC(hProcess, startAddress, lParam, &stub);
            break;
        case RT_ProcessInformationCallback:
            SetProcessCallback(hProcess, startAddress, lParam, &stub);
            break;
        case RT_Hijack: {
            // HijackThread returns a handle to the hijacked thread, but completion
            // is tracked via the stub flag, so discard it.
            HANDLE hHijacked = HijackThread(hProcess, startAddress, lParam, &stub);
            if (hHijacked && hHijacked != INVALID_HANDLE_VALUE)
                CloseHandle(hHijacked);
            break;
        }
        case RT_NtCreateThread: {
            HANDLE h = NtCreateThreadEx(hProcess, (LPTHREAD_START_ROUTINE)startAddress, lParam);
            if (h != INVALID_HANDLE_VALUE) hThread = h;
            break;
        }
    }

    if (stub || hThread) {
        e.stub = stub;
        e.hThread = hThread;
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
    if (e->hThread) return WaitForSingleObject(e->hThread, 0) == WAIT_OBJECT_0;
    ReadProcessMemory(e->hProcess, e->stub, &flag, 1, NULL);
    return flag != 0;
}

// Blocks until the injected code has run, or until timeoutMs elapses.
// Returns nonzero on completion, 0 on timeout / invalid execution.
static int RT_Wait(const RT_Execution* e, DWORD timeoutMs) {
    ULONGLONG start;
    if (!e || !e->valid) return 0;
    if (e->hThread) return WaitForSingleObject(e->hThread, timeoutMs) == WAIT_OBJECT_0;
    start = GetTickCount64();
    while (!RT_IsDone(e)) {
        if (timeoutMs != INFINITE && GetTickCount64() - start >= timeoutMs)
            return 0;
        Sleep(1);
    }
    return 1;
}

// Releases the thread handle owned by an RT_Execution (NtCreateThread path).
// Does NOT free the remote stub allocation — see note on RT_Execution.
// Safe to call multiple times.
static void RT_Close(RT_Execution* e) {
    if (!e) return;
    if (e->hThread) { CloseHandle(e->hThread); e->hThread = NULL; }
    e->valid = 0;
}

#ifdef __cplusplus
}
#endif