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

typedef struct RemoteThreat {
    HANDLE hProcess; 
    LPVOID stub;     
    int    valid;
} RemoteThreat;

static RemoteThreat CreateRemoteThreat(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, RT_Method method) {
    RemoteThreat e;
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

static int RT_IsValid(const RemoteThreat* e) {
    return e && e->valid;
}

static int RT_IsDone(const RemoteThreat* e) {
    BYTE flag = 0;
    if (!e || !e->valid) return 0;
    ReadProcessMemory(e->hProcess, e->stub, &flag, 1, NULL);
    return flag != 0;
}

static int RT_Wait(const RemoteThreat* e, DWORD timeoutMs) {
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

static void RT_Close(RemoteThreat* e) {
    if (!e) return;
    e->valid = 0;
}

#ifdef __cplusplus
}
#endif