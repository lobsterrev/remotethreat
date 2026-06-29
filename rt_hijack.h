#pragma once
#include "rt_asm.h"
#include <tlhelp32.h>

#ifdef __cplusplus
extern "C" {
#endif

static THREADENTRY32 SelectThread(HANDLE hProcess) {
    THREADENTRY32 best;
    THREADENTRY32 te;
    HANDLE snapshot;
    DWORD PID;
    ULONGLONG bestTime = ULLONG_MAX;

    ZeroMemory(&best, sizeof(best));
    ZeroMemory(&te, sizeof(te));
    te.dwSize = sizeof(te);

    PID = GetProcessId(hProcess);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    if (Thread32First(snapshot, &te)) {
        do {
            HANDLE hThread;
            FILETIME created, exited, kernel, user;
            ULONGLONG t;

            if (te.th32OwnerProcessID != PID) continue;
            hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;
            if (GetThreadTimes(hThread, &created, &exited, &kernel, &user)) {
                t = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
                if (t < bestTime) {
                    bestTime = t;
                    best = te;
                }
            }
            CloseHandle(hThread);
        } while (Thread32Next(snapshot, &te));
    }
    CloseHandle(snapshot);
    return best;
}

static HANDLE HijackThread(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub) {
    DWORD threadId;
    HANDLE hThread;
    BYTE* stub = NULL;
    SIZE_T stubSize = 0;
    LPVOID stubPtr = NULL;
    LPVOID remoteBase = NULL;

    threadId = SelectThread(hProcess).th32ThreadID;
    if (!threadId) return NULL;
    hThread = OpenThread(
        THREAD_SUSPEND_RESUME |
        THREAD_GET_CONTEXT |
        THREAD_SET_CONTEXT |
        THREAD_QUERY_INFORMATION,
        FALSE,
        threadId);
    if (!hThread) return NULL;

    SuspendThread(hThread);

#if _WIN64
    if (GetProcessBitness(hProcess) == PB_Bit32) {
        WOW64_CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(hThread, &ctx)) goto fail;
        stubSize = kHijackStub32Size;
        remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) goto fail;
        stub = GetHijackStub32((DWORD)startAddress, (DWORD)lParam, ctx.Eip, (DWORD)remoteBase, &stubSize);
        if (!WriteRemoteStub(hProcess, remoteBase, stub, stubSize)) { remoteBase = NULL; goto fail; }
        ctx.Eip = (DWORD)(uintptr_t)((BYTE*)remoteBase + 8);
        if (!Wow64SetThreadContext(hThread, &ctx)) goto fail;
        stubPtr = remoteBase;
    } else {
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) goto fail;
        stubSize = kHijackStub64Size;
        remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) goto fail;
        stub = GetHijackStub64((DWORD64)startAddress, (DWORD64)lParam, ctx.Rip, (DWORD64)remoteBase, &stubSize);
        if (!WriteRemoteStub(hProcess, remoteBase, stub, stubSize)) { remoteBase = NULL; goto fail; }
        ctx.Rip = (uintptr_t)((BYTE*)remoteBase + 8);
        if (!SetThreadContext(hThread, &ctx)) goto fail;
        stubPtr = remoteBase;
    }
#else
    {
        CONTEXT ctx;
        ZeroMemory(&ctx, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) goto fail;
        stubSize = kHijackStub32Size;
        remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) goto fail;
        stub = GetHijackStub32((DWORD)startAddress, (DWORD)lParam, ctx.Eip, (DWORD64)remoteBase, &stubSize);
        if (!WriteRemoteStub(hProcess, remoteBase, stub, stubSize)) { remoteBase = NULL; goto fail; }
        ctx.Eip = (DWORD)(uintptr_t)((BYTE*)remoteBase + 8);
        if (!SetThreadContext(hThread, &ctx)) goto fail;
        stubPtr = remoteBase;
    }
#endif

    if (outRemoteStub) *outRemoteStub = stubPtr;
    while (ResumeThread(hThread) > 1);
    PostThreadMessage(threadId, WM_NULL, 0, 0);
    return hThread;

fail:
    if (remoteBase) VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
    while (ResumeThread(hThread) > 1);
    CloseHandle(hThread);
    return NULL;
}

#ifdef __cplusplus
}
#endif