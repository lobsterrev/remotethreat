#pragma once
#include "rt_asm.h"


THREADENTRY32 SelectThread(HANDLE hProcess) {
    THREADENTRY32 entry = {};
    DWORD PID = GetProcessId(hProcess);
    entry.dwSize = sizeof(entry);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

    THREADENTRY32 best = {};
    ULONGLONG bestTime = ULLONG_MAX;

    THREADENTRY32 te = {};
    te.dwSize = sizeof(te);
    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != PID) continue;
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) continue;
            FILETIME created, exited, kernel, user;
            if (GetThreadTimes(hThread, &created, &exited, &kernel, &user)) {
                ULONGLONG t = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
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


HANDLE HijackThread(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub = nullptr) {

    DWORD threadId = SelectThread(hProcess).th32ThreadID;
    if (!threadId) return NULL;
    HANDLE hThread = OpenThread(
        THREAD_SUSPEND_RESUME |
        THREAD_GET_CONTEXT |
        THREAD_SET_CONTEXT |
        THREAD_QUERY_INFORMATION,
        FALSE,
        threadId
    );
    if (!hThread)
        return NULL;

    SuspendThread(hThread);

    auto cleanup = [&](LPVOID remoteStub) -> HANDLE {
        if (remoteStub) VirtualFreeEx(hProcess, remoteStub, 0, MEM_RELEASE);
        while (ResumeThread(hThread) > 1);
        CloseHandle(hThread);
        return NULL;
    };

    BYTE* stub = nullptr;
    SIZE_T stubSize = 0;
    LPVOID stubPtr = nullptr;

#if _WIN64
    if (GetProcessBitness(hProcess) == ProcessBitness::Bit32) {
        WOW64_CONTEXT ctx = {};
        ctx.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(hThread, &ctx))
            return cleanup(nullptr);
        { BYTE* tmp = GetHijackStub32(0, 0, 0, 0, stubSize); delete[] tmp; }
        LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) return cleanup(nullptr);
        stub = GetHijackStub32((DWORD)startAddress, (DWORD)lParam, ctx.Eip, (DWORD64)remoteBase, stubSize);
        if (!WriteProcessMemory(hProcess, remoteBase, stub, stubSize, nullptr)) {
            delete[] stub;
            return cleanup(remoteBase);
        }
        delete[] stub; stub = nullptr;
        ctx.Eip = (DWORD)(uintptr_t)((BYTE*)remoteBase + 8);
        if (!Wow64SetThreadContext(hThread, &ctx))
            return cleanup(remoteBase);
        stubPtr = remoteBase;
    } else {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx))
            return cleanup(nullptr);
        { BYTE* tmp = GetHijackStub64(0, 0, 0, 0, stubSize); delete[] tmp; }
        LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) return cleanup(nullptr);
        stub = GetHijackStub64((DWORD64)startAddress, (DWORD64)lParam, ctx.Rip, (DWORD64)remoteBase, stubSize);
        if (!WriteProcessMemory(hProcess, remoteBase, stub, stubSize, nullptr)) {
            delete[] stub;
            return cleanup(remoteBase);
        }
        delete[] stub; stub = nullptr;
        ctx.Rip = (uintptr_t)((BYTE*)remoteBase + 8);
        if (!SetThreadContext(hThread, &ctx))
            return cleanup(remoteBase);
        stubPtr = remoteBase;
    }
#else
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx))
        return cleanup(nullptr);
    { BYTE* tmp = GetHijackStub32(0, 0, 0, 0, stubSize); delete[] tmp; }
    LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) return cleanup(nullptr);
    stub = GetHijackStub32((DWORD)startAddress, (DWORD)lParam, ctx.Eip, (DWORD64)remoteBase, stubSize);
    if (!WriteProcessMemory(hProcess, remoteBase, stub, stubSize, nullptr)) {
        delete[] stub;
        return cleanup(remoteBase);
    }
    delete[] stub; stub = nullptr;
    ctx.Eip = (DWORD)(uintptr_t)((BYTE*)remoteBase + 8);
    if (!SetThreadContext(hThread, &ctx))
        return cleanup(remoteBase);
    stubPtr = remoteBase;
#endif

    if (outRemoteStub) *outRemoteStub = stubPtr;
    while (ResumeThread(hThread) > 1);
    PostThreadMessage(threadId, WM_NULL, 0, 0);
    return hThread;
}