#pragma once
#include <windows.h>
#include "rt_utl.h"
#include "rt_asm.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION 40

typedef NTSTATUS(NTAPI* fnNtSetInformationProcess_t)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG
    );

struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
};

// Injects via ProcessInstrumentationCallback.
// Supports x64 native targets and WOW64 (32-bit) targets.
// The callback fires on the next syscall return in the target, calls startAddress(lParam), then goes dormant.
// Note: WOW64 PICI fires in 64-bit mode on the WOW64 internal stack; if that stack is above 4 GB
// the mode-switch will fault. This works on most standard configurations.
// Returns INVALID_HANDLE_VALUE (no thread handle); the remote stub remains allocated.
HANDLE SetProcessCallback(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub = nullptr) {
#ifndef _WIN64
    return INVALID_HANDLE_VALUE;
#else
    ProcessBitness bitness = GetProcessBitness(hProcess);
    if (bitness == ProcessBitness::Unknown)
        return INVALID_HANDLE_VALUE;

    static fnNtSetInformationProcess_t NtSetInformationProcess =
        (fnNtSetInformationProcess_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    if (!NtSetInformationProcess)
        return INVALID_HANDLE_VALUE;

    SIZE_T stubSize = 0;
    {
        BYTE* tmp = (bitness == ProcessBitness::Bit64)
            ? GetPICIStub64(0, 0, 0, stubSize)
            : GetPICIStubWow64(0, 0, 0, stubSize);
        delete[] tmp;
    }

    LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, stubSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase)
        return INVALID_HANDLE_VALUE;

    DWORD64 flagAddr  = (DWORD64)remoteBase;
    LPVOID  codeEntry = (BYTE*)remoteBase + 8;

    BYTE* stub = (bitness == ProcessBitness::Bit64)
        ? GetPICIStub64((DWORD64)startAddress, (DWORD64)lParam, flagAddr, stubSize)
        : GetPICIStubWow64((DWORD)(DWORD64)startAddress, (DWORD)(DWORD64)lParam, flagAddr, stubSize);

    if (!WriteProcessMemory(hProcess, remoteBase, stub, stubSize, nullptr)) {
        delete[] stub;
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return INVALID_HANDLE_VALUE;
    }
    delete[] stub;

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION pici = {};
    pici.Version  = 0;
    pici.Reserved = 0;
    pici.Callback = codeEntry;

    NTSTATUS status = NtSetInformationProcess(
        hProcess,
        _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION,
        &pici, sizeof(pici));

    if (!NT_SUCCESS(status)) {
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return INVALID_HANDLE_VALUE;
    }

    if (outRemoteStub) *outRemoteStub = remoteBase;
    return INVALID_HANDLE_VALUE;
#endif
}