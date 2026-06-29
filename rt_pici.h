#pragma once
#include <windows.h>
#include "rt_utl.h"
#include "rt_asm.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION 40

typedef NTSTATUS(NTAPI* fnNtSetInformationProcess_t)(
    HANDLE,
    ULONG,
    PVOID,
    ULONG);

typedef struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_64 {
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_64;

typedef struct PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_32 {
    ULONG Version;
    ULONG Reserved;
    ULONG Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_32;

// Injects via ProcessInstrumentationCallback.
// x64 build, x64 target : Version=0, no special privileges beyond PROCESS_SET_INFORMATION.
// x64 build, WoW64 target: Version=1 (16-byte struct); requires SeSystemEnvironmentPrivilege
//                          (only present in SYSTEM tokens). Not usable from a normal admin process.
// x86 build              : Not supported. The WoW64 syscall thunk does not forward
//                          ProcessInstrumentationCallback (class 40) to the kernel
//                          and returns STATUS_INVALID_PARAMETER for all versions.
// The callback fires on the next syscall return in the target, calls startAddress(lParam),
// then goes dormant. Returns INVALID_HANDLE_VALUE (no thread handle); the remote stub
// remains allocated.
static HANDLE SetProcessCallback(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub) {
#ifndef _WIN64
    (void)hProcess; (void)startAddress; (void)lParam; (void)outRemoteStub;
    // ProcessInstrumentationCallback cannot be set from a 32-bit (WoW64) process:
    // the WoW64 syscall thunk returns STATUS_INVALID_PARAMETER for this info class.
    return INVALID_HANDLE_VALUE;
#else
    ProcessBitness bitness;
    static fnNtSetInformationProcess_t NtSetInformationProcess = NULL;
    SIZE_T stubSize;
    LPVOID remoteBase;
    DWORD64 flagAddr;
    LPVOID codeEntry;
    BYTE* stub;
    NTSTATUS status;

    bitness = GetProcessBitness(hProcess);
    if (bitness == PB_Unknown) return INVALID_HANDLE_VALUE;

    if (!NtSetInformationProcess) {
        NtSetInformationProcess = (fnNtSetInformationProcess_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    }
    if (!NtSetInformationProcess) return INVALID_HANDLE_VALUE;

    stubSize = (bitness == PB_Bit64) ? kPICIStub64Size : kPICIStub32Size;

    remoteBase = VirtualAllocEx(hProcess, NULL, stubSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteBase) return INVALID_HANDLE_VALUE;

    flagAddr  = (DWORD64)remoteBase;
    codeEntry = (BYTE*)remoteBase + 8;

    stub = (bitness == PB_Bit64)
        ? GetPICIStub64((DWORD64)startAddress, (DWORD64)lParam, flagAddr, &stubSize)
        : GetPICIStub32((DWORD)(DWORD64)startAddress, (DWORD)(DWORD64)lParam, flagAddr, &stubSize);

    if (!WriteRemoteStub(hProcess, remoteBase, stub, stubSize))
        return INVALID_HANDLE_VALUE;

    if (bitness == PB_Bit64) {
        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_64 pici;
        pici.Version  = 0;
        pici.Reserved = 0;
        pici.Callback = codeEntry;
        status = NtSetInformationProcess(
            hProcess, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, &pici, sizeof(pici));
    } else {
        // WoW64: Version=1 fires the callback directly in 32-bit compat mode.
        // Try a 12-byte struct (ULONG Callback) first, fall back to the 16-byte struct.
        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_32 pici12;
        pici12.Version  = 1;
        pici12.Reserved = 0;
        pici12.Callback = (ULONG)(ULONG_PTR)codeEntry;
        status = NtSetInformationProcess(
            hProcess, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, &pici12, sizeof(pici12));
        if (!NT_SUCCESS(status)) {
            PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_64 pici16;
            pici16.Version  = 1;
            pici16.Reserved = 0;
            pici16.Callback = codeEntry;
            status = NtSetInformationProcess(
                hProcess, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, &pici16, sizeof(pici16));
        }
    }

    if (!NT_SUCCESS(status)) {
        VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
        return INVALID_HANDLE_VALUE;
    }

    if (outRemoteStub) *outRemoteStub = remoteBase;
    return INVALID_HANDLE_VALUE;
#endif
}

#ifdef __cplusplus
}
#endif