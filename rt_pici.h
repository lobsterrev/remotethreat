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

static HANDLE SetProcessCallback(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub) {
#ifndef _WIN64
    (void)hProcess; (void)startAddress; (void)lParam; (void)outRemoteStub;
    
    
    return INVALID_HANDLE_VALUE;
#else
    ProcessBitness bitness;
    static fnNtSetInformationProcess_t NtSetInformationProcess = NULL;
    SIZE_T stubSize;
    LPVOID remoteBase;
    LPVOID localBase = NULL;
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

    remoteBase = AllocRemoteStub(hProcess, stubSize, &localBase);
    if (!remoteBase) return INVALID_HANDLE_VALUE;

    flagAddr  = (DWORD64)remoteBase;
    codeEntry = (BYTE*)remoteBase + 8;

    stub = (bitness == PB_Bit64)
        ? GetPICIStub64((DWORD64)startAddress, (DWORD64)lParam, flagAddr)
        : GetPICIStub32((DWORD)(DWORD64)startAddress, (DWORD)(DWORD64)lParam, flagAddr);

    CommitRemoteStub(localBase, stub, stubSize);

    if (bitness == PB_Bit64) {
        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION_64 pici;
        pici.Version  = 0;
        pici.Reserved = 0;
        pici.Callback = codeEntry;
        status = NtSetInformationProcess(
            hProcess, _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, &pici, sizeof(pici));
    } else {
        
        
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
        FreeRemoteStub(hProcess, remoteBase);
        return INVALID_HANDLE_VALUE;
    }

    if (outRemoteStub) *outRemoteStub = remoteBase;
    return INVALID_HANDLE_VALUE;
#endif
}

#ifdef __cplusplus
}
#endif