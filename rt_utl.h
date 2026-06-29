#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef PVOID PPS_APC_ROUTINE;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _THREAD_CYCLE_TIME_INFORMATION {
	ULONGLONG AccumulatedCycles;
	ULONGLONG CurrentCycleCount;
} THREAD_CYCLE_TIME_INFORMATION, *PTHREAD_CYCLE_TIME_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

#define ThreadBasicInformation       0
#define ThreadCycleTime             23
#define ThreadSuspendCount          35

typedef enum ProcessBitness {
	PB_Unknown,
	PB_Bit32,
	PB_Bit64
} ProcessBitness;

static ProcessBitness GetProcessBitness(HANDLE hProcess) {
	BOOL isWow64 = FALSE;
	SYSTEM_INFO si;
	int is64bitOS;

	if (!IsWow64Process(hProcess, &isWow64))
		return PB_Unknown;

	if (isWow64)
		return PB_Bit32;

	ZeroMemory(&si, sizeof(si));
	GetNativeSystemInfo(&si);

	is64bitOS = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
	          || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);

	return is64bitOS ? PB_Bit64 : PB_Bit32;
}

/* Writes stub to dest in hProcess, free()s stub, returns nonzero on success.
   On failure, free()s stub, frees dest via VirtualFreeEx, and returns 0. */
static int WriteRemoteStub(HANDLE hProcess, LPVOID dest, BYTE* stub, SIZE_T size) {
	BOOL ok = WriteProcessMemory(hProcess, dest, stub, size, NULL);
	free(stub);
	if (!ok) VirtualFreeEx(hProcess, dest, 0, MEM_RELEASE);
	return ok ? 1 : 0;
}

#ifdef __cplusplus
}
#endif
