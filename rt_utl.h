#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <limits.h>

typedef PVOID PPS_APC_ROUTINE;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// NtQueryInformationThread structs and constants
typedef struct _THREAD_CYCLE_TIME_INFORMATION {
	ULONGLONG AccumulatedCycles;
} THREAD_CYCLE_TIME_INFORMATION, * PTHREAD_CYCLE_TIME_INFORMATION;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	KAFFINITY AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;


#define ThreadBasicInformation       0
#define ThreadCycleTime             23
#define ThreadSuspendCount          35

enum class ProcessBitness { Unknown, Bit32, Bit64 };

ProcessBitness GetProcessBitness(HANDLE hProcess) {
	BOOL isWow64 = FALSE;
	if (!IsWow64Process(hProcess, &isWow64)) {
		return ProcessBitness::Unknown;
	}

	// WOW64 = 32-bit process running on 64-bit OS
	if (isWow64) {
		return ProcessBitness::Bit32;
	}

	// Not WOW64 � could be native 64-bit, or native 32-bit on a 32-bit OS
	SYSTEM_INFO si{};
	GetNativeSystemInfo(&si);

	const bool is64bitOS = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64
		|| si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;

	return is64bitOS ? ProcessBitness::Bit64 : ProcessBitness::Bit32;
}

LPVOID RemoteAllocStub(HANDLE hProcess, BYTE* stub, size_t size) {
	LPVOID allocPtr = VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!allocPtr) return nullptr;
	if (!WriteProcessMemory(hProcess, allocPtr, stub, size, 0)) {
		VirtualFreeEx(hProcess, allocPtr, 0, MEM_RELEASE);
		return nullptr;
	}
	return allocPtr;
}
