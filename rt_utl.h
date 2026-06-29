#pragma once
#include <windows.h>
#include <stdlib.h>
#include <string.h>

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

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#define RT_ViewUnmap 2

typedef NTSTATUS (NTAPI* pfnNtCreateSection)(
	PHANDLE        SectionHandle,
	ACCESS_MASK    DesiredAccess,
	PVOID          ObjectAttributes,
	PLARGE_INTEGER MaximumSize,
	ULONG          SectionPageProtection,
	ULONG          AllocationAttributes,
	HANDLE         FileHandle);

typedef NTSTATUS (NTAPI* pfnNtMapViewOfSection)(
	HANDLE         SectionHandle,
	HANDLE         ProcessHandle,
	PVOID*         BaseAddress,
	ULONG_PTR      ZeroBits,
	SIZE_T         CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T        ViewSize,
	ULONG          InheritDisposition,
	ULONG          AllocationType,
	ULONG          Win32Protect);

typedef NTSTATUS (NTAPI* pfnNtUnmapViewOfSection)(
	HANDLE ProcessHandle,
	PVOID  BaseAddress);

static LPVOID AllocRemoteStub(HANDLE hProcess, SIZE_T size, LPVOID* outLocalBase)
{
	static pfnNtCreateSection      fNtCreateSection      = NULL;
	static pfnNtMapViewOfSection   fNtMapViewOfSection   = NULL;
	static pfnNtUnmapViewOfSection fNtUnmapViewOfSection = NULL;
	HANDLE hNtdll, hSection = NULL;
	LARGE_INTEGER sectionSize;
	LPVOID remoteBase = NULL, localBase = NULL;
	SIZE_T viewSize = 0;
	NTSTATUS st;

	if (!fNtCreateSection) {
		hNtdll = GetModuleHandleA("ntdll.dll");
		fNtCreateSection      = (pfnNtCreateSection)     GetProcAddress(hNtdll, "NtCreateSection");
		fNtMapViewOfSection   = (pfnNtMapViewOfSection)  GetProcAddress(hNtdll, "NtMapViewOfSection");
		fNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
	}
	if (!fNtCreateSection || !fNtMapViewOfSection || !fNtUnmapViewOfSection)
		return NULL;

	sectionSize.QuadPart = (LONGLONG)size;
	st = fNtCreateSection(&hSection, SECTION_ALL_ACCESS, NULL,
		&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(st)) return NULL;

	st = fNtMapViewOfSection(hSection, hProcess, &remoteBase,
		0, 0, NULL, &viewSize, RT_ViewUnmap, 0, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(st)) { CloseHandle(hSection); return NULL; }

	viewSize = 0;
	st = fNtMapViewOfSection(hSection, GetCurrentProcess(), &localBase,
		0, 0, NULL, &viewSize, RT_ViewUnmap, 0, PAGE_READWRITE);
	if (!NT_SUCCESS(st)) {
		fNtUnmapViewOfSection(hProcess, remoteBase);
		CloseHandle(hSection);
		return NULL;
	}

	CloseHandle(hSection);
	*outLocalBase = localBase;
	return remoteBase;
}

static void CommitRemoteStub(LPVOID localBase, BYTE* stub, SIZE_T size)
{
	static pfnNtUnmapViewOfSection fNtUnmapViewOfSection = NULL;
	if (!fNtUnmapViewOfSection)
		fNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	memcpy(localBase, stub, size);
	free(stub);
	if (fNtUnmapViewOfSection) fNtUnmapViewOfSection(GetCurrentProcess(), localBase);
}

static void FreeRemoteStub(HANDLE hProcess, LPVOID remoteBase)
{
	static pfnNtUnmapViewOfSection fNtUnmapViewOfSection = NULL;
	if (!fNtUnmapViewOfSection)
		fNtUnmapViewOfSection = (pfnNtUnmapViewOfSection)
			GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	if (fNtUnmapViewOfSection) fNtUnmapViewOfSection(hProcess, remoteBase);
}

#ifdef __cplusplus
}
#endif
