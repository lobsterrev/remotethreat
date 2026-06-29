#pragma once
#include "rt_utl.h"
#include "rt_asm.h"
#include <tlhelp32.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef Wow64EncodeApcRoutine
#define Wow64EncodeApcRoutine(ApcRoutine) \
    ((PVOID)((0 - ((LONG_PTR)(ApcRoutine))) << 2))
#endif

typedef NTSTATUS(NTAPI* pfnNtQueryInformationThread)(
	HANDLE ThreadHandle,
	ULONG ThreadInformationClass,
	PVOID ThreadInformation,
	ULONG ThreadInformationLength,
	PULONG ReturnLength);

typedef NTSTATUS(NTAPI* pfnNtQueueApcThreadEx2)(
	HANDLE ThreadHandle,
	HANDLE ReserveHandle,
	ULONG ApcFlags,
	PPS_APC_ROUTINE ApcRoutine,
	PVOID ApcArgument1,
	PVOID ApcArgument2,
	PVOID ApcArgument3);

static HANDLE FindBestApcThread(DWORD targetPid) {
	HMODULE hNtDll;
	pfnNtQueryInformationThread NtQueryInformationThread;
	HANDLE hSnapshot;
	THREADENTRY32 te;
	HANDLE hBest = INVALID_HANDLE_VALUE;
	long long bestScore = LLONG_MIN;

	hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll) return INVALID_HANDLE_VALUE;

	NtQueryInformationThread = (pfnNtQueryInformationThread)
		GetProcAddress(hNtDll, "NtQueryInformationThread");
	if (!NtQueryInformationThread) return INVALID_HANDLE_VALUE;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

	ZeroMemory(&te, sizeof(te));
	te.dwSize = sizeof(te);

	if (Thread32First(hSnapshot, &te)) {
		do {
			HANDLE hThread;
			ULONG suspendCount = 1;
			THREAD_CYCLE_TIME_INFORMATION cycleInfo;
			THREAD_BASIC_INFORMATION basicInfo;
			LONG priority = 8;
			long long score;
			PWSTR desc = NULL;

			if (te.th32OwnerProcessID != targetPid) continue;

			hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (!hThread) continue;

			NtQueryInformationThread(hThread, ThreadSuspendCount, &suspendCount, sizeof(suspendCount), NULL);

			ZeroMemory(&cycleInfo, sizeof(cycleInfo));
			NtQueryInformationThread(hThread, ThreadCycleTime, &cycleInfo, sizeof(cycleInfo), NULL);

			if (cycleInfo.AccumulatedCycles == 0) {
				CloseHandle(hThread);
				continue;
			}

			ZeroMemory(&basicInfo, sizeof(basicInfo));
			if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &basicInfo, sizeof(basicInfo), NULL)))
				priority = basicInfo.Priority;

			score = (long long)(cycleInfo.AccumulatedCycles / 1000000ULL);

			if (suspendCount == 0) score += 500; else score -= 800LL * suspendCount;
			if (priority >= 7 && priority <= 11) score += 150;

			if (SUCCEEDED(GetThreadDescription(hThread, &desc)) && desc) {
				if (wcsstr(desc, L"pool") || wcsstr(desc, L"Worker") || wcsstr(desc, L"ThreadPool"))
					score += 300;
				LocalFree(desc);
			}

			if (score > bestScore) {
				if (hBest != INVALID_HANDLE_VALUE) CloseHandle(hBest);
				hBest = hThread;
				bestScore = score;
			} else {
				CloseHandle(hThread);
			}

		} while (Thread32Next(hSnapshot, &te));
	}

	CloseHandle(hSnapshot);
	return hBest;
}

static HANDLE QueueAPC(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub)
{
	HANDLE hThread;
	pfnNtQueueApcThreadEx2 fNtQueueApcThreadEx2;
	SIZE_T stubSize = 0;
	LPVOID remoteBase;
	LPVOID localBase = NULL;
	BYTE* stub = NULL;
	LPVOID codeEntry;
	PPS_APC_ROUTINE apcEntry;
	NTSTATUS result;
#if _WIN64
	ProcessBitness bitness;
#endif

	hThread = FindBestApcThread(GetProcessId(hProcess));
	if (!hThread || hThread == INVALID_HANDLE_VALUE)
		return INVALID_HANDLE_VALUE;

	fNtQueueApcThreadEx2 = (pfnNtQueueApcThreadEx2)
		GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThreadEx2");
	if (!fNtQueueApcThreadEx2) { CloseHandle(hThread); return INVALID_HANDLE_VALUE; }

#if _WIN64
	bitness = GetProcessBitness(hProcess);
	stubSize = (bitness == PB_Bit32) ? kAPCStub32Size : kAPCStub64Size;
#else
	stubSize = kAPCStub32Size;
#endif

	remoteBase = AllocRemoteStub(hProcess, stubSize, &localBase);
	if (!remoteBase) { CloseHandle(hThread); return INVALID_HANDLE_VALUE; }

#if _WIN64
	if (bitness == PB_Bit32)
		stub = GetAPCStub32((DWORD)(DWORD_PTR)startAddress, (DWORD)(DWORD_PTR)lParam, (DWORD64)remoteBase);
	else
		stub = GetAPCStub64((DWORD64)startAddress, (DWORD64)lParam, (DWORD64)remoteBase);
#else
	stub = GetAPCStub32((DWORD)startAddress, (DWORD)lParam, (DWORD64)remoteBase);
#endif

	CommitRemoteStub(localBase, stub, stubSize);

	codeEntry = (BYTE*)remoteBase + 8;
#if _WIN64
	apcEntry = (bitness == PB_Bit32)
		? (PPS_APC_ROUTINE)Wow64EncodeApcRoutine(codeEntry)
		: (PPS_APC_ROUTINE)codeEntry;
#else
	apcEntry = (PPS_APC_ROUTINE)codeEntry;
#endif
	result = fNtQueueApcThreadEx2(hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, apcEntry, lParam, NULL, NULL);
	if (result == STATUS_NOT_SUPPORTED)
		result = fNtQueueApcThreadEx2(hThread, NULL, 0, apcEntry, lParam, NULL, NULL);

	CloseHandle(hThread);

	if (!NT_SUCCESS(result)) {
		FreeRemoteStub(hProcess, remoteBase);
		return INVALID_HANDLE_VALUE;
	}
	if (outRemoteStub) *outRemoteStub = remoteBase;
	return NULL;
}

#ifdef __cplusplus
}
#endif