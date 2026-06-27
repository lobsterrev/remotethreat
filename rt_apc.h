#pragma once
#include <string_view>
#include "rt_utl.h"
#include "rt_asm.h"
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)

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

HANDLE FindBestApcThread(DWORD targetPid) {
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll) return INVALID_HANDLE_VALUE;

	auto NtQueryInformationThread = reinterpret_cast<pfnNtQueryInformationThread>(
		GetProcAddress(hNtDll, "NtQueryInformationThread"));
	if (!NtQueryInformationThread) return INVALID_HANDLE_VALUE;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;

	THREADENTRY32 te{ sizeof(te) };
	HANDLE hBest = INVALID_HANDLE_VALUE;
	long long bestScore = LLONG_MIN;

	if (Thread32First(hSnapshot, &te)) {
		do {
			if (te.th32OwnerProcessID != targetPid) continue;

			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (!hThread) continue;

			ULONG suspendCount = 1;
			NtQueryInformationThread(hThread, ThreadSuspendCount, &suspendCount, sizeof(suspendCount), nullptr);

			THREAD_CYCLE_TIME_INFORMATION cycleInfo{};
			NtQueryInformationThread(hThread, ThreadCycleTime, &cycleInfo, sizeof(cycleInfo), nullptr);

			if (cycleInfo.AccumulatedCycles == 0) {
				CloseHandle(hThread);
				continue;
			}

			THREAD_BASIC_INFORMATION basicInfo{};
			LONG priority = 8;
			if (NT_SUCCESS(NtQueryInformationThread(hThread, ThreadBasicInformation, &basicInfo, sizeof(basicInfo), nullptr)))
				priority = basicInfo.Priority;

			long long score = static_cast<long long>(cycleInfo.AccumulatedCycles / 1'000'000ULL);

			if (suspendCount == 0) score += 500; else score -= 800LL * suspendCount;
			if (priority >= 7 && priority <= 11) score += 150;

			PWSTR desc = nullptr;
			if (SUCCEEDED(GetThreadDescription(hThread, &desc)) && desc) {
				std::wstring_view dv(desc);
				if (dv.find(L"pool")       != std::wstring_view::npos ||
					dv.find(L"Worker")     != std::wstring_view::npos ||
					dv.find(L"ThreadPool") != std::wstring_view::npos)
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

HANDLE QueueAPC(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, LPVOID* outRemoteStub = nullptr)
{
	HANDLE hThread = FindBestApcThread(GetProcessId(hProcess));

	if (!hThread)
		return INVALID_HANDLE_VALUE;

	pfnNtQueueApcThreadEx2 fNtQueueApcThreadEx2 = (pfnNtQueueApcThreadEx2)GetProcAddress(GetModuleHandleA("ntdll"), "NtQueueApcThreadEx2");
	if (!fNtQueueApcThreadEx2) { CloseHandle(hThread); return INVALID_HANDLE_VALUE; }
	SIZE_T stubSize = 0;
#if _WIN64
	ProcessBitness bitness = GetProcessBitness(hProcess);
	if (bitness == ProcessBitness::Bit32) {
		BYTE* tmp = GetAPCCrossStub(0, 0, 0, stubSize); delete[] tmp;
	} else {
		BYTE* tmp = GetAPCStub64(0, 0, 0, stubSize); delete[] tmp;
	}
#else
	{ BYTE* tmp = GetAPCStub32(0, 0, 0, stubSize); delete[] tmp; }
#endif

	LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, stubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteBase) { CloseHandle(hThread); return INVALID_HANDLE_VALUE; }

	BYTE* stub = nullptr;
#if _WIN64
	if (bitness == ProcessBitness::Bit32)
		stub = GetAPCCrossStub((DWORD)startAddress, (DWORD)lParam, (DWORD64)remoteBase, stubSize);
	else
		stub = GetAPCStub64((DWORD64)startAddress, (DWORD64)lParam, (DWORD64)remoteBase, stubSize);
#else
	stub = GetAPCStub32((DWORD)startAddress, (DWORD)lParam, (DWORD64)remoteBase, stubSize);
#endif

	if (!WriteProcessMemory(hProcess, remoteBase, stub, stubSize, nullptr)) {
		delete[] stub;
		VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
		CloseHandle(hThread);
		return INVALID_HANDLE_VALUE;
	}
	delete[] stub;

	LPVOID codeEntry = (BYTE*)remoteBase + 8;
	NTSTATUS result = fNtQueueApcThreadEx2(hThread, NULL, QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, (PPS_APC_ROUTINE)codeEntry, lParam, NULL, NULL);
	if (result == STATUS_NOT_SUPPORTED)
		result = fNtQueueApcThreadEx2(hThread, NULL, 0, (PPS_APC_ROUTINE)codeEntry, lParam, NULL, NULL);

	CloseHandle(hThread);

	if (!NT_SUCCESS(result)) {
		VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
		return INVALID_HANDLE_VALUE;
	}
	if (outRemoteStub) *outRemoteStub = remoteBase;
	return NULL;
}