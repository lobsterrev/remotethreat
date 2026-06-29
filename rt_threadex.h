#pragma once
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(x) ((x) >= 0)
#endif

typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)(
	PHANDLE hThread,
	ACCESS_MASK DesiredAccess,
	PVOID ObjectAttributes,
	HANDLE ProcessHandle,
	PVOID lpStartAddress,
	PVOID lpParameter,
	ULONG Flags,
	SIZE_T StackZeroBits,
	SIZE_T SizeOfStackCommit,
	SIZE_T SizeOfStackReserve,
	PVOID lpBytesBuffer);

static HANDLE NtCreateThreadEx(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter) {
	HMODULE hNtDll;
	pfnNtCreateThreadEx pNtCreateThreadEx;
	HANDLE hThread = NULL;
	NTSTATUS status;

	hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll) return INVALID_HANDLE_VALUE;
	pNtCreateThreadEx = (pfnNtCreateThreadEx)GetProcAddress(hNtDll, "NtCreateThreadEx");
	if (!pNtCreateThreadEx) return INVALID_HANDLE_VALUE;
	status = pNtCreateThreadEx(
		&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
		lpStartAddress, lpParameter, FALSE, 0, 0, 0, NULL);
	if (!NT_SUCCESS(status)) return INVALID_HANDLE_VALUE;
	return hThread;
}

#ifdef __cplusplus
}
#endif