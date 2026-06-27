#pragma once
#include <windows.h>
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

#define NT_SUCCESS(x) ((x) >= 0)

HANDLE NtCreateThreadEx(HANDLE hProcess, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter) {
	HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
	if (!hNtDll) return INVALID_HANDLE_VALUE;
	auto NtCreateThreadEx = reinterpret_cast<pfnNtCreateThreadEx>(
		GetProcAddress(hNtDll, "NtCreateThreadEx")
		);
	if (!NtCreateThreadEx) return INVALID_HANDLE_VALUE;
	HANDLE hThread = nullptr;
	NTSTATUS status = NtCreateThreadEx(
		&hThread,
		THREAD_ALL_ACCESS,
		nullptr,
		hProcess,
		lpStartAddress,
		lpParameter,
		FALSE,
		0,
		0,
		0,
		nullptr
	);
	if (!NT_SUCCESS(status)) {
		return INVALID_HANDLE_VALUE;
	}
	return hThread;
}