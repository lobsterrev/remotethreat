#pragma once
#include "rt_threadex.h"
#include "rt_apc.h"
#include "rt_hijack.h"
#include "rt_asm.h"
#include "rt_pici.h"
#include <utility>
#if !(defined _M_IX86) && !(defined _M_X64) && !(defined __i386__) && !(defined __x86_64__)
    #error RemoteThreat only supports x86 and x64 systems.
#endif
namespace RT {
    enum Method {
        NtCreateThread,
        Hijack,
        APC,
        ProcessInformationCallback,
    };

    // Tracks a remote execution request created by RT::Create.
    // For stub-based methods (APC / Hijack / PICI) completion is detected by
    // reading the flag byte at the start of the remote stub allocation.
    // For NtCreateThread, completion is detected via the thread's signaled state.
    class Execution {
    public:
        Execution() = default;
        Execution(const Execution&) = delete;
        Execution& operator=(const Execution&) = delete;

        Execution(Execution&& other) noexcept { swap(other); }
        Execution& operator=(Execution&& other) noexcept {
            if (this != &other) {
                Execution tmp(std::move(other));
                swap(tmp);
            }
            return *this;
        }

        ~Execution() {
            // Intentionally do NOT VirtualFreeEx the remote stub: freeing memory
            // that the target has not yet executed would crash the target. The
            // stub allocation is left in place by design.
            if (hThread_) CloseHandle(hThread_);
        }

        bool Valid() const { return valid_; }
        explicit operator bool() const { return valid_; }

        // Non-blocking: returns true once the injected code has run.
        bool IsDone() const {
            if (!valid_) return false;
            if (hThread_) {
                return WaitForSingleObject(hThread_, 0) == WAIT_OBJECT_0;
            }
            BYTE flag = 0;
            ReadProcessMemory(hProcess_, stub_, &flag, 1, nullptr);
            return flag != 0;
        }

        // Blocks until the injected code has run, or until timeoutMs elapses.
        // Returns true on completion, false on timeout / invalid execution.
        bool Wait(DWORD timeoutMs = INFINITE) const {
            if (!valid_) return false;
            if (hThread_) {
                return WaitForSingleObject(hThread_, timeoutMs) == WAIT_OBJECT_0;
            }
            DWORD start = GetTickCount();
            while (!IsDone()) {
                if (timeoutMs != INFINITE && GetTickCount() - start >= timeoutMs)
                    return false;
                Sleep(1);
            }
            return true;
        }

    private:
        friend Execution Create(HANDLE, LPVOID, LPVOID, Method);

        void swap(Execution& o) noexcept {
            std::swap(hProcess_, o.hProcess_);
            std::swap(stub_, o.stub_);
            std::swap(hThread_, o.hThread_);
            std::swap(valid_, o.valid_);
        }

        HANDLE hProcess_ = nullptr; // non-owning
        LPVOID stub_     = nullptr; // remote allocation; intentionally leaked
        HANDLE hThread_  = nullptr; // owned (NtCreateThread path only)
        bool   valid_    = false;
    };

    inline Execution Create(HANDLE hProcess, LPVOID startAddress, LPVOID lParam, Method method = NtCreateThread) {
        Execution e;
        e.hProcess_ = hProcess;

        LPVOID stub = nullptr;
        HANDLE hThread = nullptr;

        switch (method) {
            case APC:
                QueueAPC(hProcess, startAddress, lParam, &stub);
                break;
            case ProcessInformationCallback:
                SetProcessCallback(hProcess, startAddress, lParam, &stub);
                break;
            case Hijack: {
                // HijackThread returns a handle to the hijacked thread, but
                // completion is tracked via the stub flag, so discard it.
                HANDLE hHijacked = HijackThread(hProcess, startAddress, lParam, &stub);
                if (hHijacked && hHijacked != INVALID_HANDLE_VALUE)
                    CloseHandle(hHijacked);
                break;
            }
            case NtCreateThread: {
                HANDLE h = NtCreateThreadEx(hProcess, (LPTHREAD_START_ROUTINE)startAddress, lParam);
                if (h != INVALID_HANDLE_VALUE) hThread = h;
                break;
            }
        }

        if (stub || hThread) {
            e.stub_    = stub;
            e.hThread_ = hThread;
            e.valid_   = true;
        }
        return e;
    }
}