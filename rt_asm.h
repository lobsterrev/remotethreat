#pragma once
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static const BYTE stub32_hijack[] =
{
	0x60,                               // PUSHAD

	0xE8, 0x00, 0x00, 0x00, 0x00,       // CALL $+5

	0x5B,                               // POP EBX  (EBX = address after call)

	0x81, 0xEB, 0x06, 0x00, 0x00, 0x00, // SUB EBX, 6  (EBX = stub base)

	0xB8, 0xCC, 0xCC, 0xCC, 0xCC,       // MOV EAX, startAddress  [14..17]

	0xBA, 0xCC, 0xCC, 0xCC, 0xCC,       // MOV EDX, lParam  [19..22]

	0x52,                               // PUSH EDX

	0xFF, 0xD0,                         // CALL EAX

	0xB8, 0xCC, 0xCC, 0xCC, 0xCC,       // MOV EAX, flagAddr32  [27..30]
	0xC6, 0x00, 0x01,                   // MOV BYTE PTR [EAX], 1

	0x61,                               // POPAD

	0x68, 0xCC, 0xCC, 0xCC, 0xCC,       // PUSH returnAddr  [36..39]
	0xC3                                // RET
};

static const BYTE stub32_apc[] = {
	0xB8, 0xCC, 0xCC, 0xCC, 0xCC,       // MOV EAX, startAddress  [1..4]
	0xBA, 0xCC, 0xCC, 0xCC, 0xCC,       // MOV EDX, lParam  [6..9]
	0x52,                               // PUSH EDX
	0xFF, 0xD0,                         // CALL EAX
	0xB8, 0xCC, 0xCC, 0xCC, 0xCC,       // MOV EAX, flagAddr32  [14..17]
	0xC6, 0x00, 0x01,                   // MOV BYTE PTR [EAX], 1
	0xC3                                // RET
};

static const BYTE stub64_hijack[] = {
	0x9C,                               // PUSHFQ
	0x50,                               // PUSH RAX
	0x53,                               // PUSH RBX
	0x51,                               // PUSH RCX
	0x52,                               // PUSH RDX
	0x41, 0x50,                         // PUSH R8
	0x41, 0x51,                         // PUSH R9
	0x41, 0x52,                         // PUSH R10
	0x41, 0x53,                         // PUSH R11

	0x55,                               // PUSH RBP
	0x48, 0x89, 0xE5,                   // MOV RBP, RSP
	0x48, 0x83, 0xE4, 0xF0,             // AND RSP, -16
	0x48, 0x83, 0xEC, 0x20,             // SUB RSP, 0x20

	0x48, 0xB9,                         // MOVABS RCX, argument (placeholder) [offset 27]
	0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,

	0x48, 0xB8,                         // MOVABS RAX, shellcode function (placeholder) [offset 37]
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

	0xFF, 0xD0,                         // CALL RAX

	0x48, 0x89, 0xEC,                   // MOV RSP, RBP
	0x5D,                               // POP RBP

	0x41, 0x5B,                         // POP R11
	0x41, 0x5A,                         // POP R10
	0x41, 0x59,                         // POP R9
	0x41, 0x58,                         // POP R8
	0x5A,                               // POP RDX
	0x59,                               // POP RCX
	0x5B,                               // POP RBX
	0x58,                               // POP RAX
	0x9D,                               // POPFQ

	0x48, 0xB8,                         // MOVABS RAX, flagAddr  [66..73]
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
	0xC6, 0x00, 0x01,                   // MOV BYTE PTR [RAX], 1

	0x48, 0xB8,                         // MOVABS RAX, originalRIP  [79..86]
	0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE,

	0xFF, 0xE0                          // JMP RAX
};

static const BYTE stub64_apc[] = {
	0x9C,                               // PUSHFQ
	0x50,                               // PUSH RAX
	0x53,                               // PUSH RBX
	0x51,                               // PUSH RCX
	0x52,                               // PUSH RDX
	0x41, 0x50,                         // PUSH R8
	0x41, 0x51,                         // PUSH R9
	0x41, 0x52,                         // PUSH R10
	0x41, 0x53,                         // PUSH R11

	0x48, 0x83, 0xEC, 0x20,             // SUB RSP, 0x20  (32 bytes shadow space)

	0x48, 0xB9,                         // MOVABS RCX, argument (placeholder)
	0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,

	0x48, 0xB8,                         // MOVABS RAX, function (placeholder)
	0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

	0xFF, 0xD0,                         // CALL RAX

	0x48, 0x83, 0xC4, 0x20,             // ADD RSP, 0x20

	0x48, 0xB8,                         // MOVABS RAX, flagAddr  [45..52]
	0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,
	0xC6, 0x00, 0x01,                   // MOV BYTE PTR [RAX], 1

	0x41, 0x5B,                         // POP R11
	0x41, 0x5A,                         // POP R10
	0x41, 0x59,                         // POP R9
	0x41, 0x58,                         // POP R8
	0x5A,                               // POP RDX
	0x59,                               // POP RCX
	0x5B,                               // POP RBX
	0x58,                               // POP RAX
	0x9D,                               // POPFQ

	0xC3                                // RET
};

// Compile-time sizes for each stub, including the 8-byte completion-flag
// prefix that the stub-building helpers prepend. Use these to size
// VirtualAllocEx without having to build (and immediately discard) a
// throwaway stub just to learn its length.
static const SIZE_T kHijackStub32Size  = 8 + sizeof(stub32_hijack);
static const SIZE_T kHijackStub64Size  = 8 + sizeof(stub64_hijack);
static const SIZE_T kAPCStub32Size     = 8 + sizeof(stub32_apc);
static const SIZE_T kAPCStub64Size     = 8 + sizeof(stub64_apc);

static BYTE* GetHijackStub32(DWORD startAddress, DWORD lParam, DWORD dwReturnAddress, DWORD64 flagAddr, SIZE_T* outSize)
{
    SIZE_T size = 8 + sizeof(stub32_hijack);
    BYTE* buf = (BYTE*)calloc(1, size);
    *outSize = size;
    memcpy(buf + 8, stub32_hijack, sizeof(stub32_hijack));
    *(DWORD*)&buf[8 + 14] = startAddress;
    *(DWORD*)&buf[8 + 19] = lParam;
    *(DWORD*)&buf[8 + 27] = (DWORD)flagAddr;
    *(DWORD*)&buf[8 + 36] = dwReturnAddress;
    return buf;
}

static BYTE* GetHijackStub64(DWORD64 startAddress, DWORD64 lParam, DWORD64 dwReturnAddress, DWORD64 flagAddr, SIZE_T* outSize)
{
    SIZE_T size = 8 + sizeof(stub64_hijack);
    BYTE* buf = (BYTE*)calloc(1, size);
    *outSize = size;
    memcpy(buf + 8, stub64_hijack, sizeof(stub64_hijack));
    *(DWORD64*)&buf[8 + 27] = lParam;
    *(DWORD64*)&buf[8 + 37] = startAddress;
    *(DWORD64*)&buf[8 + 66] = flagAddr;
    *(DWORD64*)&buf[8 + 79] = dwReturnAddress;
    return buf;
}

static BYTE* GetAPCStub32(DWORD startAddress, DWORD lParam, DWORD64 flagAddr, SIZE_T* outSize)
{
    SIZE_T size = 8 + sizeof(stub32_apc);
    BYTE* buf = (BYTE*)calloc(1, size);
    *outSize = size;
    memcpy(buf + 8, stub32_apc, sizeof(stub32_apc));
    *(DWORD*)&buf[8 + 1]  = startAddress;
    *(DWORD*)&buf[8 + 6]  = lParam;
    *(DWORD*)&buf[8 + 14] = (DWORD)flagAddr;
    return buf;
}

static BYTE* GetAPCStub64(DWORD64 startAddress, DWORD64 lParam, DWORD64 flagAddr, SIZE_T* outSize)
{
    SIZE_T size = 8 + sizeof(stub64_apc);
    BYTE* buf = (BYTE*)calloc(1, size);
    *outSize = size;
    memcpy(buf + 8, stub64_apc, sizeof(stub64_apc));
    *(DWORD64*)&buf[8 + 19] = lParam;
    *(DWORD64*)&buf[8 + 29] = startAddress;
    *(DWORD64*)&buf[8 + 45] = flagAddr;
    return buf;
}

// x64 PICI callback stub.
// Layout: [0..7] one-shot flag (QWORD) | [8..121] code entry
// Patch offsets: flagAddr@[12], lParam@[70], startAddress@[80]
// Stack alignment: PICI fires with arbitrary RSP alignment (kernel does not
// normalize it), so we set up an RBP frame and explicitly AND RSP, -16 before
// the call. MOV RSP, RBP afterwards both undoes the alignment and recovers
// from any stack imbalance the callee may have left behind.
static const BYTE stub64_pici[] = {
    // [0] one-shot flag (initially 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // [8] code entry — quick-exit if already fired
    0x50,                                                       // PUSH RAX
    0x51,                                                       // PUSH RCX
    0x48, 0xB9,                                                 // MOVABS RCX, flagAddr
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,           // [12] flagAddr placeholder
    0xB8, 0x01, 0x00, 0x00, 0x00,                              // MOV EAX, 1
    0x87, 0x01,                                                 // XCHG [RCX], EAX (atomic)
    0x85, 0xC0,                                                 // TEST EAX, EAX
    0x59,                                                       // POP RCX
    0x58,                                                       // POP RAX
    0x75, 0x54,                                                 // JNZ .done (target [33+0x54=117])

    // [33] save all GPRs + flags (16 pushes + PUSHFQ = 136 bytes)
    0x50,                                                       // PUSH RAX
    0x51,                                                       // PUSH RCX
    0x52,                                                       // PUSH RDX
    0x53,                                                       // PUSH RBX
    0x55,                                                       // PUSH RBP
    0x56,                                                       // PUSH RSI
    0x57,                                                       // PUSH RDI
    0x41, 0x50,                                                 // PUSH R8
    0x41, 0x51,                                                 // PUSH R9
    0x41, 0x52,                                                 // PUSH R10 (PICI return addr)
    0x41, 0x53,                                                 // PUSH R11
    0x41, 0x54,                                                 // PUSH R12
    0x41, 0x55,                                                 // PUSH R13
    0x41, 0x56,                                                 // PUSH R14
    0x41, 0x57,                                                 // PUSH R15
    0x9C,                                                       // PUSHFQ

    // [57] RBP frame for stack alignment (RBP already saved above)
    0x48, 0x89, 0xE5,                                          // MOV RBP, RSP
    0x48, 0x83, 0xE4, 0xF0,                                    // AND RSP, -16  (align to 16)
    0x48, 0x83, 0xEC, 0x20,                                    // SUB RSP, 0x20 (shadow space)

    // [68] call payload
    0x48, 0xB9,                                                 // MOVABS RCX, lParam
    0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,           // [70] lParam placeholder
    0x48, 0xB8,                                                 // MOVABS RAX, startAddress
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,           // [80] startAddress placeholder
    0xFF, 0xD0,                                                 // CALL RAX

    // [90] restore stack via RBP (also recovers if callee imbalanced RSP)
    0x48, 0x89, 0xEC,                                          // MOV RSP, RBP

    // [93] restore all registers (reverse of push order)
    0x9D,                                                       // POPFQ
    0x41, 0x5F,                                                 // POP R15
    0x41, 0x5E,                                                 // POP R14
    0x41, 0x5D,                                                 // POP R13
    0x41, 0x5C,                                                 // POP R12
    0x41, 0x5B,                                                 // POP R11
    0x41, 0x5A,                                                 // POP R10
    0x41, 0x59,                                                 // POP R9
    0x41, 0x58,                                                 // POP R8
    0x5F,                                                       // POP RDI
    0x5E,                                                       // POP RSI
    0x5D,                                                       // POP RBP
    0x5B,                                                       // POP RBX
    0x5A,                                                       // POP RDX
    0x59,                                                       // POP RCX
    0x58,                                                       // POP RAX

    // [117] .done
    0x41, 0xFF, 0xE2,                                          // JMP R10
    0x0F, 0x0B,                                                 // UD2 (unreachable)
};

static const SIZE_T kPICIStub64Size = sizeof(stub64_pici);

static BYTE* GetPICIStub64(DWORD64 startAddress, DWORD64 lParam, DWORD64 flagAddr, SIZE_T* outSize)
{
    *outSize = sizeof(stub64_pici);
    BYTE* buf = (BYTE*)malloc(*outSize);
    memcpy(buf, stub64_pici, *outSize);
    *(DWORD64*)&buf[12] = flagAddr;
    *(DWORD64*)&buf[70] = lParam;
    *(DWORD64*)&buf[80] = startAddress;
    return buf;
}

// 32-bit PICI stub for WoW64 targets (Version=1).
// The kernel fires this in 32-bit compat mode with EDI = saved return EIP.
// Layout: [0..7] one-shot flag | [8..44] code
// Patch offsets: flagAddr@[16..19] (DWORD), startAddress@[30..33] (DWORD), lParam@[35..38] (DWORD)
static const BYTE stub32_pici[] = {
    // [0..7] one-shot flag (QWORD, only low DWORD used)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // [8] code entry
    0x50,                               // [8]  PUSH EAX
    0x51,                               // [9]  PUSH ECX
    0xB8, 0x01, 0x00, 0x00, 0x00,      // [10..14] MOV EAX, 1
    0xB9, 0xCC, 0xCC, 0xCC, 0xCC,      // [15..19] MOV ECX, flagAddr  <- patch [16..19]
    0x87, 0x01,                         // [20..21] XCHG [ECX], EAX (atomic)
    0x85, 0xC0,                         // [22..23] TEST EAX, EAX
    0x59,                               // [24] POP ECX
    0x58,                               // [25] POP EAX
    0x75, 0x0F,                         // [26..27] JNZ .done (+15 -> [43])
    0x60,                               // [28] PUSHAD
    0xB8, 0xCC, 0xCC, 0xCC, 0xCC,      // [29..33] MOV EAX, startAddress <- patch [30..33]
    0xB9, 0xCC, 0xCC, 0xCC, 0xCC,      // [34..38] MOV ECX, lParam       <- patch [35..38]
    0x51,                               // [39] PUSH ECX
    0xFF, 0xD0,                         // [40..41] CALL EAX
    0x61,                               // [42] POPAD
    // [43] .done
    0xFF, 0xE7,                         // [43..44] JMP EDI  (EDI = return address set by kernel)
};

static const SIZE_T kPICIStub32Size = sizeof(stub32_pici);

static BYTE* GetPICIStub32(DWORD startAddress, DWORD lParam, DWORD64 flagAddr, SIZE_T* outSize)
{
    *outSize = sizeof(stub32_pici);
    BYTE* buf = (BYTE*)malloc(*outSize);
    memcpy(buf, stub32_pici, *outSize);
    *(DWORD*)&buf[16] = (DWORD)flagAddr;
    *(DWORD*)&buf[30] = startAddress;
    *(DWORD*)&buf[35] = lParam;
    return buf;
}

#ifdef __cplusplus
}
#endif

