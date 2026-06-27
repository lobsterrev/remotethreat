#pragma once
#include <windows.h>

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

// APC-specific 64-bit stub: CALL entry (OS pushes return addr), so SUB RSP, 0x20 only.
// Ends with RET to return to the OS APC dispatcher. No RIP placeholder needed.
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

// Mode-switching APC stub: 64-bit entry → 32-bit call → 64-bit continuation
// Layout: [64-bit entry @ 0][32-bit stub @ 25][64-bit continuation @ 56], total 70 bytes
static const BYTE crossStub_apc[] = {
    // 64-bit entry (offset 0): save context, switch to 32-bit mode
    0x9C,                                           // PUSHFQ
    0x50,                                           // PUSH RAX
    0x53,                                           // PUSH RBX
    0x51,                                           // PUSH RCX
    0x52,                                           // PUSH RDX
    0x41, 0x50,                                     // PUSH R8
    0x41, 0x51,                                     // PUSH R9
    0x41, 0x52,                                     // PUSH R10
    0x41, 0x53,                                     // PUSH R11
    0x48, 0x8D, 0x05, 0x05, 0x00, 0x00, 0x00,      // LEA RAX, [RIP+5]  → offset 25 (32-bit stub)
    0x6A, 0x23,                                     // PUSH 23h  (32-bit compat CS)
    0x50,                                           // PUSH RAX
    0x48, 0xCB,                                     // RETFQ  → switch to 32-bit mode

    // 32-bit stub (offset 25): call function then switch back to 64-bit
    0x60,                                           // PUSHAD
    0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                  // MOV ECX, lParam       ← patch [27..30]
    0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                  // MOV EAX, startAddress ← patch [32..35]
    0x51,                                           // PUSH ECX
    0xFF, 0xD0,                                     // CALL EAX
    0x61,                                           // POPAD
    0xE8, 0x00, 0x00, 0x00, 0x00,                  // CALL $+5  (get EIP)
    0x5B,                                           // POP EBX  → EBX = stubBase + 45
    0x81, 0xC3, 0x0B, 0x00, 0x00, 0x00,            // ADD EBX, 11  → EBX = stubBase + 56 (continuation)
    0x6A, 0x33,                                     // PUSH 33h  (64-bit CS)
    0x53,                                           // PUSH EBX
    0xCB,                                           // RETF  → switch back to 64-bit mode

    // 64-bit continuation (offset 56): flag write + restore context and return
    0x48, 0xB8,                                     // MOVABS RAX, flagAddr  [58..65]
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xC6, 0x00, 0x01,                               // MOV BYTE PTR [RAX], 1
    0x41, 0x5B,                                     // POP R11
    0x41, 0x5A,                                     // POP R10
    0x41, 0x59,                                     // POP R9
    0x41, 0x58,                                     // POP R8
    0x5A,                                           // POP RDX
    0x59,                                           // POP RCX
    0x5B,                                           // POP RBX
    0x58,                                           // POP RAX
    0x9D,                                           // POPFQ
    0xC3,                                           // RET
};

// static unsigned char piciStubX64[] = {
//   0x50, 0x51, 0x53, 0x55, 0x57, 0x56, 0x54, 0x41, 0x54, 0x41, 0x55, 0x41,
//   0x56, 0x41, 0x57, 0x48, 0x81, 0xec, 0x00, 0x10, 0x00, 0x00, 0x48, 0xb8,
//   0xef, 0xbe, 0xad, 0xde, 0xef, 0xbe, 0xad, 0xde, 0xff, 0xd0, 0x48, 0x81,
//   0xc4, 0x00, 0x10, 0x00, 0x00, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41,
//   0x5c, 0x5c, 0x5e, 0x5f, 0x5d, 0x5b, 0x59, 0x58, 0x41, 0xff, 0xe2, 0x0f,
//   0x0b, 0x90, 0x90, 0x90
// };

BYTE* GetHijackStub32(DWORD startAddress, DWORD lParam, DWORD dwReturnAddress, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = 8 + sizeof(stub32_hijack);
    BYTE* buf = new BYTE[outSize]();
    memcpy(buf + 8, stub32_hijack, sizeof(stub32_hijack));
    *(DWORD*)&buf[8 + 14] = startAddress;
    *(DWORD*)&buf[8 + 19] = lParam;
    *(DWORD*)&buf[8 + 27] = (DWORD)flagAddr;
    *(DWORD*)&buf[8 + 36] = dwReturnAddress;
    return buf;
}

BYTE* GetHijackStub64(DWORD64 startAddress, DWORD64 lParam, DWORD64 dwReturnAddress, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = 8 + sizeof(stub64_hijack);
    BYTE* buf = new BYTE[outSize]();
    memcpy(buf + 8, stub64_hijack, sizeof(stub64_hijack));
    *(DWORD64*)&buf[8 + 27] = lParam;
    *(DWORD64*)&buf[8 + 37] = startAddress;
    *(DWORD64*)&buf[8 + 66] = flagAddr;
    *(DWORD64*)&buf[8 + 79] = dwReturnAddress;
    return buf;
}

BYTE* GetAPCStub32(DWORD startAddress, DWORD lParam, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = 8 + sizeof(stub32_apc);
    BYTE* buf = new BYTE[outSize]();
    memcpy(buf + 8, stub32_apc, sizeof(stub32_apc));
    *(DWORD*)&buf[8 + 1]  = startAddress;
    *(DWORD*)&buf[8 + 6]  = lParam;
    *(DWORD*)&buf[8 + 14] = (DWORD)flagAddr;
    return buf;
}

BYTE* GetAPCCrossStub(DWORD startAddress, DWORD lParam, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = 8 + sizeof(crossStub_apc);
    BYTE* buf = new BYTE[outSize]();
    memcpy(buf + 8, crossStub_apc, sizeof(crossStub_apc));
    *(DWORD*)  &buf[8 + 27] = lParam;
    *(DWORD*)  &buf[8 + 32] = startAddress;
    *(DWORD64*)&buf[8 + 58] = flagAddr;
    return buf;
}

BYTE* GetAPCStub64(DWORD64 startAddress, DWORD64 lParam, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = 8 + sizeof(stub64_apc);
    BYTE* buf = new BYTE[outSize]();
    memcpy(buf + 8, stub64_apc, sizeof(stub64_apc));
    *(DWORD64*)&buf[8 + 19] = lParam;
    *(DWORD64*)&buf[8 + 29] = startAddress;
    *(DWORD64*)&buf[8 + 45] = flagAddr;
    return buf;
}

// x64 PICI callback stub.
// Layout: [0..7] one-shot flag (QWORD) | [8..117] code entry
// Patch offsets: flagAddr@[12], lParam@[64], startAddress@[74]
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
    0x75, 0x50,                                                 // JNZ .done (target [113])

    // [33] save all registers
    0x50,                                                       // PUSH RAX
    0x51,                                                       // PUSH RCX
    0x52,                                                       // PUSH RDX
    0x53,                                                       // PUSH RBX
    0x55,                                                       // PUSH RBP
    0x57,                                                       // PUSH RDI
    0x56,                                                       // PUSH RSI
    0x54,                                                       // PUSH RSP (saves RSP after 7 pushes)
    0x41, 0x50,                                                 // PUSH R8
    0x41, 0x51,                                                 // PUSH R9
    0x41, 0x52,                                                 // PUSH R10 (PICI return addr)
    0x41, 0x53,                                                 // PUSH R11
    0x41, 0x54,                                                 // PUSH R12
    0x41, 0x55,                                                 // PUSH R13
    0x41, 0x56,                                                 // PUSH R14
    0x41, 0x57,                                                 // PUSH R15
    0x9C,                                                       // PUSHFQ
    0x48, 0x83, 0xEC, 0x20,                                    // SUB RSP, 0x20

    // [62] call payload
    0x48, 0xB9,                                                 // MOVABS RCX, lParam
    0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD,           // [64] lParam placeholder
    0x48, 0xB8,                                                 // MOVABS RAX, startAddress
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,           // [74] startAddress placeholder
    0xFF, 0xD0,                                                 // CALL RAX
    0x48, 0x83, 0xC4, 0x20,                                    // ADD RSP, 0x20

    // [88] restore all registers
    0x9D,                                                       // POPFQ
    0x41, 0x5F,                                                 // POP R15
    0x41, 0x5E,                                                 // POP R14
    0x41, 0x5D,                                                 // POP R13
    0x41, 0x5C,                                                 // POP R12
    0x41, 0x5B,                                                 // POP R11
    0x41, 0x5A,                                                 // POP R10
    0x41, 0x59,                                                 // POP R9
    0x41, 0x58,                                                 // POP R8
    0x5C,                                                       // POP RSP (restores via PUSH RSP trick)
    0x5E,                                                       // POP RSI
    0x5F,                                                       // POP RDI
    0x5D,                                                       // POP RBP
    0x5B,                                                       // POP RBX
    0x5A,                                                       // POP RDX
    0x59,                                                       // POP RCX
    0x58,                                                       // POP RAX

    // [113] .done
    0x41, 0xFF, 0xE2,                                          // JMP R10
    0x0F, 0x0B,                                                 // UD2 (unreachable)
};

BYTE* GetPICIStub64(DWORD64 startAddress, DWORD64 lParam, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = sizeof(stub64_pici);
    BYTE* buf = new BYTE[outSize];
    memcpy(buf, stub64_pici, outSize);
    *(DWORD64*)&buf[12] = flagAddr;
    *(DWORD64*)&buf[64] = lParam;
    *(DWORD64*)&buf[74] = startAddress;
    return buf;
}

// WOW64 PICI cross-mode stub: 64-bit callback entry → 32-bit call → 64-bit continuation.
// Layout: [0..7] one-shot flag | [8..57] 64-bit entry | [58..88] 32-bit stub | [89..106] 64-bit continuation
// Patch offsets: flagAddr@[12], lParam@[60] (DWORD), startAddress@[65] (DWORD)
static const BYTE stub64_pici_wow64[] = {
    // [0] one-shot flag (initially 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

    // [8] 64-bit entry — one-shot flag check
    0x50,                                               // PUSH RAX
    0x51,                                               // PUSH RCX
    0x48, 0xB9,                                         // MOVABS RCX, flagAddr
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,   // [12] flagAddr placeholder
    0xB8, 0x01, 0x00, 0x00, 0x00,                      // MOV EAX, 1
    0x87, 0x01,                                         // XCHG [RCX], EAX (atomic)
    0x85, 0xC0,                                         // TEST EAX, EAX
    0x59,                                               // POP RCX
    0x58,                                               // POP RAX
    0x75, 0x45,                                         // JNZ .done → [102]

    // [33] save registers and switch to 32-bit mode
    0x9C,                                               // PUSHFQ
    0x50,                                               // PUSH RAX
    0x53,                                               // PUSH RBX
    0x51,                                               // PUSH RCX
    0x52,                                               // PUSH RDX
    0x41, 0x50,                                         // PUSH R8
    0x41, 0x51,                                         // PUSH R9
    0x41, 0x52,                                         // PUSH R10 (PICI return addr)
    0x41, 0x53,                                         // PUSH R11
    0x48, 0x8D, 0x05, 0x05, 0x00, 0x00, 0x00,          // LEA RAX, [RIP+5] → [58]
    0x6A, 0x23,                                         // PUSH 23h (32-bit CS)
    0x50,                                               // PUSH RAX
    0x48, 0xCB,                                         // RETFQ → switch to 32-bit mode

    // [58] 32-bit stub
    0x60,                                               // PUSHAD
    0xB9, 0xCC, 0xCC, 0xCC, 0xCC,                      // MOV ECX, lParam       ← [60..63]
    0xB8, 0xCC, 0xCC, 0xCC, 0xCC,                      // MOV EAX, startAddress ← [65..68]
    0x51,                                               // PUSH ECX
    0xFF, 0xD0,                                         // CALL EAX
    0x61,                                               // POPAD
    0xE8, 0x00, 0x00, 0x00, 0x00,                      // CALL $+5
    0x5B,                                               // POP EBX → EBX = remoteBase+78
    0x81, 0xC3, 0x0B, 0x00, 0x00, 0x00,               // ADD EBX, 11 → remoteBase+89
    0x6A, 0x33,                                         // PUSH 33h (64-bit CS)
    0x53,                                               // PUSH EBX
    0xCB,                                               // RETF → switch back to 64-bit

    // [89] 64-bit continuation
    0x41, 0x5B,                                         // POP R11
    0x41, 0x5A,                                         // POP R10 (PICI return addr)
    0x41, 0x59,                                         // POP R9
    0x41, 0x58,                                         // POP R8
    0x5A,                                               // POP RDX
    0x59,                                               // POP RCX
    0x5B,                                               // POP RBX
    0x58,                                               // POP RAX
    0x9D,                                               // POPFQ

    // [102] .done
    0x41, 0xFF, 0xE2,                                   // JMP R10
    0x0F, 0x0B,                                         // UD2 (unreachable)
};

BYTE* GetPICIStubWow64(DWORD startAddress, DWORD lParam, DWORD64 flagAddr, SIZE_T& outSize)
{
    outSize = sizeof(stub64_pici_wow64);
    BYTE* buf = new BYTE[outSize];
    memcpy(buf, stub64_pici_wow64, outSize);
    *(DWORD64*)&buf[12] = flagAddr;
    *(DWORD*)  &buf[60] = lParam;
    *(DWORD*)  &buf[65] = startAddress;
    return buf;
}

