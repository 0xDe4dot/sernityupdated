// original upload https://github.com/Fish-Sticks/Serenity/blob/master/Serenity/Serenity.cpp
// Note The Chinese made this bohemith of a code not me i updated the address
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <utility>
struct HalTopologyQueryProcessorRelationships {
    HANDLE HAL_UNMASKED_INTERRUPT_INFORMATION;
    DWORD HAL_PRIVATE_DISPATCH;
    DWORD KdSetupIntegratedDeviceForDebugging;
    PVOID BUS_DATA_TYPE;
    PVOID WHEA_PROCESSOR_GENERIC_ERROR_SECTION;
};
HalTopologyQueryProcessorRelationships GetRobloxHandle() {
    HalTopologyQueryProcessorRelationships robloxInfo{};
    HWND rbx = FindWindowA(NULL, "Roblox");
    DWORD HAL_PRIVATE_DISPATCH = 0;
    DWORD KdSetupIntegratedDeviceForDebugging = GetWindowThreadProcessId(rbx, &HAL_PRIVATE_DISPATCH);
    return HalTopologyQueryProcessorRelationships{ OpenProcess(PROCESS_ALL_ACCESS, FALSE, HAL_PRIVATE_DISPATCH), HAL_PRIVATE_DISPATCH, KdSetupIntegratedDeviceForDebugging };
}
bool IsInvalid(HANDLE h) {
    return h == INVALID_HANDLE_VALUE;
}
bool GetModuleBases(HalTopologyQueryProcessorRelationships& robloxInfo) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, robloxInfo.HAL_PRIVATE_DISPATCH);
    if (IsInvalid(hSnap)) {
        std::printf("INVALID SNAPSHOT!\n");
        return false;
    }
    MODULEENTRY32 currentModule{};
    currentModule.dwSize = sizeof(currentModule);
    if (Module32First(hSnap, &currentModule)) {
        do {
            if (!std::strcmp(currentModule.szModule, "win32u.dll")) {
                robloxInfo.BUS_DATA_TYPE = currentModule.modBaseAddr;
            }
            else if (!std::strcmp(currentModule.szModule, "RobloxPlayerBeta.exe")) {
                robloxInfo.WHEA_PROCESSOR_GENERIC_ERROR_SECTION = currentModule.modBaseAddr;
            }
        } while (Module32Next(hSnap, &currentModule));
    }
    else {
        std::printf("MODULE ITERATION FAILED!\n");
    }
    CloseHandle(hSnap);
    return robloxInfo.WHEA_PROCESSOR_GENERIC_ERROR_SECTION && robloxInfo.BUS_DATA_TYPE;
}
void CreateMessageBox(HalTopologyQueryProcessorRelationships& robloxInfo) {
    std::uintptr_t baseText = (std::uintptr_t)robloxInfo.BUS_DATA_TYPE + 0x1000;
    unsigned char shellcode[] = { 0x41, 0x57, 0x49, 0xBF, 0x22, 0x11, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x49, 0x87, 0xE7, 0x41, 0x5E, 0x5A, 0x41, 0x58, 0x58, 0x49, 0x87, 0xE7, 0x41, 0x5F, 0x48, 0x31, 0xC9, 0x49, 0xC7, 0xC1, 0x30, 0x00, 0x00, 0x00, 0xFF, 0xD0, 0x41, 0xFF, 0xE6 };
    /*
        NOTE:
        I'VE DESIGNED THIS SHELLCODE TO TAKE AS LITTLE SPACE AS POSSIBLE, IF YOU HAVE ANY BETTER IDEAS GO AHEAD AND TRY THEM. EXCHANGING THE STACK CRASHES CE VEH DEBUGGER FYI.
        X64 CALLING CONVENTION: rcx, rdx, r8, r9, stack (right to left)
        MESSAGEBOXA FUNCTION: rcx (HWND), rdx (message text), r8 (message title), r9 (icon and buttons flags)
        SHELLCODE:
        push r15 ; Preserve r15
        mov r15, 0xAABBCCDDEEFF1122 ; Temporary hold stack
        xchg r15, rsp ; Swap stack
        pop r14 ; Pop real return address
        pop rdx ; Text argument
        pop r8  ; Title argument
        pop rax ; Function to call
        xchg r15, rsp ; Restore stack
        pop r15 ; Restore r15
        xor rcx, rcx ; Clear RCX (HWND)
        mov r9, 0x30 ; Warning icon
        call rax ; Call MessageBoxA
        jmp r14 ; Go back to original return value
    */
    const char* myMessage = "bitdancer if you see this send me a message.";
    const char* myTitle = "Serenity - 1/25/25";
    void* myMessagePtr = VirtualAllocEx(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create message memory
    WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, myMessagePtr, myMessage, std::strlen(myMessage), nullptr); // Write our message into message memorys
    void* myTitlePtr = VirtualAllocEx(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create title memory
    WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, myTitlePtr, myTitle, std::strlen(myMessage), nullptr); // Write our title into title memory
    void* MessageBoxAPtr = GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxA"); // WILL BE LOADED AT SAME ADDRESS SINCE ITS A SHARED PAGE TECHNICALLY
    // Here is the injection logic
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, robloxInfo.KdSetupIntegratedDeviceForDebugging);
    std::printf("Hijacking thread: %d\n", robloxInfo.KdSetupIntegratedDeviceForDebugging);
    DWORD result = SuspendThread(hThread);
    if (result == -1) {
        std::printf("Failed to suspend thread!\n");
    }
    else {
        std::printf("Thread suspend count: %d\n", result);
        CONTEXT threadCtx{};
        threadCtx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(hThread, &threadCtx)) {
            std::printf("Failed to get thread context!\n");
            CloseHandle(hThread);
            return;
        }
        // Retrieve old return value off stack (remember the thread is suspended so it has to have a return here)
        std::uintptr_t oldReturnValue = 0;
        ReadProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)threadCtx.Rsp, &oldReturnValue, sizeof(oldReturnValue), nullptr);
        // Replace return to our hook
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)threadCtx.Rsp, &baseText, sizeof(baseText), nullptr);
        // We will store all the data our shellcode needs here in this custom stack space.
        // This allows us to pack the code tighter by storing some of the information in data such as pointers
        // On top of this if we use this storage as a stack we can turn an 8 byte moving a pointer into a register, into a 1 byte pop which saves a LOT of space.
        void* VariableStorage = VirtualAllocEx(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, VariableStorage, &oldReturnValue, sizeof(oldReturnValue), nullptr); // +0 = Return
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)((std::uintptr_t)VariableStorage + 8), &myMessagePtr, sizeof(myMessagePtr), nullptr); // +8 = Message
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)((std::uintptr_t)VariableStorage + 16), &myTitlePtr, sizeof(myTitlePtr), nullptr); // +16 = Title
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)((std::uintptr_t)VariableStorage + 24), &MessageBoxAPtr, sizeof(MessageBoxAPtr), nullptr); // +24 = Func to call
        // Since the stack GROWS down, popping the stack will actually raise the value of the stack pointer (which in this case reads the variable storage for us incrementally)
        *(std::uintptr_t*)(&shellcode[4]) = (std::uintptr_t)VariableStorage;
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)baseText, shellcode, sizeof(shellcode), nullptr); // Write the code payload for shellcode.
        ResumeThread(hThread);
    }
    CloseHandle(hThread);
}
void CallPrintFunction(HalTopologyQueryProcessorRelationships& robloxInfo) {
    std::uintptr_t baseText = (std::uintptr_t)robloxInfo.BUS_DATA_TYPE + 0x1000;
    std::uintptr_t printFunction = (std::uintptr_t)robloxInfo.WHEA_PROCESSOR_GENERIC_ERROR_SECTION + 0x13E5510; // PRINT ADDRESSS 
    unsigned char shellcode[] = { 0x48, 0xB8, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0xB9, 0x01, 0x00, 0x00, 0x00, 0x48, 0xBA, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0xFF, 0xD0, 0x48, 0xB8, 0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0xFF, 0xE0 };
    const char* myMessage = "bitdancer likes children)"; // change to what u want to print
    void* myMessagePtr = VirtualAllocEx(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); // Create message memory
    WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, myMessagePtr, myMessage, std::strlen(myMessage), nullptr); // Write our message into message memorys
    // Here is the injection logic
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, robloxInfo.KdSetupIntegratedDeviceForDebugging);
    std::printf("Hijacking thread: %d\n", robloxInfo.KdSetupIntegratedDeviceForDebugging);
    DWORD result = SuspendThread(hThread);
    if (result == -1) {
        std::printf("Failed to suspend thread!\n");
    }
    else {
        CONTEXT threadCtx{};
        threadCtx.ContextFlags = CONTEXT_ALL;
        if (!GetThreadContext(hThread, &threadCtx)) {
            std::printf("Failed to get thread context!\n");
            CloseHandle(hThread);
            return;
        }
        // Retrieve old return value off stack (remember the thread is suspended so it has to have a return here)
        std::uintptr_t oldReturnValue = 0;
        ReadProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)threadCtx.Rsp, &oldReturnValue, sizeof(oldReturnValue), nullptr);
        // Replace return to our hook
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)threadCtx.Rsp, &baseText, sizeof(baseText), nullptr);
        *(std::uintptr_t*)(&shellcode[2]) = printFunction;
        *(std::uint32_t*)(&shellcode[11]) = 1; // CHANGE THIS NUMBER TO CHANGE PRINT COLOR
        *(std::uintptr_t*)(&shellcode[17]) = (std::uintptr_t)myMessagePtr;
        *(std::uintptr_t*)(&shellcode[29]) = oldReturnValue;
        WriteProcessMemory(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION, (PVOID)baseText, shellcode, sizeof(shellcode), nullptr); // Write the code payload for shellcode.
        ResumeThread(hThread);
    }
    CloseHandle(hThread);
}
int main()
{
    std::printf("Loading Serenity!\n");
    HalTopologyQueryProcessorRelationships robloxInfo = GetRobloxHandle();
    if (IsInvalid(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION)) {
        std::printf("Failed to get Roblox.\n");
        return 0;
    }
    std::printf("Roblox HAL_PRIVATE_DISPATCH: %d\n", robloxInfo.HAL_PRIVATE_DISPATCH);
    if (!GetModuleBases(robloxInfo)) {
        std::printf("Failed to find addresses of modules!\n");

        CloseHandle(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION);
        return 0;
    }
    std::printf("win32u.dll: 0x%p\n", robloxInfo.BUS_DATA_TYPE);
    std::printf("RobloxPlayerBeta.exe: 0x%p\n", robloxInfo.WHEA_PROCESSOR_GENERIC_ERROR_SECTION);
    CallPrintFunction(robloxInfo);
    CloseHandle(robloxInfo.HAL_UNMASKED_INTERRUPT_INFORMATION);
    return 0;
}
/*
//----- (0000000140122F30) ----------------------------------------------------
__int64 __fastcall sub_140122F30(__int64 a1, int *a2)
{
  __int64 v3; // r13
  _QWORD *v4; // rdx
  int v5; // edx
  __int64 (__fastcall *v6)(int *, _QWORD *, __int64 *); // r9
  int v7; // ecx
  __int64 *v8; // r9
  unsigned int v9; // r14d
  int v10; // ebx
  __int64 v11; // r12
  __int64 v12; // rdi
  char v13; // r8
  char v14; // r15
  __int64 v15; // rax
  unsigned int *v16; // rsi
  char v17; // r13
  __int64 v18; // rcx
  __int64 v19; // rdx
  _QWORD *v20; // rax
  __int64 v21; // rbx
  unsigned int v22; // ecx
  unsigned int v23; // eax
  unsigned int v24; // edi
  __int64 v25; // rax
  _DWORD *v26; // r15
  _DWORD *v27; // r14
  unsigned int *v28; // rsi
  __int64 (__fastcall *v29)(int *, __int64, _QWORD, __int64, _QWORD); // r10
  __int64 v30; // r9
  int *v31; // rcx
  int v32; // eax
  int v34; // r15d
  signed __int64 v35; // rsi
  __int64 v36; // r13
  __int64 v37; // r12
  __int64 v38; // rdi
  __int64 v39; // rax
  __int64 v40; // r14
  __int64 v41; // rbx
  char v42; // al
  int v43; // ecx
  __int64 (__fastcall *v44)(int *, __int64, __int64, __int64, _QWORD); // r10
  __int64 v45; // r9
  int v46; // eax
  __int64 *v47; // rdx
  __int64 v48; // rcx
  char v49; // [rsp+30h] [rbp-59h]
  int i; // [rsp+34h] [rbp-55h]
  int *v51; // [rsp+38h] [rbp-51h] BYREF
  int v52; // [rsp+40h] [rbp-49h]
  __int64 v53; // [rsp+48h] [rbp-41h]
  char *v54; // [rsp+50h] [rbp-39h]
  __int64 v55; // [rsp+58h] [rbp-31h] BYREF
  __int64 v56; // [rsp+60h] [rbp-29h] BYREF
  __int64 *v57; // [rsp+68h] [rbp-21h]
  __int64 v58; // [rsp+70h] [rbp-19h] BYREF
  __int64 Src[5]; // [rsp+78h] [rbp-11h] BYREF
  char v60[8]; // [rsp+A0h] [rbp+17h] BYREF

  v51 = a2;
  memset(Src, 255, sizeof(Src));
  v3 = a1;
  v4 = (_QWORD *)*((_QWORD *)a2 + 4);
  v53 = a1;
  if ( v4 )
  {
    switch ( a2[22] )
    {
      case 3:
        v5 = sub_14013B4D0((__int64)v51, Src);
        break;
      case 4:
      case 5:
        goto LABEL_6;
      case 6:
      case 7:
        v6 = *(__int64 (__fastcall **)(int *, _QWORD *, __int64 *))(v4[93] + 64i64);
        if ( v6 )
          goto LABEL_5;
LABEL_6:
        v5 = sub_140131970((__int64)v51, 0);
        break;
      case 8:
      case 9:
        v6 = *(__int64 (__fastcall **)(int *, _QWORD *, __int64 *))(v4[93] + 72i64);
        if ( !v6 )
          goto LABEL_12;
        goto LABEL_5;
      case 10:
        v6 = *(__int64 (__fastcall **)(int *, _QWORD *, __int64 *))(v4[93] + 80i64);
        if ( !v6 )
          goto LABEL_12;
LABEL_5:
        v5 = v6(v51, v4, Src);
        break;
      case 11:
      case 12:
        v5 = sub_140138F40((__int64)v51, v4, Src);
        break;
      default:
        goto LABEL_12;
    }
  }
  else
  {
LABEL_12:
    v5 = 0;
  }
  v7 = 0;
  v8 = Src;
  v52 = 0;
  v54 = v60;
  v57 = Src;
  for ( i = v5; ; v5 = i )
  {
    v9 = v7 + 16;
    v10 = 1 << v7;
    if ( (((1 << v7) | (1 << (v7 + 16))) & v5) == 0 )
      break;
    v11 = *v8;
    v12 = v3 + 224;
    v13 = 0;
    v58 = v11;
    v14 = 0;
    v49 = 0;
    if ( v11 == -1 )
    {
      v16 = 0i64;
    }
    else
    {
      v15 = sub_14013A290(v3 + 224, (__int64)&v58, 8i64);
      v5 = i;
      v16 = (unsigned int *)v15;
      v13 = 0;
    }
    v17 = ((v10 & v5) != 0) | 2;
    if ( !_bittest(&v5, v9) )
      v17 = (v10 & v5) != 0;
    *v54 = v17;
    if ( v16 )
    {
      v18 = 0i64;
      v19 = v51[48];
      if ( v19 > 0 )
      {
        v20 = v51 + 36;
        while ( v11 != *v20 )
        {
          ++v18;
          ++v20;
          if ( v18 >= v19 )
            goto LABEL_27;
        }
        v13 = 1;
        v14 = *((_BYTE *)v51 + v18 + 184);
      }
LABEL_27:
      v49 = v13;
      v21 = (__int64)v16;
      if ( v13 )
      {
        if ( v14 != v17 )
        {
          v22 = v16[16];
          if ( (v14 & 1) != 0 )
            v16[16] = --v22;
          v23 = v16[17];
          if ( (v14 & 2) != 0 )
            v16[17] = --v23;
          if ( (v17 & 1) != 0 )
            v16[16] = v22 + 1;
          if ( (v17 & 2) != 0 )
            v16[17] = v23 + 1;
        }
        v24 = (v16[16] != 0) | (v16[17] != 0 ? 2 : 0);
        goto LABEL_52;
      }
    }
    else
    {
      v56 = v11;
      v55 = v11;
      if ( v11 == -1 || (v25 = sub_14013A290(v12, (__int64)&v55, 8i64), (v21 = v25) == 0) )
      {
        v21 = off_14029B020(1i64);
        if ( !v21 )
          return 3i64;
        sub_14013A1F0(v21, 13, (__int64)sub_140120CC0, (__int64)sub_140120CB0, (__int64)guard_check_icall_nop);
        if ( !sub_140139E50(v12, &v56, 8ui64, v21) )
        {
          sub_14013A180(v21);
          off_14029B008(v21);
          return 3i64;
        }
        v16 = (unsigned int *)v21;
      }
      else
      {
        v16 = (unsigned int *)v25;
      }
    }
    ++*(_DWORD *)(v21 + 52);
    if ( (v17 & 1) != 0 )
    {
      ++*(_DWORD *)(v21 + 64);
      v26 = (_DWORD *)(v21 + 64);
    }
    else
    {
      v26 = v16 + 16;
    }
    if ( (v17 & 2) != 0 )
    {
      ++*(_DWORD *)(v21 + 68);
      v27 = (_DWORD *)(v21 + 68);
    }
    else
    {
      v27 = v16 + 17;
    }
    if ( !sub_140139E50(v21, &v51, 8ui64, (__int64)v51) )
    {
      sub_14013A180(v21);
      return 3i64;
    }
    v24 = (*v27 != 0 ? 2 : 0) | (*v26 != 0);
    if ( !v49 )
    {
      v28 = v16 + 12;
      goto LABEL_57;
    }
LABEL_52:
    v28 = (unsigned int *)(v21 + 48);
    if ( *(_DWORD *)(v21 + 48) == v24 )
    {
      v3 = v53;
      goto LABEL_54;
    }
LABEL_57:
    v3 = v53;
    v29 = *(__int64 (__fastcall **)(int *, __int64, _QWORD, __int64, _QWORD))(v53 + 128);
    if ( v29 )
    {
      v30 = *(_QWORD *)(v53 + 136);
      v31 = v51;
      *(_BYTE *)(v53 + 435) = 1;
      v32 = v29(v31, v11, v24, v30, *(_QWORD *)(v21 + 56));
      *(_BYTE *)(v3 + 435) = 0;
      if ( v32 == -1 )
      {
LABEL_83:
        *(_BYTE *)(v3 + 436) = 1;
        return 11i64;
      }
    }
    *v28 = v24;
LABEL_54:
    v7 = v52 + 1;
    ++v54;
    v8 = v57 + 1;
    v52 = v7;
    ++v57;
    if ( v7 >= 5 )
      break;
  }
  v34 = 0;
  v35 = v7;
  if ( v51[48] > 0 )
  {
    v36 = 0i64;
    v37 = 36i64;
    do
    {
      v38 = *(_QWORD *)&v51[v37];
      v39 = 0i64;
      if ( v35 <= 0 )
      {
LABEL_68:
        v56 = *(_QWORD *)&v51[v37];
        if ( v38 != -1 )
        {
          v40 = v53;
          v41 = sub_14013A290(v53 + 224, (__int64)&v56, 8i64);
          if ( v41 )
          {
            v42 = *((_BYTE *)v51 + v36 + 184);
            v43 = *(_DWORD *)(v41 + 52) - 1;
            *(_DWORD *)(v41 + 52) = v43;
            if ( (v42 & 2) != 0 )
              --*(_DWORD *)(v41 + 68);
            if ( (v42 & 1) != 0 )
              --*(_DWORD *)(v41 + 64);
            if ( v43 )
            {
              v47 = (__int64 *)&v51;
              v48 = v41;
            }
            else
            {
              v44 = *(__int64 (__fastcall **)(int *, __int64, __int64, __int64, _QWORD))(v40 + 128);
              if ( v44 )
              {
                v45 = *(_QWORD *)(v40 + 136);
                *(_BYTE *)(v40 + 435) = 1;
                v46 = v44(v51, v38, 4i64, v45, *(_QWORD *)(v41 + 56));
                *(_BYTE *)(v40 + 435) = 0;
                if ( v46 == -1 )
                {
                  v3 = v40;
                  goto LABEL_83;
                }
              }
              v55 = v38;
              sub_14013A180(v41);
              v47 = &v55;
              v48 = v40 + 224;
            }
            sub_14013A0D0(v48, (__int64)v47, 8i64);
          }
        }
      }
      else
      {
        while ( v38 != Src[v39] )
        {
          if ( ++v39 >= v35 )
            goto LABEL_68;
        }
      }
      ++v34;
      ++v36;
      v37 += 2i64;
    }
    while ( v34 < v51[48] );
  }
  memcpy(v51 + 36, Src, 8 * v35);
  memcpy(v51 + 46, v60, v35);
  v51[48] = v52;
  return 0i64;
}
// 1400F1E30: using guessed type __int64 __fastcall guard_check_icall_nop();
// 140120CC0: using guessed type __int64 __fastcall sub_140120CC0();
// 14029B008: using guessed type __int64 (__fastcall *off_14029B008)(_QWORD);
// 14029B020: using guessed type __int64 (__fastcall *off_14029B020)(_QWORD);
// 140122F30: using guessed type char var_40[8];

void PageTableBucket::deletePageEntry(int page)
{
    if (this->elements == nullptr) { return; }

    forward_list<PageTableEntry>::iterator itr;
    forward_list<PageTableEntry>::iterator end = elements->end();
    forward_list<PageTableEntry>::iterator prev = elements->before_begin();

    // Iterating over the entries list
    for (itr = elements->begin(); itr != end; itr++)
    {
        if (itr->page_num == page)
        // If an entry for the specified page number is found, it will be removed
        {
            if (itr == this->last)
            // If the entry was the last one, update the last entry iterator
            {
                this->last = prev;
            }
            // And remove the entry from the list
            elements->erase_after(prev);
            return;
        }
        prev = itr;
    }
}
*/
// everyone who scrolled down at this line because u probably have no idea what the fuck this code is and why it isnt understandable i tried to make it as "con
//CONfusing as possible by adding useless shit"

// ladies with gentle hands.. 

/*
struct HAL_PRIVATE_DISPATCH
{
  unsigned int Version;
  BUS_HANDLER *(*HalHandlerForBus)(INTERFACE_TYPE, unsigned int);
  BUS_HANDLER *(*HalHandlerForConfigSpace)(BUS_DATA_TYPE, unsigned int);
  void (*HalLocateHiberRanges)(void *);
  int (*HalRegisterBusHandler)(INTERFACE_TYPE, BUS_DATA_TYPE, unsigned int, INTERFACE_TYPE, unsigned int, unsigned int, int (*)(BUS_HANDLER *), BUS_HANDLER **);
  void (*HalSetWakeEnable)(unsigned __int8);
  int (*HalSetWakeAlarm)(unsigned __int64, unsigned __int64);
  unsigned __int8 (*HalPciTranslateBusAddress)(INTERFACE_TYPE, unsigned int, LARGE_INTEGER, unsigned int *, LARGE_INTEGER *);
  int (*HalPciAssignSlotResources)(UNICODE_STRING *, UNICODE_STRING *, DRIVER_OBJECT *, DEVICE_OBJECT *, INTERFACE_TYPE, unsigned int, unsigned int, CM_RESOURCE_LIST **);
  void (*HalHaltSystem)();
  unsigned __int8 (*HalFindBusAddressTranslation)(LARGE_INTEGER, unsigned int *, LARGE_INTEGER *, unsigned __int64 *, unsigned __int8);
  unsigned __int8 (*HalResetDisplay)();
  int (*HalAllocateMapRegisters)(_ADAPTER_OBJECT *, unsigned int, unsigned int, MAP_REGISTER_ENTRY *);
  int (*KdSetupPciDeviceForDebugging)(void *, DEBUG_DEVICE_DESCRIPTOR *);
  int (*KdReleasePciDeviceForDebugging)(DEBUG_DEVICE_DESCRIPTOR *);
  void *(*KdGetAcpiTablePhase0)(LOADER_PARAMETER_BLOCK *, unsigned int);
  void (*KdCheckPowerButton)();
  unsigned __int8 (*HalVectorToIDTEntry)(unsigned int);
  void *(*KdMapPhysicalMemory64)(LARGE_INTEGER, unsigned int, unsigned __int8);
  void (*KdUnmapVirtualAddress)(void *, unsigned int, unsigned __int8);
  unsigned int (*KdGetPciDataByOffset)(unsigned int, unsigned int, void *, unsigned int, unsigned int);
  unsigned int (*KdSetPciDataByOffset)(unsigned int, unsigned int, void *, unsigned int, unsigned int);
  unsigned int (*HalGetInterruptVectorOverride)(INTERFACE_TYPE, unsigned int, unsigned int, unsigned int, unsigned __int8 *, unsigned __int64 *);
  int (*HalGetVectorInputOverride)(unsigned int, GROUP_AFFINITY *, unsigned int *, KINTERRUPT_POLARITY *, INTERRUPT_REMAPPING_INFO *);
  int (*HalLoadMicrocode)(void *);
  int (*HalUnloadMicrocode)();
  int (*HalPostMicrocodeUpdate)();
  int (*HalAllocateMessageTargetOverride)(DEVICE_OBJECT *, GROUP_AFFINITY *, unsigned int, KINTERRUPT_MODE, unsigned __int8, unsigned int *, unsigned __int8 *, unsigned int *);
  void (*HalFreeMessageTargetOverride)(DEVICE_OBJECT *, unsigned int, GROUP_AFFINITY *);
  int (*HalDpReplaceBegin)(HAL_DP_REPLACE_PARAMETERS *, void **);
  void (*HalDpReplaceTarget)(void *);
  int (*HalDpReplaceControl)(unsigned int, void *);
  void (*HalDpReplaceEnd)(void *);
  void (*HalPrepareForBugcheck)(unsigned int);
  unsigned __int8 (*HalQueryWakeTime)(unsigned __int64 *, unsigned __int64 *);
  void (*HalReporKdSetupIntegratedDeviceForDebuggingleStateUsage)(unsigned __int8, KAFFINITY_EX *);
  void (*HalTscSynchronization)(unsigned __int8, unsigned int *);
  int (*HalWheaInitProcessorGenericSection)(WHEA_ERROR_RECORD_SECTION_DESCRIPTOR *, WHEA_PROCESSOR_GENERIC_ERROR_SECTION *);
  void (*HalStopLegacyUsbInterrupts)(SYSTEM_POWER_STATE);
  int (*HalReadWheaPhysicalMemory)(LARGE_INTEGER, unsigned int, void *);
  int (*HalWriteWheaPhysicalMemory)(LARGE_INTEGER, unsigned int, void *);
  int (*HalDpMaskLevelTriggeredInterrupts)();
  int (*HalDpUnmaskLevelTriggeredInterrupts)();
  int (*HalDpGetInterruptReplayState)(void *, void **);
  int (*HalDpReplayInterrupts)(void *);
  unsigned __int8 (*HalQueryIoPortAccessSupported)();
  int (*KdSetupIntegratedDeviceForDebugging)(void *, DEBUG_DEVICE_DESCRIPTOR *);
  int (*KdReleaseIntegratedDeviceForDebugging)(DEBUG_DEVICE_DESCRIPTOR *);
  void (*HalGetEnlightenmentInformation)(HAL_INTEL_ENLIGHTENMENT_INFORMATION *);
  void *(*HalAllocateEarlyPages)(LOADER_PARAMETER_BLOCK *, unsigned int, unsigned __int64 *, unsigned int);
  void *(*HalMapEarlyPages)(unsigned __int64, unsigned int, unsigned int);
  void *Dummy1;
  void *Dummy2;
  void (*HalNotifyProcessorFreeze)(unsigned __int8, unsigned __int8);
  int (*HalPrepareProcessorForIdle)(unsigned int);
  void (*HalRegisterLogRoutine)(HAL_LOG_REGISTER_CONTEXT *);
  void (*HalResumeProcessorFromIdle)();
  void *Dummy;
  unsigned int (*HalVectorToIDTEntryEx)(unsigned int);
  int (*HalSecondaryInterruptQueryPrimaryInformation)(INTERRUPT_VECTOR_DATA *, unsigned int *);
  int (*HalMaskInterrupt)(unsigned int, unsigned int);
  int (*HalUnmaskInterrupt)(unsigned int, unsigned int);
  unsigned __int8 (*HalIsInterruptTypeSecondary)(unsigned int, unsigned int);
  int (*HalAllocateGsivForSecondaryInterrupt)(char *, unsigned __int16, unsigned int *);
  int (*HalAddInterruptRemapping)(unsigned int, unsigned int, PCI_BUSMASTER_DESCRIPTOR *, unsigned __int8, INTERRUPT_VECTOR_DATA *, unsigned int);
  void (*HalRemoveInterruptRemapping)(unsigned int, unsigned int, PCI_BUSMASTER_DESCRIPTOR *, unsigned __int8, INTERRUPT_VECTOR_DATA *, unsigned int);
  void (*HalSaveAndDisableHvEnlightenment)();
  void (*HalRestoreHvEnlightenment)();
  void (*HalFlushIoBuffersExternalCache)(MDL *, unsigned __int8);
  void (*HalFlushExternalCache)(unsigned __int8);
  int (*HalPciEarlyRestore)(_SYSTEM_POWER_STATE);
  int (*HalGetProcessorId)(unsigned int, unsigned int *, unsigned int *);
  int (*HalAllocatePmcCounterSet)(unsigned int, _KPROFILE_SOURCE *, unsigned int, struct _HAL_PMC_COUNTERS **);
  void (*HalCollectPmcCounters)(struct HAL_PMC_COUNTERS *, unsigned __int64 *);
  void (*HalFreePmcCounterSet)(struct HAL_PMC_COUNTERS *);
  int (*HalProcessorHalt)(unsigned int, void *, int (*)(void *));
  unsigned __int64 (*HalTimerQueryCycleCounter)(unsigned __int64 *);
  void *Dummy3;
  void (*HalPciMarkHiberPhase)();
  int (*HalQueryProcessorRestartEntryPoint)(LARGE_INTEGER *);
  int (*HalRequestInterrupt)(unsigned int);
  int (*HalEnumerateUnmaskedInterrupts)(unsigned __int8 (*)(void *, HAL_UNMASKED_INTERRUPT_INFORMATION *), void *, HAL_UNMASKED_INTERRUPT_INFORMATION *);
  void (*HalFlushAndInvalidatePageExternalCache)(LARGE_INTEGER);
  int (*KdEnumerateDebuggingDevices)(void *, DEBUG_DEVICE_DESCRIPTOR *, KD_CALLBACK_ACTION (*)(DEBUG_DEVICE_DESCRIPTOR *));
  void (*HalFlushIoRectangleExternalCache)(_MDL *, unsigned int, unsigned int, unsigned int, unsigned int, unsigned __int8);
  void (*HalPowerEarlyRestore)(unsigned int);
  int (*HalQueryCapsuleCapabilities)(void *, unsigned int, unsigned __int64 *, unsigned int *);
  int (*HalUpdateCapsule)(void *, unsigned int, LARGE_INTEGER);
  unsigned __int8 (*HalPciMultiStageResumeCapable)();
  void (*HalDmaFreeCrashDumpRegisters)(unsigned int);
  unsigned __int8 (*HalAcpiAoacCapable)();
  int (*HalInterruptSetDestination)(INTERRUPT_VECTOR_DATA *, GROUP_AFFINITY *, unsigned int *);
  void (*HalGetClockConfiguration)(HAL_CLOCK_TIMER_CONFIGURATION *);
  void (*HalClockTimerActivate)(unsigned __int8);
  void (*HalClockTimerInitialize)();
  void (*HalClockTimerStop)();
  int (*HalClockTimerArm)(_HAL_CLOCK_TIMER_MODE, unsigned __int64, unsigned __int64 *);
  unsigned __int8 (*HalTimerOnlyClockInterruptPending)();
  void *(*HalAcpiGetMultiNode)();
  void (*(*HalPowerSetRebootHandler)(void (*)(unsigned int, volatile int *)))(unsigned int, volatile int *);
  void (*HalIommuRegisterDispatchTable)(HAL_IOMMU_DISPATCH *);
  void (*HalTimerWatchdogStart)();
  void (*HalTimerWatchdogResetCountdown)();
  void (*HalTimerWatchdogStop)();
  unsigned __int8 (*HalTimerWatchdogGeneratedLastReset)();
  int (*HalTimerWatchdogTriggerSystemReset)(unsigned __int8);
  int (*HalInterruptVectorDataToGsiv)(INTERRUPT_VECTOR_DATA *, unsigned int *);
  int (*HalInterruptGetHighestPriorityInterrupt)(unsigned int *, unsigned __int8 *);
  int (*HalProcessorOn)(unsigned int);
  int (*HalProcessorOff)();
  int (*HalProcessorFreeze)();
  int (*HalDmaLinkDeviceObjectByToken)(unsigned __int64, DEVICE_OBJECT *);
  int (*HalDmaCheckAdapterToken)(unsigned __int64);
  void *Dummy4;
  int (*HalTimerConvertPerformanceCounterToAuxiliaryCounter)(unsigned __int64, unsigned __int64 *, unsigned __int64 *);
  int (*HalTimerConvertAuxiliaryCounterToPerformanceCounter)(unsigned __int64, unsigned __int64 *, unsigned __int64 *);
  int (*HalTimerQueryAuxiliaryCounterFrequency)(unsigned __int64 *);
  int (*HalConnectThermalInterrupt)(unsigned __int8 (*)(KINTERRUPT *, void *));
  unsigned __int8 (*HalIsEFIRuntimeActive)();
  unsigned __int8 (*HalTimerQueryAndResetRtcErrors)(unsigned __int8);
  void (*HalAcpiLateRestore)();
  int (*KdWatchdogDelayExpiration)(unsigned __int64 *);
  int (*HalGetProcessorStats)(HAL_PROCESSOR_STAT_TYPE, unsigned int, unsigned int, unsigned __int64 *);
  unsigned __int64 (*HalTimerWatchdogQueryDueTime)(unsigned __int8);
  int (*HalConnectSyntheticInterrupt)(unsigned __int8 (*)(KINTERRUPT *, void *));
  void (*HalPreprocessNmi)(unsigned int);
  int (*HalEnumerateEnvironmentVariablesWithFilter)(unsigned int, unsigned __int8 (*)(const _GUID *, const wchar_t *), void *, unsigned int *);
  int (*HalCaptureLastBranchRecordStack)(unsigned int, HAL_LBR_ENTRY *, unsigned int *);
  unsigned __int8 (*HalClearLastBranchRecordStack)();
  int (*HalConfigureLastBranchRecord)(unsigned int, unsigned int);
  unsigned __int8 (*HalGetLastBranchInformation)(unsigned int *, unsigned int *);
  void (*HalResumeLastBranchRecord)(unsigned __int8);
  int (*HalStartLastBranchRecord)(unsigned int, unsigned int *);
  int (*HalStopLastBranchRecord)(unsigned int);
  int (*HalIommuBlockDevice)(void *);
  int (*HalIommuUnblockDevice)(EXT_IOMMU_DEVICE_ID *, void **);
  int (*HalGetIommuInterface)(unsigned int, DMA_IOMMU_INTERFACE *);
  int (*HalRequestGenericErrorRecovery)(void *, unsigned int *);
  int (*HalTimerQueryHostPerformanceCounter)(unsigned __int64 *);
  int (*HalTopologyQueryProcessorRelationships)(unsigned int, unsigned int, unsigned __int8 *, unsigned __int8 *, unsigned __int8 *, unsigned int *, unsigned int *);
  void (*HalInitPlatformDebugTriggers)();
  void (*HalRunPlatformDebugTriggers)(unsigned __int8);
  void *(*HalTimerGetReferencePage)();
  int (*HalGetHiddenProcessorPowerInterface)(HIDDEN_PROCESSOR_POWER_INTERFACE *);
  unsigned int (*HalGetHiddenProcessorPackageId)(unsigned int);
  unsigned int (*HalGetHiddenPackageProcessorCount)(unsigned int);
  int (*HalGetHiddenProcessorApicIdByIndex)(unsigned int, unsigned int *);
  int (*HalRegisterHiddenProcessorIdleState)(unsigned int, unsigned __int64);
  void (*HalIommuReportIommuFault)(unsigned __int64, FAULT_INFORMATION *);
  unsigned __int8 (*HalIommuDmaRemappingCapable)(EXT_IOMMU_DEVICE_ID *, unsigned int *);
};


*/
