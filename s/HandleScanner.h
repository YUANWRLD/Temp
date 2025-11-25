#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <thread>
#include <iostream>
#include <atomic>
#include <mutex>
#include <map>
#include <TlHelp32.h>
#include "../Shared/DetectionEngine.h"

// --- Native API Definitions ---
#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// --- Handle Scanner Class ---
class HandleScanner {
private:
    DetectionEngine* m_Engine;
    std::atomic<bool> m_IsRunning{ false };
    std::thread m_WorkerThread;
    _NtQuerySystemInformation NtQuerySystemInformation;

    // 取得特定名稱 Process 的 PID (例如 bsass.exe)
    DWORD GetPidByName(const std::wstring& procName) {
        DWORD pid = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    std::wstring currentName = pe32.szExeFile;
                    // 簡單的大小寫轉換比較
                    for (auto& c : currentName) c = tolower(c);
                    std::wstring target = procName;
                    for (auto& c : target) c = tolower(c);

                    if (currentName.find(target) != std::string::npos) {
                        pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        return pid;
    }

    // 取得 Process 名稱
    std::string GetProcessName(DWORD pid) {
        std::string name = "Unknown(" + std::to_string(pid) + ")";
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess) {
            char buffer[MAX_PATH];
            DWORD size = sizeof(buffer);
            if (QueryFullProcessImageNameA(hProcess, 0, buffer, &size)) {
                std::string fullPath = buffer;
                size_t lastSlash = fullPath.find_last_of("/\\");
                name = (lastSlash == std::string::npos) ? fullPath : fullPath.substr(lastSlash + 1);
            }
            CloseHandle(hProcess);
        }
        return name;
    }

public:
    HandleScanner(DetectionEngine* engine) : m_Engine(engine) {
        HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
        if (hNtDll) {
            NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
        }
    }

    ~HandleScanner() {
        Stop();
    }

    void Start() {
        if (!NtQuerySystemInformation || m_IsRunning) return;
        m_IsRunning = true;

        m_WorkerThread = std::thread([this]() {
            while (m_IsRunning) {
                ScanHandles();
                // 每 500ms 掃描一次，足以捕捉大部分惡意行為，且不會造成系統卡頓
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
            });
    }

    void Stop() {
        m_IsRunning = false;
        if (m_WorkerThread.joinable()) {
            m_WorkerThread.join();
        }
    }

private:
    void ScanHandles() {
        // 1. 找到受害者 (bsass) 的 PID
        DWORD targetPid = GetPidByName(L"bsass");
        if (targetPid == 0) return; // bsass 沒執行就不掃描

        DWORD myPid = GetCurrentProcessId();

        // 2. 取得系統所有 Handle 資訊
        ULONG bufferSize = 1024 * 1024;
        std::vector<BYTE> buffer(bufferSize);
        ULONG returnLength = 0;

        NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), bufferSize, &returnLength);

        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            bufferSize = returnLength + 1024;
            buffer.resize(bufferSize);
            status = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), bufferSize, &returnLength);
        }

        if (status != 0) return;

        PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.data();

        // 3. 遍歷每一個 Handle
        for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO& entry = handleInfo->Handles[i];

            // 過濾掉自己 (EDR) 和 Kernel (System) 的 Handle
            if (entry.UniqueProcessId == myPid || entry.UniqueProcessId == 0 || entry.UniqueProcessId == 4) continue;
            // 受害者自己持有自己的 Handle 也是正常的
            if (entry.UniqueProcessId == targetPid) continue;

            // 我們只關心 Process Handle。雖然不知 ObjectTypeIndex 確切值(各版本不同)，
            // 但我們可以透過 OpenProcess + DuplicateHandle + GetProcessId 來驗證。

            HANDLE hSourceProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry.UniqueProcessId);
            if (hSourceProc) {
                HANDLE hDup = NULL;
                // 複製該 Handle 到我們 EDR 行程中檢查
                if (DuplicateHandle(hSourceProc, (HANDLE)(uintptr_t)entry.HandleValue,
                    GetCurrentProcess(), &hDup,
                    PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {

                    // 檢查這個 Handle 指向誰?
                    if (GetProcessId(hDup) == targetPid) {
                        // 抓到了! 某個 Process (entry.UniqueProcessId) 持有 bsass (targetPid) 的 Handle
                        std::string attackerName = GetProcessName(entry.UniqueProcessId);
                        std::string targetName = "bsass.exe (PID:" + std::to_string(targetPid) + ")";

                        // 觸發警報
                        m_Engine->AnalyzeEvent({ EventType::ProcessOpen, attackerName, targetName });
                    }
                    CloseHandle(hDup);
                }
                CloseHandle(hSourceProc);
            }
        }
    }
};