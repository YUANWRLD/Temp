#pragma once
#include <windows.h>
#include <tdh.h>
#include <evntrace.h>
#include <thread>
#include <string>
#include <mutex>
#include <map>
#include <atomic>
#include <vector>
#include <algorithm>
#include <TlHelp32.h>
#include "../Shared/DetectionEngine.h"

// --- Native API Definitions (加入防護以免衝突) ---

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#endif

#ifndef SystemHandleInformation
#define SystemHandleInformation 16
#endif

// 定義結構，如果尚未定義
#ifndef _SYSTEM_HANDLE_TABLE_ENTRY_INFO_DEFINED
#define _SYSTEM_HANDLE_TABLE_ENTRY_INFO_DEFINED
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
#endif

#ifndef _SYSTEM_HANDLE_INFORMATION_DEFINED
#define _SYSTEM_HANDLE_INFORMATION_DEFINED
typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;
#endif

// 定義函式指標類型
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// --- Provider GUIDs ---
static const GUID FileGuid = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };
static const GUID RegGuid = { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };
static const GUID ProcessGuid = { 0x222962AB, 0x6180, 0x4B88, { 0xA8, 0x25, 0x34, 0x6B, 0x75, 0xF2, 0xA2, 0x48 } };

// --- ProcessTracker ---
class ProcessTracker {
public:
    ProcessTracker();
    void Initialize();
    void Update(DWORD pid, const std::string& imagePath);
    void Remove(DWORD pid);
    std::string GetName(DWORD pid);

private:
    std::map<DWORD, std::string> m_ProcessMap;
    std::mutex m_Mutex;
};

// --- EtwMonitor (整合 Scanner) ---
class EtwMonitor {
public:
    EtwMonitor(DetectionEngine* engine, const std::string& sessionName);
    ~EtwMonitor();

    void Start();
    void Stop();

private:
    // ETW Callback
    static void WINAPI StaticEventRecordCallback(PEVENT_RECORD pEvent);
    void ProcessEvent(PEVENT_RECORD pEvent);
    std::string GetProperty(PEVENT_RECORD pEvent, const std::wstring& propName);

    // Active Handle Scanning Logic
    void ScannerWorker();
    void ScanHandles();
    // [修正] 統一使用 std::string 避免型別錯誤
    DWORD GetPidByName(const std::string& procName);

private:
    DetectionEngine* m_Engine;
    std::string m_SessionName;

    // ETW Resources
    TRACEHANDLE m_hSession = 0;
    TRACEHANDLE m_hTrace = 0;
    std::thread m_EtwThread;

    // Scanner Resources
    std::thread m_ScannerThread;
    _NtQuerySystemInformation NtQuerySystemInformation = nullptr;

    std::atomic<bool> m_IsRunning{ false };

    ProcessTracker m_ProcessTracker;
    static EtwMonitor* s_CurrentInstance;
};