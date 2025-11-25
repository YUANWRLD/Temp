#pragma once
#include <windows.h>
#include <tdh.h>
#include <evntrace.h>
#include <thread>
#include <string>
#include <mutex>
#include <map>
#include <TlHelp32.h>
#include "../Shared/DetectionEngine.h"

// ETW - TI READVM_REMOTE 的事件結構(根據逆向工程結果)
#pragma pack(push, 1)
struct TiReadVmRemoteEvent {
    uint32_t CallingProcessId; // 誰在讀 (攻擊者)
    uint32_t TargetProcessId;  // 讀誰 (受害者, e.g., lsass)
    uint32_t CallingTid;
    uint64_t BaseAddress;      // 讀取位址
    uint64_t RegionSize;       // 讀取大小
    // ... 後面可能還有 Flags，但我們只需要前幾個
};
#pragma pack(pop)

// Provider GUIDs

// Microsoft-Windows-Kernel-File
static const GUID FileGuid = { 0xEDD08927, 0x9CC4, 0x4E65, { 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89 } };
// Microsoft-Windows-Kernel-Registry
static const GUID RegGuid = { 0x70EB4F03, 0xC1DE, 0x4F73, { 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD } };
// Microsoft-Windows-Threat-Intelligence
static const GUID ThreatIntGuid = { 0xF4E1897C, 0xBB5D, 0x5668, { 0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44 } };
// Microsoft-Windows-Kernel-Process GUID (用來維護 PID -> Name 對照表)
static const GUID ProcessGuid = { 0x222962AB, 0x6180, 0x4B88, { 0xA8, 0x25, 0x34, 0x6B, 0x75, 0xF2, 0xA2, 0x48 } };

// --- [新模組] ProcessTracker: 專責管理 PID 快取 ---
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

// --- [主類別] EtwMonitor ---
class EtwMonitor {
public:
    EtwMonitor(DetectionEngine* engine, const std::string& sessionName);
    ~EtwMonitor();

    void Start();
    void Stop();

private:
    // 靜態 Callback 轉發器
    static void WINAPI StaticEventRecordCallback(PEVENT_RECORD pEvent);

    // 實例處理邏輯
    void ProcessEvent(PEVENT_RECORD pEvent);

    // 輔助函式
    std::string GetProperty(PEVENT_RECORD pEvent, const std::wstring& propName);

private:
    DetectionEngine* m_Engine;
    std::string m_SessionName;
    TRACEHANDLE m_hSession = 0;
    TRACEHANDLE m_hTrace = 0;
    std::thread m_WorkerThread;
    std::atomic<bool> m_IsRunning{ false };

    ProcessTracker m_ProcessTracker; // 內建 Process Tracker

    // 用於靜態 Callback 存取當前實例 (Singleton-like for callback context)
    static EtwMonitor* s_CurrentInstance;
};
/*
class EtwMonitor {
private:
    TRACEHANDLE hSession = 0;
    TRACEHANDLE hTrace = 0;
    std::string sessionName = "EdrRealTimeSession";
    bool isRunning = false;
    std::thread workerThread;
    DetectionEngine* engine;

    static void WINAPI EventRecordCallback(PEVENT_RECORD pEvent);
    static std::string GetProperty(PEVENT_RECORD pEvent, const std::wstring& name);

public:
    EtwMonitor(DetectionEngine* e) : engine(e) {}
    ~EtwMonitor() { Stop(); }
    void Start();
    void Stop();
};
*/