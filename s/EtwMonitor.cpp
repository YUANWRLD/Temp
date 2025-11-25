#include "EtwMonitor.h"
#include <vector>
#include <iostream>
#include <filesystem>
#include <algorithm>

// --- Constants ---
constexpr ULONG KEYWORD_FILE_FILENAME = 0x0010;
constexpr ULONG KEYWORD_FILE_IO = 0x0020;
constexpr ULONG KEYWORD_FILE_READ = 0x0100;
constexpr ULONG KEYWORD_REG_OPEN = 0x2000;
constexpr ULONG KEYWORD_REG_QUERY_VAL = 0x0400;

// Opcode constants
constexpr UCHAR OPCODE_PROCESS_START = 1;
constexpr UCHAR OPCODE_PROCESS_STOP = 2;
constexpr UCHAR OPCODE_REG_OPEN_KEY = 33;
constexpr UCHAR OPCODE_REG_QUERY_KEY = 35;
constexpr UCHAR OPCODE_REG_QUERY_VALUE = 38;

// =========================================================
// ProcessTracker Implementation
// =========================================================
ProcessTracker::ProcessTracker() {}

void ProcessTracker::Initialize() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        std::lock_guard<std::mutex> lock(m_Mutex);
        do {
            std::wstring wName = pe32.szExeFile;
            std::string name(wName.begin(), wName.end());
            m_ProcessMap[pe32.th32ProcessID] = name;
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

void ProcessTracker::Update(DWORD pid, const std::string& imagePath) {
    std::lock_guard<std::mutex> lock(m_Mutex);
    size_t lastSlash = imagePath.find_last_of("/\\");
    std::string filename = (lastSlash == std::string::npos) ? imagePath : imagePath.substr(lastSlash + 1);
    m_ProcessMap[pid] = filename;
}

void ProcessTracker::Remove(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_Mutex);
    m_ProcessMap.erase(pid);
}

std::string ProcessTracker::GetName(DWORD pid) {
    {
        std::lock_guard<std::mutex> lock(m_Mutex);
        auto it = m_ProcessMap.find(pid);
        if (it != m_ProcessMap.end()) {
            return it->second;
        }
    }

    // Lazy Resolution
    std::string resolvedName = "Unknown(" + std::to_string(pid) + ")";
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess) {
        char path[MAX_PATH];
        DWORD size = sizeof(path);
        if (QueryFullProcessImageNameA(hProcess, 0, path, &size)) {
            std::string fullPath(path);
            size_t lastSlash = fullPath.find_last_of("/\\");
            resolvedName = (lastSlash == std::string::npos) ? fullPath : fullPath.substr(lastSlash + 1);
            Update(pid, fullPath);
        }
        CloseHandle(hProcess);
    }
    return resolvedName;
}

// =========================================================
// EtwMonitor Implementation
// =========================================================

EtwMonitor* EtwMonitor::s_CurrentInstance = nullptr;

EtwMonitor::EtwMonitor(DetectionEngine* engine, const std::string& sessionName)
    : m_Engine(engine), m_SessionName(sessionName) {

    HMODULE hNtDll = GetModuleHandleA("ntdll.dll");
    if (hNtDll) {
        NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtDll, "NtQuerySystemInformation");
    }
}

EtwMonitor::~EtwMonitor() {
    Stop();
}

void WINAPI EtwMonitor::StaticEventRecordCallback(PEVENT_RECORD pEvent) {
    if (s_CurrentInstance) {
        s_CurrentInstance->ProcessEvent(pEvent);
    }
}

// ETW Event Processing (Registry & File)
void EtwMonitor::ProcessEvent(PEVENT_RECORD pEvent) {
    if (!m_Engine) return;

    DWORD pid = pEvent->EventHeader.ProcessId;
    if (pid == 0 || pid == 4) return;

    if (IsEqualGUID(pEvent->EventHeader.ProviderId, ProcessGuid)) {
        if (pEvent->EventHeader.EventDescriptor.Opcode == OPCODE_PROCESS_START) {
            std::string imagePath = GetProperty(pEvent, L"ImageName");
            if (imagePath.empty()) imagePath = GetProperty(pEvent, L"ImageFileName");
            m_ProcessTracker.Update(pid, imagePath);
        }
        else if (pEvent->EventHeader.EventDescriptor.Opcode == OPCODE_PROCESS_STOP) {
            m_ProcessTracker.Remove(pid);
        }
        return;
    }

    std::string procName = m_ProcessTracker.GetName(pid);

    if (IsEqualGUID(pEvent->EventHeader.ProviderId, FileGuid)) {
        std::string fileName = GetProperty(pEvent, L"FileName");
        if (!fileName.empty()) {
            m_Engine->AnalyzeEvent({ EventType::FileRead, procName, fileName });
        }
    }
    else if (IsEqualGUID(pEvent->EventHeader.ProviderId, RegGuid)) {
        UCHAR opcode = pEvent->EventHeader.EventDescriptor.Opcode;
        if (opcode == OPCODE_REG_OPEN_KEY) {
            std::string keyName = GetProperty(pEvent, L"KeyName");
            if (!keyName.empty()) m_Engine->AnalyzeEvent({ EventType::RegistryOpen, procName, keyName });
        }
        else if (opcode == OPCODE_REG_QUERY_KEY) {
            std::string keyName = GetProperty(pEvent, L"KeyName");
            if (!keyName.empty()) m_Engine->AnalyzeEvent({ EventType::RegistryQuery, procName, keyName });
        }
        else if (opcode == OPCODE_REG_QUERY_VALUE) {
            std::string valName = GetProperty(pEvent, L"ValueName");
            if (!valName.empty()) m_Engine->AnalyzeEvent({ EventType::RegistryQueryValue, procName, valName });
        }
    }
}

std::string EtwMonitor::GetProperty(PEVENT_RECORD pEvent, const std::wstring& propName) {
    DWORD bufferSize = 0;
    TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);

    if (bufferSize == 0) return "";
    std::vector<BYTE> buffer(bufferSize);
    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)buffer.data();

    if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize) != ERROR_SUCCESS) return "";

    for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        if (pInfo->EventPropertyInfoArray[i].NameOffset == 0) continue;
        wchar_t* pName = (wchar_t*)((BYTE*)pInfo + pInfo->EventPropertyInfoArray[i].NameOffset);
        if (!pName) continue;

        if (propName == pName) {
            PROPERTY_DATA_DESCRIPTOR desc;
            desc.PropertyName = (ULONGLONG)pName;
            desc.ArrayIndex = ULONG_MAX;
            desc.Reserved = 0;
            DWORD size = 0;
            TdhGetPropertySize(pEvent, 0, NULL, 1, &desc, &size);
            std::vector<BYTE> val(size);
            if (TdhGetProperty(pEvent, 0, NULL, 1, &desc, size, val.data()) == ERROR_SUCCESS) {
                if (size > 1) {
                    std::wstring wResult((wchar_t*)val.data());
                    if (!wResult.empty() && wResult.back() == L'\0') wResult.pop_back();
                    return std::string(wResult.begin(), wResult.end());
                }
            }
            break;
        }
    }
    return "";
}

// =========================================================
// Active Handle Scanner Implementation
// =========================================================

void EtwMonitor::ScannerWorker() {
    while (m_IsRunning) {
        ScanHandles();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void EtwMonitor::ScanHandles() {
    if (!NtQuerySystemInformation) return;

    DWORD targetPid = GetPidByName("bsass"); // 這裡傳入 std::string
    if (targetPid == 0) return;

    DWORD myPid = GetCurrentProcessId();

    ULONG bufferSize = 1024 * 1024;
    std::vector<BYTE> buffer(bufferSize);
    ULONG returnLength = 0;

    NTSTATUS status = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), bufferSize, &returnLength);
    while (status == STATUS_INFO_LENGTH_MISMATCH) {
        bufferSize = returnLength + 4096;
        buffer.resize(bufferSize);
        status = NtQuerySystemInformation(SystemHandleInformation, buffer.data(), bufferSize, &returnLength);
    }

    if (status != 0) return;

    // 轉型為結構指標
    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)buffer.data();

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO& entry = handleInfo->Handles[i];

        if (entry.UniqueProcessId == myPid || entry.UniqueProcessId == 0 || entry.UniqueProcessId == 4) continue;
        if (entry.UniqueProcessId == targetPid) continue;

        HANDLE hSourceProc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, entry.UniqueProcessId);
        if (hSourceProc) {
            HANDLE hDup = NULL;
            if (DuplicateHandle(hSourceProc, (HANDLE)(uintptr_t)entry.HandleValue,
                GetCurrentProcess(), &hDup,
                PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {

                if (GetProcessId(hDup) == targetPid) {
                    std::string attackerName = m_ProcessTracker.GetName(entry.UniqueProcessId);
                    std::string targetInfo = "bsass.exe (PID:" + std::to_string(targetPid) + ")";
                    m_Engine->AnalyzeEvent({ EventType::ProcessOpen, attackerName, targetInfo });
                }
                CloseHandle(hDup);
            }
            CloseHandle(hSourceProc);
        }
    }
}

// [修正] 確保這裡接受 std::string
DWORD EtwMonitor::GetPidByName(const std::string& procName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32; // 使用 ANSI 版本對應 std::string
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string currentName = pe32.szExeFile;

                std::string s1 = currentName;
                std::string s2 = procName;
                std::transform(s1.begin(), s1.end(), s1.begin(), ::tolower);
                std::transform(s2.begin(), s2.end(), s2.begin(), ::tolower);

                if (s1.find(s2) != std::string::npos) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    return pid;
}

// =========================================================
// Start / Stop
// =========================================================

void EtwMonitor::Start() {
    if (m_IsRunning) return;

    s_CurrentInstance = this;
    m_IsRunning = true;

    m_EtwThread = std::thread([this]() {
        ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
        std::vector<char> propsBuf(bufSize, 0);
        EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)propsBuf.data();

        pProps->Wnode.BufferSize = bufSize;
        pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pProps->EnableFlags = 0;

        m_ProcessTracker.Initialize();

        ControlTraceA(0, m_SessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);

        if (StartTraceA(&m_hSession, m_SessionName.c_str(), pProps) != ERROR_SUCCESS) {
            return;
        }

        auto enableProvider = [&](const GUID* guid, ULONG keywords) {
            EnableTraceEx2(m_hSession, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, keywords, 0, 0, NULL);
            };

        enableProvider(&FileGuid, KEYWORD_FILE_FILENAME | KEYWORD_FILE_IO | KEYWORD_FILE_READ);
        enableProvider(&RegGuid, KEYWORD_REG_OPEN | KEYWORD_REG_QUERY_VAL);
        enableProvider(&ProcessGuid, 0x10);

        EVENT_TRACE_LOGFILEA logFile = { 0 };
        logFile.LoggerName = (char*)m_SessionName.c_str();
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = StaticEventRecordCallback;

        m_hTrace = OpenTraceA(&logFile);
        if (m_hTrace != INVALID_PROCESSTRACE_HANDLE) {
            ProcessTrace(&m_hTrace, 1, 0, 0);
            CloseTrace(m_hTrace);
        }
        m_hTrace = 0;
        m_hSession = 0;
        });

    m_ScannerThread = std::thread(&EtwMonitor::ScannerWorker, this);
}

void EtwMonitor::Stop() {
    if (!m_IsRunning) return;

    EVENT_TRACE_PROPERTIES p = { 0 };
    p.Wnode.BufferSize = sizeof(p);
    ControlTraceA(0, m_SessionName.c_str(), &p, EVENT_TRACE_CONTROL_STOP);

    m_IsRunning = false;
    s_CurrentInstance = nullptr;

    if (m_EtwThread.joinable()) m_EtwThread.join();
    if (m_ScannerThread.joinable()) m_ScannerThread.join();
}