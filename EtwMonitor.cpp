#include "EtwMonitor.h"
#include <vector>
#include <iostream>
#include <filesystem>
#include <algorithm>

// --- Constants (Magic Numbers Removal) ---
constexpr ULONG KEYWORD_FILE_FILENAME   = 0x0010;
constexpr ULONG KEYWORD_FILE_IO         = 0x0020;
constexpr ULONG KEYWORD_FILE_READ       = 0x0100;
constexpr ULONG KEYWORD_REG_OPEN        = 0x2000;
constexpr ULONG KEYWORD_REG_QUERY_VAL   = 0x0400;
constexpr ULONG KEYWORD_THREAT_READVM   = 0x20000; // THREATINT_KEYWORD_READVM_REMOTE

// Opcode constants
constexpr UCHAR OPCODE_PROCESS_START    = 1;
constexpr UCHAR OPCODE_PROCESS_STOP     = 2;
constexpr UCHAR OPCODE_REG_OPEN_KEY     = 33;
constexpr UCHAR OPCODE_REG_QUERY_KEY    = 35;
constexpr UCHAR OPCODE_REG_QUERY_VALUE  = 38;

// --- ProcessTracker Implementation ---

ProcessTracker::ProcessTracker() {}

void ProcessTracker::Initialize() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32W pe32; // 使用 Wide char 版本
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        std::lock_guard<std::mutex> lock(m_Mutex);
        do {
            std::wstring wName = pe32.szExeFile;
            // 轉成 string (簡單轉換，若有中文需考慮編碼)
            std::string name(wName.begin(), wName.end());
            m_ProcessMap[pe32.th32ProcessID] = name;
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
}

void ProcessTracker::Update(DWORD pid, const std::string& imagePath) {
    std::lock_guard<std::mutex> lock(m_Mutex);
    // 提取檔名: "C:\Path\To\cmd.exe" -> "cmd.exe"
    // [修正] 不使用 std::filesystem，改用手動尋找路徑分隔符號
    size_t lastSlash = imagePath.find_last_of("/\\");
    std::string filename = (lastSlash == std::string::npos) ? imagePath : imagePath.substr(lastSlash + 1);

    m_ProcessMap[pid] = filename;
}

void ProcessTracker::Remove(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_Mutex);
    m_ProcessMap.erase(pid);
}

std::string ProcessTracker::GetName(DWORD pid) {
    std::lock_guard<std::mutex> lock(m_Mutex);
    auto it = m_ProcessMap.find(pid);
    if (it != m_ProcessMap.end()) {
        return it->second;
    }
    return "Unknown(" + std::to_string(pid) + ")";
}

// --- EtwMonitor Implementation ---

EtwMonitor* EtwMonitor::s_CurrentInstance = nullptr;

EtwMonitor::EtwMonitor(DetectionEngine* engine, const std::string& sessionName)
    : m_Engine(engine), m_SessionName(sessionName) {
}

EtwMonitor::~EtwMonitor() {
    Stop();
}

// 靜態 Callback：只負責轉發
void WINAPI EtwMonitor::StaticEventRecordCallback(PEVENT_RECORD pEvent) {
    if (s_CurrentInstance) {
        s_CurrentInstance->ProcessEvent(pEvent);
    }
}

// 實際處理邏輯
void EtwMonitor::ProcessEvent(PEVENT_RECORD pEvent) {
    if (!m_Engine) return;

    DWORD pid = pEvent->EventHeader.ProcessId;
    if (pid == 0 || pid == 4) return;

    // 1. 維護 Process Cache (優先處理)
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, ProcessGuid)) {
        if (pEvent->EventHeader.EventDescriptor.Opcode == OPCODE_PROCESS_START) {
            std::string imagePath = GetProperty(pEvent, L"ImageName");
            m_ProcessTracker.Update(pid, imagePath);
        }
        else if (pEvent->EventHeader.EventDescriptor.Opcode == OPCODE_PROCESS_STOP) {
            m_ProcessTracker.Remove(pid);
        }
        return;
    }

    // 取得當前 Process 名稱
    std::string procName = m_ProcessTracker.GetName(pid);

    // 2. File Events
    if (IsEqualGUID(pEvent->EventHeader.ProviderId, FileGuid)) {
        std::string fileName = GetProperty(pEvent, L"FileName");
        if (!fileName.empty()) {
            m_Engine->AnalyzeEvent({ EventType::FileRead, procName, fileName });
        }
    }

    // 3. Registry Events
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

    // 4. Threat Intelligence (ETW-TI)
    else if (IsEqualGUID(pEvent->EventHeader.ProviderId, ThreatIntGuid)) {
        // 需加上更嚴謹的長度檢查與 Opcode 檢查
        // 假設這是 ReadVmRemote 事件
        if (pEvent->UserDataLength >= sizeof(TiReadVmRemoteEvent)) {
            TiReadVmRemoteEvent* pTiEvent = (TiReadVmRemoteEvent*)pEvent->UserData;
            DWORD targetPid = pTiEvent->TargetProcessId;
            std::string targetName = m_ProcessTracker.GetName(targetPid);

            if (targetName.find("bsass") != std::string::npos || targetName.find("bsass.exe") != std::string::npos) {
                std::string targetInfo = targetName + " (PID:" + std::to_string(targetPid) + ")";
                m_Engine->AnalyzeEvent({ EventType::ProcessOpen, procName, targetInfo });
            }
        }
    }
}

std::string EtwMonitor::GetProperty(PEVENT_RECORD pEvent, const std::wstring& propName) {
    DWORD bufferSize = 0;
    // 第一次呼叫取得 buffer 大小
    TdhGetEventInformation(pEvent, 0, NULL, NULL, &bufferSize);
    
    // 使用 vector 管理記憶體，自動釋放
    std::vector<BYTE> buffer(bufferSize); 
    PTRACE_EVENT_INFO pInfo = (PTRACE_EVENT_INFO)buffer.data();

    if (TdhGetEventInformation(pEvent, 0, NULL, pInfo, &bufferSize) != ERROR_SUCCESS) return "";

    for (DWORD i = 0; i < pInfo->TopLevelPropertyCount; i++) {
        // 指標運算稍微危險，建議封裝，這裡保持原樣但加上邊界檢查意識
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
                if (size > 2) { // 假設是字串
                    std::wstring wResult((wchar_t*)val.data());
                    // 這裡的轉換是基礎的，若要處理 UTF-8 建議用 WideCharToMultiByte
                    return std::string(wResult.begin(), wResult.end());
                }
            }
            break; // 找到就離開迴圈
        }
    }
    return "";
}

void EtwMonitor::Start() {
    if (m_IsRunning) return;
    
    // 設定全域指針，讓 Static Callback 找得到物件
    s_CurrentInstance = this;
    m_IsRunning = true;

    m_WorkerThread = std::thread([this]() {
        // 使用 vector 取代 malloc
        ULONG bufSize = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(KERNEL_LOGGER_NAME);
        std::vector<char> propsBuf(bufSize, 0);
        EVENT_TRACE_PROPERTIES* pProps = (EVENT_TRACE_PROPERTIES*)propsBuf.data();

        pProps->Wnode.BufferSize = bufSize;
        pProps->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        pProps->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        pProps->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pProps->EnableFlags = 0;

        // 初始化 Process Cache (在開始監控前建立基準)
        m_ProcessTracker.Initialize();

        // 嘗試停止已存在的 Session (Clean start)
        ControlTraceA(0, m_SessionName.c_str(), pProps, EVENT_TRACE_CONTROL_STOP);

        if (StartTraceA(&m_hSession, m_SessionName.c_str(), pProps) != ERROR_SUCCESS) {
            // Error handling: logging or throw
            m_IsRunning = false;
            return;
        }

        // Enable Providers
        auto enableProvider = [&](const GUID* guid, ULONG keywords) {
            EnableTraceEx2(m_hSession, guid, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION, keywords, 0, 0, NULL);
        };

        enableProvider(&FileGuid, KEYWORD_FILE_FILENAME | KEYWORD_FILE_IO | KEYWORD_FILE_READ);
        enableProvider(&RegGuid, KEYWORD_REG_OPEN | KEYWORD_REG_QUERY_VAL);
        
        // ETW-TI (Requires PPL)
        enableProvider(&ThreatIntGuid, KEYWORD_THREAT_READVM);

        // Process Provider (Kernel) is special, sometimes needs SystemTraceControlGuid or specific flags
        // 這裡維持你原本邏輯，假設 ProcessGuid 可用
        enableProvider(&ProcessGuid, 0x10); 

        EVENT_TRACE_LOGFILEA logFile = { 0 };
        logFile.LoggerName = (char*)m_SessionName.c_str();
        logFile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logFile.EventRecordCallback = StaticEventRecordCallback; // 指向靜態函式

        m_hTrace = OpenTraceA(&logFile);
        if (m_hTrace != INVALID_PROCESSTRACE_HANDLE) {
            ProcessTrace(&m_hTrace, 1, 0, 0); // Blocking call
            CloseTrace(m_hTrace);
        }
        
        m_hTrace = 0;
        m_hSession = 0;
    });
}

void EtwMonitor::Stop() {
    if (!m_IsRunning) return;

    EVENT_TRACE_PROPERTIES p = { 0 };
    p.Wnode.BufferSize = sizeof(p);
    
    // 停止 ETW Session 會讓 ProcessTrace 返回
    ControlTraceA(0, m_SessionName.c_str(), &p, EVENT_TRACE_CONTROL_STOP);
    
    m_IsRunning = false;
    s_CurrentInstance = nullptr;

    if (m_WorkerThread.joinable()) {
        m_WorkerThread.join();
    }
}