#pragma once
#include <string>
#include <cstdint>

enum class EventType {
    RegistryOpen,
    RegistryQuery,
    RegistryQueryValue,
    FileRead,
    ProcessOpen,   // 對應 bsass 讀取
    NetworkConnect // 對應 C2 連線
};

struct EdrEvent {
    EventType type;
    std::string processName; // PID
    std::string target;      // 檔案路徑 / Registry Key / Domain / Object Name
};