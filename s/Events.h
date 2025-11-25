#pragma once
#include <string>

enum class EventType {
    RegistryOpen,
    RegistryQuery,
    RegistryQueryValue,
    FileRead,
    ProcessOpen,   // 用於對應 Memory Access (ReadVmRemote)
    NetworkConnect
};

struct EdrEvent {
    EventType type;
    std::string processName; // 發起行為的 Process
    std::string target;      // 行為的目標 (File Path, Reg Key, Target Process Name)
};