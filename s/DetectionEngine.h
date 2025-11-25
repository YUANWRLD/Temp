#pragma once
#include "Events.h"
#include "IAlerter.h"
#include <algorithm>
#include <string>
#include <vector>

// ---------------------------------------------------------
// 偵測引擎
// ---------------------------------------------------------
class DetectionEngine {
private:
    IAlerter* alerter;

    // 輔助：轉小寫 (Case-Insensitive Check)
    std::string ToLower(const std::string& input) {
        std::string output = input;
        std::transform(output.begin(), output.end(), output.begin(),
            [](unsigned char c) { return std::tolower(c); });
        return output;
    }

    // 輔助：檢查是否包含子字串
    bool Contains(const std::string& source, const std::string& target) {
        if (source.empty() || target.empty()) return false;
        return ToLower(source).find(ToLower(target)) != std::string::npos;
    }

public:
    DetectionEngine(IAlerter* a) : alerter(a) {}

    void AnalyzeEvent(const EdrEvent& evt) {
        // =========================================================
        // Behavior 1: Registry Access (Persistence / Config)
        // Malware Target: HKLM\SOFTWARE\BOMBE
        // ETW Path 範例: \REGISTRY\MACHINE\SOFTWARE\BOMBE
        // =========================================================
        if (evt.type == EventType::RegistryOpen || evt.type == EventType::RegistryQuery) {
            // 同時檢查 Machine 與 Software\BOMBE 以確保準確度
            if (Contains(evt.target, "SOFTWARE\\BOMBE")) {
                // 避免自我偵測雜訊，可選
                if (!Contains(evt.processName, "EdrAgent")) {
                    alerter->TriggerAlert("Malware Registry Access",
                        "Process [" + evt.processName + "] accessed malicious Key: " + evt.target);
                }
            }
        }

        if (evt.type == EventType::RegistryQueryValue) {
            // Malware 具體讀取 "answer_1"
            if (Contains(evt.target, "answer_1")) {
                alerter->TriggerAlert("Malware Registry Value Read",
                    "Process [" + evt.processName + "] queried specific flag: " + evt.target);
            }
        }

        // =========================================================
        // Behavior 2: Credential Theft (File Access)
        // Malware Target: C:\Users\...\AppData\Local\bhrome\Login Data
        // =========================================================
        if (evt.type == EventType::FileRead) {
            // 偵測針對 "bhrome" 目錄下 "Login Data" 的存取
            if (Contains(evt.target, "bhrome") && Contains(evt.target, "Login Data")) {
                alerter->TriggerAlert("Credential Theft Attempt (File Access)",
                    "Process [" + evt.processName + "] stealing credentials from: " + evt.target);
            }
        }
    }
};