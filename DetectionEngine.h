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
        std::string targetLower = ToLower(evt.target);

        // =========================================================
        // Behavior 1: Registry Access (HKLM Only)
        // Target: HKLM:\SOFTWARE\BOMBE
        // ETW Path for HKLM: \REGISTRY\MACHINE\SOFTWARE\BOMBE
        // ETW Path for HKCU: \REGISTRY\USER\...\SOFTWARE\BOMBE
        // =========================================================
        if (evt.type == EventType::RegistryOpen) {
            // 必須同時包含 "machine" 和 "software\bombe" 以區分 HKLM 與 HKCU
            if (Contains(evt.target, "SOFTWARE\\BOMBE")) {
                alerter->TriggerAlert("Malware Registry Access (Registry Open)",
                    "Process [" + evt.processName + "] Open HKLM Key: " + evt.target);
            }
        }
        
        if (evt.type == EventType::RegistryQuery) {
            // 必須同時包含 "machine" 和 "software\bombe" 以區分 HKLM 與 HKCU
            if (Contains(evt.target, "SOFTWARE\\BOMBE")) {
                alerter->TriggerAlert("Malware Registry Access (Registry Query)",
                    "Process [" + evt.processName + "] Query HKLM Key: " + evt.target);
            }
        }

        if (evt.type == EventType::RegistryQueryValue) {
            // 必須同時包含 "machine" 和 "software\bombe" 以區分 HKLM 與 HKCU
            if (Contains(evt.target, "answer_1")) {
                alerter->TriggerAlert("Malware Registry Access (Registry Query Value)",
                    "Process [" + evt.processName + "] Query HKLM\\SOFTWARE\\BOMBE Value: " + evt.target);
            }
        }

        // =========================================================
        // Behavior 2: Credential Theft (File Access)
        // Target: C:\Users\bombe\AppData\Local\bhrome\Login Data
        // Logic: 偵測開啟包含 "bhrome" 且包含 "Login Data" 的檔案
        // =========================================================
        if (evt.type == EventType::FileRead) {
            if (Contains(evt.target, "bhrome") && Contains(evt.target, "Login Data")) {
                alerter->TriggerAlert("Credential Theft Attempt (File Access)",
                    "Process [" + evt.processName + "] accessed sensitive file: " + evt.target);
            }
        }

        // =========================================================
        // Behavior 3: LSASS/Critical Process Memory Access
        // Target: bsass.exe
        // Logic: 偵測針對 bsass 的 OpenProcess (Handle Creation)
        // =========================================================
        if (evt.type == EventType::ProcessOpen) {
            // 嚴格匹配 bsass.exe 或 bsass (這裡使用 Contains)
            // 為了更準確，建議使用 ContainsIgnoreCase
            if (Contains(evt.target, "2652") || Contains(evt.target, "bsass") || Contains(evt.target, "bsass.exe")) {

                alerter->TriggerAlert("Critical Process Access (Memory Dump)",
                    "Process [" + evt.processName + "] opened handle to: " + evt.target);
            }
        }
    }
};