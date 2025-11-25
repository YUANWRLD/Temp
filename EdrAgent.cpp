#include <iostream>
#include <windows.h>
#include "../Shared/DetectionEngine.h"
#include "EtwMonitor.h"

// 真實的 Alerter
class ConsoleAlerter : public IAlerter {
public:
    void TriggerAlert(const std::string& title, const std::string& description) override {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        // 設定紅色高亮文字
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);

        std::cout << "\n[!!! THREAT DETECTED !!!] " << title << "\n";
        std::cout << "    Details: " << description << "\n";

        // 恢復預設顏色
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    }
};

int main() {
    // 檢查管理員權限
    BOOL isAdmin = FALSE;
    PSID adminGroup;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    if (!isAdmin) {
        std::cout << "[ERROR] Please run as Administrator.\n";
        return 1;
    }

    ConsoleAlerter alerter;
    DetectionEngine engine(&alerter);
    EtwMonitor monitor(&engine, "MyEtwMonitorSession");

    std::cout << "========================================\n";
    std::cout << "   EDR Real-time Sensor: ACTIVE\n";
    std::cout << "   Monitoring Registry, Files, Memory, Network\n";
    std::cout << "========================================\n";

    monitor.Start();

    // 保持程式執行
    std::cin.get();

    monitor.Stop();
    return 0;
}