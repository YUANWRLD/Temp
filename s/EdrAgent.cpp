#include <iostream>
#include <windows.h>
#include "../Shared/DetectionEngine.h"
#include "EtwMonitor.h"
#include "HandleScanner.h" // 引入新模組

// 真實的 Alerter
class ConsoleAlerter : public IAlerter {
public:
    void TriggerAlert(const std::string& title, const std::string& description) override {
        static std::mutex alertMutex;
        std::lock_guard<std::mutex> lock(alertMutex);

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

    // 提升 Debug 權限 (掃描 Handle 需要)
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        TOKEN_PRIVILEGES tp;
        LUID luid;
        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
        }
        CloseHandle(hToken);
    }

    ConsoleAlerter alerter;
    DetectionEngine engine(&alerter);

    // 1. 啟動 ETW Monitor (負責 Registry & File)
    EtwMonitor etwMonitor(&engine, "MyEtwSession");

    // 2. 啟動 Handle Scanner (專門負責抓 bsass 的記憶體存取)
    HandleScanner handleScanner(&engine);

    std::cout << "========================================\n";
    std::cout << "   EDR Real-time Sensor: ACTIVE\n";
    std::cout << "   [ETW] Monitoring Registry & Files\n";
    std::cout << "   [Scanner] Monitoring Memory Access (bsass)\n";
    std::cout << "========================================\n";

    etwMonitor.Start();
    handleScanner.Start();

    std::cout << "Press ENTER to stop monitoring...\n";
    std::cin.get();

    handleScanner.Stop();
    etwMonitor.Stop();

    return 0;
}