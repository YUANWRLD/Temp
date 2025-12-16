#pragma once
#include <windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// =========================================================
// [Object Manager Symlink Access Rights]
// =========================================================
#define SYMBOLIC_LINK_QUERY (0x0001)
#define SYMBOLIC_LINK_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | 0x1)

// =========================================================
// [System Information Class]
// =========================================================
#define SystemProcessInformation_Const 5
#define SystemHandleInformation_Const 16

// =========================================================
// [Registry & File Flags]
// =========================================================
#ifndef KEY_READ
#define KEY_READ 0x20019
#endif
#ifndef FILE_OPEN
#define FILE_OPEN 0x00000001
#endif
#ifndef FILE_DIRECTORY_FILE
#define FILE_DIRECTORY_FILE 0x00000001
#endif
#ifndef FILE_NON_DIRECTORY_FILE
#define FILE_NON_DIRECTORY_FILE 0x00000040
#endif
#ifndef FILE_SYNCHRONOUS_IO_NONALERT
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#endif
#ifndef FILE_OPEN_BY_FILE_ID
#define FILE_OPEN_BY_FILE_ID 0x00002000
#endif
#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif
#ifndef OBJ_OPENIF
#define OBJ_OPENIF 0x00000080L
#endif

// =========================================================
// [Structs]
// =========================================================

// Registry Value
typedef struct _KEY_VALUE_PARTIAL_INFORMATION_IMPL {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION_IMPL, * PKEY_VALUE_PARTIAL_INFORMATION_IMPL;

// File ID & Info
#define FileIdBothDirectoryInformation_Const 37
#define FileStandardInformation_Const 5

typedef struct _FILE_ID_BOTH_DIR_INFORMATION_IMPL {
    ULONG NextEntryOffset;
    ULONG FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG FileAttributes;
    ULONG FileNameLength;
    ULONG EaSize;
    CCHAR ShortNameLength;
    WCHAR ShortName[12];
    LARGE_INTEGER FileId;
    WCHAR FileName[1];
} FILE_ID_BOTH_DIR_INFORMATION_IMPL, * PFILE_ID_BOTH_DIR_INFORMATION_IMPL;

typedef struct _FILE_STANDARD_INFORMATION_IMPL {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION_IMPL, * PFILE_STANDARD_INFORMATION_IMPL;

// System Handle Info
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_IMPL {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_IMPL, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_IMPL;

typedef struct _SYSTEM_HANDLE_INFORMATION_IMPL {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_IMPL Handles[1];
} SYSTEM_HANDLE_INFORMATION_IMPL, * PSYSTEM_HANDLE_INFORMATION_IMPL;

// System Process Info
typedef LONG KPRIORITY;
typedef struct _SYSTEM_PROCESS_INFORMATION_FULL {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION_FULL, * PSYSTEM_PROCESS_INFORMATION_FULL;