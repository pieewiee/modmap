#include "stdafx.h"
#include "Process.h"
#include "DriverInterface.h"

namespace process {

    Process::Process(LPCWSTR processName) {
        auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32 entry = { 0 };
        entry.dwSize = sizeof(entry);
        if (Process32First(snapshot, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, processName) == 0) {
                    this->ProcessId = entry.th32ProcessID;
                    break;
                }
            } while (Process32Next(snapshot, &entry));
        }

        CloseHandle(snapshot);
    }

    BOOLEAN Process::Valid() {
        return this->ProcessId != 0;
    }

    NTSTATUS Process::Module(LPCWSTR moduleName, PBYTE* base, PDWORD size) {
        return DriverInterface::Instance().SendIOCTL(IOCTL_GET_MODULE_INFO, this->ProcessId, moduleName, base, size);
    }

    NTSTATUS Process::Extend(LPCWSTR moduleName, DWORD size) {
        return DriverInterface::Instance().SendIOCTL(IOCTL_EXTEND_MODULE, this->ProcessId, moduleName, size);

    }

    NTSTATUS Process::Write(PVOID dest, PVOID src, DWORD size) {
        return DriverInterface::Instance().SendIOCTL(IOCTL_WRITE_MEMORY, this->ProcessId, dest, src, size);
    }

    NTSTATUS Process::Read(PVOID dest, PVOID src, DWORD size) {
        return DriverInterface::Instance().SendIOCTL(IOCTL_READ_MEMORY, this->ProcessId, dest, src, size);
    }

    NTSTATUS Process::Protect(PVOID address, DWORD size, PDWORD inOutProtect) {
        return DriverInterface::Instance().SendIOCTL(IOCTL_PROTECT_MEMORY, this->ProcessId, address, size, inOutProtect);
    }

    PVOID Process::Alloc(DWORD size, DWORD protect) {
        PVOID address = NULL;
		printf("Allocating memory for process %d. Size: %u, Protect: %u\n", this->ProcessId, size, protect);
		// status = DriverInterface::Instance().SendIOCTL(IOCTL_ALLOC_MEMORY, this->ProcessId, size, protect, &address);
		NTSTATUS status = DriverInterface::Instance().SendIOCTL(IOCTL_ALLOC_MEMORY, this->ProcessId, size, protect, &address);

		address = &address;
        return address;
    }

    NTSTATUS Process::Free(PVOID address) {
        return DriverInterface::Instance().SendIOCTL(IOCTL_FREE_MEMORY, this->ProcessId, address);
    }
}