#pragma once
#include <Windows.h>
#include "DriverInterface.h"

namespace process {
    class Process {
    private:
        DWORD ProcessId = 0;

    public:
        Process(DWORD processId) : ProcessId{ processId } {}
        Process(LPCWSTR processName);

        BOOLEAN Valid();
        NTSTATUS Extend(LPCWSTR module, DWORD size);
        NTSTATUS Write(PVOID dest, PVOID src, DWORD size);
        NTSTATUS Read(PVOID dest, PVOID src, DWORD size);
        NTSTATUS Protect(PVOID address, DWORD size, PDWORD inOutProtect);
        PVOID Alloc(DWORD size, DWORD protect);
        NTSTATUS Free(PVOID address);
        NTSTATUS Module(LPCWSTR moduleName, PBYTE* base, PDWORD size);
        DWORD GetProcessId() const { return ProcessId; }
    };
}