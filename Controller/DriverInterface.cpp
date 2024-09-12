#include "stdafx.h"
#include "DriverInterface.h"
#include <stdarg.h>

// If you have the Windows Driver Kit installed, you can use this include:
// #include <ntstatus.h>

// If you don't have the WDK, we'll define the constants ourselves:
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

//STATUS_NOT_IMPLEMENTED
#ifndef STATUS_NOT_IMPLEMENTED
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)
#endif

#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#endif

DriverInterface& DriverInterface::Instance() {
    static DriverInterface instance;
    return instance;
}

DriverInterface::DriverInterface() {
    m_hDriver = CreateFileA("\\\\.\\OwnDriver", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    if (m_hDriver == INVALID_HANDLE_VALUE) {
        errorf("Failed to open driver handle. Error code: %d\n", GetLastError());
    }
}

DriverInterface::~DriverInterface() {
    if (m_hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hDriver);
    }
}


NTSTATUS DriverInterface::SendIOCTL(DWORD ioControlCode, ...) {
    va_list args;
    va_start(args, ioControlCode);

    DWORD bytesReturned = 0;
    BOOL success = FALSE;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    switch (ioControlCode) {
    case IOCTL_GET_MODULE_INFO: {
        DWORD processId = va_arg(args, DWORD);
        LPCWSTR moduleName = va_arg(args, LPCWSTR);
        PBYTE* base = va_arg(args, PBYTE*);
        PDWORD size = va_arg(args, PDWORD);

        struct {
            DWORD ProcessId;
            WCHAR ModuleName[256];
            PBYTE Base;
            DWORD Size;
        } input = { processId };
        wcscpy_s(input.ModuleName, moduleName);

        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), &input, sizeof(input), &bytesReturned, NULL);
        if (success) {
            *base = input.Base;
            *size = input.Size;
            status = STATUS_SUCCESS;
        }
        break;
    }

    case IOCTL_EXTEND_MODULE: {
        DWORD processId = va_arg(args, DWORD);
        LPCWSTR moduleName = va_arg(args, LPCWSTR);
        DWORD size = va_arg(args, DWORD);

        struct {
            DWORD ProcessId;
            WCHAR ModuleName[256];
            DWORD Size;
        } input = { processId, {0}, size };
        wcscpy_s(input.ModuleName, moduleName);

        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), &input, sizeof(input), &bytesReturned, NULL);

        if (success) {
            status = STATUS_SUCCESS;
        }
        else {
            DWORD error = GetLastError();
            printf("Failed to extend module. Error code: %d\n", error);
        }
        break;
    }

    case IOCTL_WRITE_MEMORY: {
        DWORD processId = va_arg(args, DWORD);
        PVOID dest = va_arg(args, PVOID);
        PVOID src = va_arg(args, PVOID);
        DWORD size = va_arg(args, DWORD);

        struct {
            DWORD ProcessId;
            PVOID DestAddress;
            PVOID SourceBuffer;
            DWORD Size;
        } input = { processId, dest, src, size };

        //print all input values in one line
		//printf("[-] Writing memory for process %d. Dest: 0x%p, Src: 0x%p, Size: %u\n", input.ProcessId, input.DestAddress, input.SourceBuffer, input.Size);

        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), NULL, 0, &bytesReturned, NULL);

        if (success) {
            status = STATUS_SUCCESS;
            printf("Memory written successfully. Bytes written: %u\n", bytesReturned);
        }
        else {
            DWORD error = GetLastError();
            printf("Failed to write memory. Error code: %d\n", error);
        }
        break;
    }

    case IOCTL_READ_MEMORY: {
        DWORD processId = va_arg(args, DWORD);
        PVOID dest = va_arg(args, PVOID);
        PVOID src = va_arg(args, PVOID);
        DWORD size = va_arg(args, DWORD);

        struct REQUEST_READ {
            DWORD ProcessId;
            PVOID Dest;
            PVOID Src;
            DWORD Size;
        } input = { processId, dest, src, size };



        // We don't need a separate output buffer because the driver will write directly to 'dest'
        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), &input, sizeof(input), &bytesReturned, NULL);

        if (success) {
            status = STATUS_SUCCESS;

        }
        else {
            DWORD error = GetLastError();
            errorf("Failed to read memory. Error code: %d\n", error);
            status = STATUS_UNSUCCESSFUL;
        }

        break;
    }

    case IOCTL_PROTECT_MEMORY: {
        DWORD processId = va_arg(args, DWORD);
        PVOID address = va_arg(args, PVOID);
        DWORD size = va_arg(args, DWORD);
        PDWORD inOutProtect = va_arg(args, PDWORD);

        struct {
            DWORD ProcessId;
            PVOID Address;
            DWORD Size;
            PDWORD NewProtect;
        } input = { processId, address, size, inOutProtect };

        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), &input, sizeof(input), &bytesReturned, NULL);

        if (success) {
            status = STATUS_SUCCESS;
            printf("Memory protection changed successfully. Old protection: %u\n", *inOutProtect);
        }
        else {
            DWORD error = GetLastError();
            printf("Failed to change memory protection. Error code: %d\n", error);
        }
        break;
    }

    case IOCTL_ALLOC_MEMORY: {
        DWORD processId = va_arg(args, DWORD);
        PVOID& outAddress = va_arg(args, PVOID);
        DWORD size = va_arg(args, DWORD);
        DWORD protect = va_arg(args, DWORD);

        struct {
            DWORD ProcessId;
            PVOID* OutAddress;
            DWORD Size;
            DWORD Protect;
        } input = { processId, &outAddress, size, protect };

        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), &input, sizeof(input), &bytesReturned, NULL);

        if (success) {
            status = STATUS_SUCCESS;

            printf("Memory allocated successfully. Address: 0x%p\n", input.OutAddress);
        }
        else {
            DWORD error = GetLastError();
            printf("Failed to allocate memory. Error code: %d\n", error);
        }
        break;
    }

    case IOCTL_FREE_MEMORY: {
        DWORD processId = va_arg(args, DWORD);
        PVOID address = va_arg(args, PVOID);

        struct {
            DWORD ProcessId;
            PVOID Address;
        } input = { processId, address };

        success = DeviceIoControl(m_hDriver, ioControlCode, &input, sizeof(input), &input, sizeof(input), &bytesReturned, NULL);

        if (success) {
            status = STATUS_SUCCESS;
            printf("Memory freed successfully.\n");
        }
        else {
            DWORD error = GetLastError();
            printf("Failed to free memory. Error code: %d\n", error);
        }
        break;
    }
                          // Implement other IOCTL handlers similarly
                          // ...

    default:
        errorf("Unknown IOCTL code: %d\n", ioControlCode);
        break;
    }

    va_end(args);
    return status;
}