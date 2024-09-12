#pragma once
#include <Windows.h>

// If you don't have the WDK, we'll define NTSTATUS ourselves:
#ifndef NTSTATUS
typedef LONG NTSTATUS;
#endif

// Define IOCTL codes
#define IOCTL_GET_MODULE_INFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_EXTEND_MODULE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PROTECT_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ALLOC_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_MEMORY     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)

class DriverInterface {
public:
    static DriverInterface& Instance();
    NTSTATUS SendIOCTL(DWORD ioControlCode, ...);

private:
    DriverInterface();
    ~DriverInterface();
    DriverInterface(const DriverInterface&) = delete;
    DriverInterface& operator=(const DriverInterface&) = delete;

    HANDLE m_hDriver;
};