#include "stdafx.h"

DRIVER_DISPATCH HandleCreate;
DRIVER_DISPATCH HandleClose;
DRIVER_DISPATCH HandleIOCTL;
DRIVER_UNLOAD DriverUnload;

INT64(NTAPI* EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);

PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);

// Global variable to store the original function pointer
PVOID OriginalEnumerateDebuggingDevices = NULL;

NTSTATUS GetNtOsVersion(PRTL_OSVERSIONINFOW lpVersionInformation) {
    if (lpVersionInformation == NULL || lpVersionInformation->dwOSVersionInfoSize != sizeof(RTL_OSVERSIONINFOW)) {
        return STATUS_INVALID_PARAMETER;
    }
    return RtlGetVersion(lpVersionInformation);
}



NTSTATUS InitializeVadFunctions() {
    PCHAR base = GetKernelBase();
    if (!base) {
        printf("! failed to get ntoskrnl base !\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    // MiAllocateVad (yes I'm this lazy)
    //PBYTE addr = (PBYTE)FindPatternImage(base, "\x41\xB8\x00\x00\x00\x00\x48\x8B\xD6\x49\x8B\xCE\xE8\x00\x00\x00\x00\x48\x8B\xD8", "xx????xxxxxxx????xxx");
    //PBYTE addr = (PBYTE)FindPatternImage(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30\x48\x8B\xE9\x41\x8B\xF8\xB9\x00\x00\x00\x00\x48\x8B\xF2\x8B\xD1\x41\xB8\x00\x00\x00\x00", "xxxx?xxxx?xxxx?xxxxxxxxxxxx????xxxxxxx????");
    PBYTE addr = (PBYTE)FindPatternImage(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30\x48\x8B\xE9\x41\x8B\xF8\xB9\x40\x00\x00\x00", "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxx");
    if (!addr) {
        printf("! failed to find MiAllocateVad !\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    //*(PVOID*)&MiAllocateVad = RELATIVE_ADDR(addr + 12, 5);
    *(PVOID*)&MiAllocateVad = addr;

    // MiInsertVadCharges
    addr = FindPatternImage(base, "\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x56\x41\x57\x48\x83\xEC\x40\x44\x0F\xB6\x79", "xxxx?xxxx?xxxxxxxxxxxxx");
    if (!addr) {
        printf("! failed to find MiInsertVadCharges !\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    //*(PVOID*)&MiInsertVadCharges = RELATIVE_ADDR(addr, 5);
    *(PVOID*)&MiInsertVadCharges = addr;

    // MiInsertVad
    addr = FindPatternImage(base, "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x56\x57\x41\x54\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x00\x45\x33\xFF", "xxxx?xxxx?xxxxxxxxxxxxxx?xxx");
    if (!addr) {
        printf("! failed to find MiInsertVad !\n");
        return STATUS_FAILED_DRIVER_ENTRY;
    }

    //for (; *addr != 0xE8 || *(addr + 5) != 0x8B; ++addr);
    //*(PVOID*)&MiInsertVad = RELATIVE_ADDR(addr, 5);

    *(PVOID*)&MiInsertVad = addr;


    return STATUS_SUCCESS;
}


NTSTATUS HandleCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status = STATUS_SUCCESS;
}

NTSTATUS HandleClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status = STATUS_SUCCESS;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING devName;
    UNICODE_STRING symLink;

    RtlInitUnicodeString(&devName, DEVICE_NAME);
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

	InitializeVadFunctions();

    status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to create device (0x%08X)\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &devName);

    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to create symbolic link (0x%08X)\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIOCTL;
    DriverObject->DriverUnload = DriverUnload;

    deviceObject->Flags |= DO_BUFFERED_IO;

    DbgPrint("Driver loaded successfully\n");
    return STATUS_SUCCESS;
}

NTSTATUS HandleIOCTL(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    PVOID outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG_PTR information = 0;

    switch (ioControlCode) {
    case IOCTL_GET_MODULE_INFO: {
        if (inputBufferLength < sizeof(REQUEST_MODULE) || outputBufferLength < sizeof(REQUEST_MODULE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREQUEST_MODULE args = (PREQUEST_MODULE)inputBuffer;


        // Call CoreModule with the args
        status = CoreModule(args);

        //print all input values in one line 
		DbgPrint("GET_MODULE_INFO - ProcessId: %d, Module: %ws, OutAddress: %p, OutSize: %d\n", args->ProcessId, args->Module, args->OutAddress, args->OutSize);

        if (NT_SUCCESS(status)) {
			DbgPrint("GET_MODULE_INFO: Found module %ws at %p\n", args->Module, args->OutAddress);
            // Copy the updated args back to the output buffer
            RtlCopyMemory(outputBuffer, args, sizeof(REQUEST_MODULE));
            information = sizeof(REQUEST_MODULE);
        }
        break;
    }

    case IOCTL_EXTEND_MODULE: {
        if (inputBufferLength < sizeof(REQUEST_EXTEND)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREQUEST_EXTEND args = (PREQUEST_EXTEND)inputBuffer;

        if (args->Size == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        //print all input values in one line 
		DbgPrint("EXTEND_MODULE - ProcessId: %d, Address: %p, Size: %d\n", args->ProcessId, args->Size);

        status = CoreExtend(args);

        if (NT_SUCCESS(status)) {

			DbgPrint("EXTEND_MODULE: Extended memory to %p\n", args->Size);
            RtlCopyMemory(outputBuffer, args, sizeof(REQUEST_EXTEND));
            information = sizeof(REQUEST_EXTEND);
		
        }
        break;
    }

    case IOCTL_WRITE_MEMORY: {
        if (inputBufferLength < sizeof(REQUEST_WRITE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREQUEST_WRITE args = (PREQUEST_WRITE)inputBuffer;

        //print all input values in one line 
        DbgPrint("WRITE_MEMORY - ProcessId: %d, Src: %p, Dest: %p, Size: %lu\n", args->ProcessId, args->Src, args->Dest, args->Size);

        if (args->Size == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = CoreWrite(args);

        if (NT_SUCCESS(status)) {
			DbgPrint("WRITE_MEMORY: Wrote memory at %p\n", args->Dest);
            information = sizeof(REQUEST_WRITE);
        }
        break;
    }

    case IOCTL_READ_MEMORY: {
        if (inputBufferLength < sizeof(REQUEST_READ) || outputBufferLength < sizeof(REQUEST_READ)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREQUEST_READ args = (PREQUEST_READ)inputBuffer;

        if (args->Size == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

		//print all input values in one line 
		DbgPrint("READ_MEMORY - ProcessId: %d, Src: %p, Dest: %p, Size: %d\n", args->ProcessId, args->Src, args->Dest,  args->Size);


        status = CoreRead(args);

        if (NT_SUCCESS(status)) {
			DbgPrint("READ_MEMORY: Read memory at %p\n", args->Dest);
            RtlCopyMemory(outputBuffer, args, sizeof(REQUEST_READ));
            information = sizeof(REQUEST_READ);
        }
        break;
    }

    case IOCTL_PROTECT_MEMORY: {
        if (inputBufferLength < sizeof(REQUEST_PROTECT) || outputBufferLength < sizeof(REQUEST_PROTECT)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREQUEST_PROTECT args = (PREQUEST_PROTECT)inputBuffer;

        //print all input values in one line 
		DbgPrint("PROTECT_MEMORY - ProcessId: %d, Address: %p, Size: %d, InOutProtect: %p\n", args->ProcessId, args->Address, args->Size, args->InOutProtect);

        if (args->Size == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = CoreProtect(args);

        if (NT_SUCCESS(status)) {
			DbgPrint("PROTECT_MEMORY: Protected memory at %p\n", args->Address);
            RtlCopyMemory(outputBuffer, args, sizeof(REQUEST_PROTECT));
            information = sizeof(REQUEST_PROTECT);
        }
        break;
    }


    case IOCTL_ALLOC_MEMORY: {
        if (inputBufferLength < sizeof(REQUEST_ALLOC) || outputBufferLength < sizeof(REQUEST_ALLOC)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        PREQUEST_ALLOC args = (PREQUEST_ALLOC)inputBuffer;

        //print all input values in one line 
		DbgPrint("ALLOC_MEMORY - ProcessId: %d, OutAddress: %p, Size: %d, Protect: %d\n", args->ProcessId, args->OutAddress, args->Size, args->Protect);

        if (args->Size == 0) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = CoreAlloc(args);

        if (NT_SUCCESS(status)) {
			DbgPrint("ALLOC_MEMORY: Allocated memory at %p\n", args->OutAddress);
            RtlCopyMemory(outputBuffer, args, sizeof(REQUEST_ALLOC));
            information = sizeof(REQUEST_ALLOC);
        }
        break;
    }

    case IOCTL_FREE_MEMORY: {
        if (inputBufferLength < sizeof(REQUEST_FREE)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }



        PREQUEST_FREE args = (PREQUEST_FREE)inputBuffer;

		//print all input values in one line
		DbgPrint("FREE_MEMORY - ProcessId: %d, Address: %p\n", args->ProcessId, args->Address);

        status = CoreFree(args);

        if (NT_SUCCESS(status)) {
            //print status
            DbgPrint("FREE_MEMORY: freed memory at %p\n", args->Address);
            information = sizeof(REQUEST_FREE);
        }
        break;
    }


	//default: {
    //    status = STATUS_INVALID_DEVICE_REQUEST;
    //    break;
    //}


                              // ... [Other cases remain the same]
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink;
    RtlInitUnicodeString(&symLink, SYMLINK_NAME);

    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrint("Driver Unloaded\n");
}