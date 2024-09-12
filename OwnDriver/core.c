#include "stdafx.h"

extern PMMVAD(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable);
extern NTSTATUS(*MiInsertVadCharges)(PMMVAD vad, PEPROCESS process);
extern VOID(*MiInsertVad)(PMMVAD vad, PEPROCESS process);


PLDR_DATA_TABLE_ENTRY GetModuleByName(PEPROCESS process, PWCHAR moduleName) {
	UNICODE_STRING moduleNameStr = { 0 };
	RtlInitUnicodeString(&moduleNameStr, moduleName);

	//DbgPrint("GetModuleByName: Searching for module %wZ\n", &moduleNameStr);

	__try {
		PPEB peb = PsGetProcessPeb(process);
		if (!peb) {
			DbgPrint("GetModuleByName: Failed to get PEB\n");
			return NULL;
		}

		KAPC_STATE apcState;
		KeStackAttachProcess(process, &apcState);

		PPEB_LDR_DATA ldr = peb->Ldr;
		if (!ldr) {
			DbgPrint("GetModuleByName: Ldr is NULL\n");
			KeUnstackDetachProcess(&apcState);
			return NULL;
		}

		for (PLIST_ENTRY entry = ldr->InLoadOrderModuleList.Flink;
			entry != &ldr->InLoadOrderModuleList;
			entry = entry->Flink) {
			PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (RtlCompareUnicodeString(&module->BaseDllName, &moduleNameStr, TRUE) == 0) {
				//DbgPrint("GetModuleByName: Found matching module %wZ\n", &module->BaseDllName);
				KeUnstackDetachProcess(&apcState);
				return module;
			}
		}

		KeUnstackDetachProcess(&apcState);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("GetModuleByName: Exception occurred\n");
		return NULL;
	}

	DbgPrint("GetModuleByName: Module %wZ not found\n", &moduleNameStr);
	return NULL;
}


NTSTATUS CoreExtend(PREQUEST_EXTEND args) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
	if (!NT_SUCCESS(status)) {
		DbgPrint("CoreExtend: PsLookupProcessByProcessId failed with status 0x%X\n", status);
		return status;
	}

	KeAttachProcess(process);

	PLDR_DATA_TABLE_ENTRY module = GetModuleByName(process, args->Module);
	if (!module) {
		DbgPrint("CoreExtend: Module %ws not found\n", args->Module);
		status = STATUS_NOT_FOUND;
		goto cleanup;
	}


	UINT_PTR start;
	UINT_PTR end;
	SIZE_T moduleSize;

	if (!SafeCopy(&start, &module->DllBase, sizeof(UINT_PTR)) ||
		!SafeCopy(&moduleSize, &module->SizeOfImage, sizeof(SIZE_T))) {
		DbgPrint("CoreExtend: SafeCopy failed for module base or size\n");
		status = STATUS_ACCESS_VIOLATION;
		goto cleanup;
	}


	start += moduleSize;
	end = start + args->Size - 1;


	MEMORY_BASIC_INFORMATION info = { 0 };
	status = ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)start, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("CoreExtend: ZwQueryVirtualMemory failed with status 0x%X\n", status);
		goto cleanup;
	}

	if (info.State != MEM_FREE || info.BaseAddress != (PVOID)start || info.RegionSize < args->Size) {
		DbgPrint("CoreExtend: Invalid memory region. State: %d, BaseAddress: 0x%p, RegionSize: 0x%zX\n",
			info.State, info.BaseAddress, info.RegionSize);
		status = STATUS_INVALID_ADDRESS;
		goto cleanup;
	}


	PMMVAD vad = MiAllocateVad(start, end, TRUE);
	if (!vad) {
		DbgPrint("CoreExtend: MiAllocateVad failed\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanup;
	}



	static RTL_OSVERSIONINFOW version = { sizeof(RTL_OSVERSIONINFOW) };
	if (!version.dwBuildNumber) {
		RtlGetVersion(&version);
	}

	

	if (version.dwBuildNumber >= 22000) {
		//DbgPrint("CoreExtend: Windows Build Number: %d\n", version.dwBuildNumber);

		PMMVAD_FLAGS flags = (PMMVAD_FLAGS)&vad->u1.LongFlags;
		flags->Protection = MM_EXECUTE_READWRITE;
		flags->NoChange = 0;
	}


	if (!NT_SUCCESS(status = MiInsertVadCharges(vad, process))) {
		DbgPrint("CoreExtend: MiInsertVadCharges failed with status 0x%X\n", status);
		ExFreePool(vad);
		goto cleanup;
	}

	MiInsertVad(vad, process);
	module->SizeOfImage += args->Size;

cleanup:
	KeDetachProcess();
	ObDereferenceObject(process);
	return status;
}

NTSTATUS CoreWrite(PREQUEST_WRITE args) {
	if (((PBYTE)args->Src + args->Size < (PBYTE)args->Src) ||
		((PBYTE)args->Dest + args->Size < (PBYTE)args->Dest) ||
		((PVOID)((PBYTE)args->Src + args->Size) > MM_HIGHEST_USER_ADDRESS) ||
		((PVOID)((PBYTE)args->Dest + args->Size) > MM_HIGHEST_USER_ADDRESS)) {

		return STATUS_ACCESS_VIOLATION;
	}	

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		SIZE_T outSize = 0;
		status = MmCopyVirtualMemory(PsGetCurrentProcess(), args->Src, process, args->Dest, (SIZE_T)args->Size, KernelMode, &outSize);
		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS CoreRead(PREQUEST_READ args) {
	if (((PBYTE)args->Src + args->Size < (PBYTE)args->Src) ||
		((PBYTE)args->Dest + args->Size < (PBYTE)args->Dest) ||
		((PVOID)((PBYTE)args->Src + args->Size) > MM_HIGHEST_USER_ADDRESS) ||
		((PVOID)((PBYTE)args->Dest + args->Size) > MM_HIGHEST_USER_ADDRESS)) {

		return STATUS_ACCESS_VIOLATION;
	}

	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		SIZE_T outSize = 0;
		status = MmCopyVirtualMemory(process, args->Src, PsGetCurrentProcess(), args->Dest, (SIZE_T)args->Size, KernelMode, &outSize);
		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS CoreProtect(PREQUEST_PROTECT args) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		DWORD protect = 0;
		if (SafeCopy(&protect, args->InOutProtect, sizeof(protect))) {
			SIZE_T size = args->Size;

			//DWORD protect2 = *args->InOutProtect;
			//DbgPrint("CoreProtect: protect2: %08x\n", protect2);

			//print input parameters in one line NtCurrentProcess(), &args->Address, &size, protect, &protect
			DbgPrint("CoreProtect: NtCurrentProcess: %p, Address: %p, Size: %d, Protect: %08x, InOutProtect: %08x\n", NtCurrentProcess(), args->Address, size, protect, protect);

			KeAttachProcess(process);
			status = ZwProtectVirtualMemory(NtCurrentProcess(), &args->Address, &size, protect, &protect);
			KeDetachProcess();

			SafeCopy(args->InOutProtect, &protect, sizeof(protect));
		} else {
			status = STATUS_ACCESS_VIOLATION;
		}
		
		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS CoreAlloc(PREQUEST_ALLOC args) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		PVOID address = NULL;
		SIZE_T size = args->Size;

		
		KeAttachProcess(process);
		ZwAllocateVirtualMemory(NtCurrentProcess(), &address, 0, &size, MEM_COMMIT | MEM_RESERVE, args->Protect);
		KeDetachProcess();


		SafeCopy(args->OutAddress, &address, sizeof(address));


		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS CoreFree(PREQUEST_FREE args) {
	PEPROCESS process = NULL;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
	if (NT_SUCCESS(status)) {
		SIZE_T size = 0;

		KeAttachProcess(process);
		ZwFreeVirtualMemory(NtCurrentProcess(), &args->Address, &size, MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(process);
	}

	return status;
}

NTSTATUS CoreModule(PREQUEST_MODULE args) {
	PEPROCESS process = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	KAPC_STATE apcState;

	__try {
		status = PsLookupProcessByProcessId((HANDLE)args->ProcessId, &process);
		if (!NT_SUCCESS(status)) {
			DbgPrint("CoreModule: PsLookupProcessByProcessId failed with status %08x\n", status);
			return status;
		}

		PLDR_DATA_TABLE_ENTRY module = NULL;

		__try {
			KeStackAttachProcess(process, &apcState);
			module = GetModuleByName(process, args->Module);

			if (module) {
				// Safely read the DllBase and SizeOfImage
				PVOID base = NULL;
				ULONG size = 0;

				if (SafeCopy(&base, &module->DllBase, sizeof(PVOID)) &&
					SafeCopy(&size, &module->SizeOfImage, sizeof(ULONG))) {


					// Update the args structure
					args->OutAddress = base;
					args->OutSize = size;

					status = STATUS_SUCCESS;
				}
				else {
					DbgPrint("CoreModule: Failed to safely read module information\n");
					status = STATUS_UNSUCCESSFUL;
				}
			}
			else {
				DbgPrint("CoreModule: Module not found\n");
				status = STATUS_NOT_FOUND;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			status = GetExceptionCode();
			DbgPrint("CoreModule: Exception while accessing module information. Status: %08x\n", status);
		}

		KeUnstackDetachProcess(&apcState);

		if (!NT_SUCCESS(status)) {
			// Clear the output fields in case of failure
			args->OutAddress = NULL;
			args->OutSize = 0;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		status = GetExceptionCode();
		DbgPrint("CoreModule: Unexpected exception occurred. Status: %08x\n", status);

		// Clear the output fields in case of exception
		args->OutAddress = NULL;
		args->OutSize = 0;
	}

	if (process) {
		ObDereferenceObject(process);
	}

	return status;
}