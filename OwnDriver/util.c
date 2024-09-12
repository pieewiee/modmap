#include "stdafx.h"

BOOLEAN SafeCopy(PVOID Destination, PVOID Source, SIZE_T Size) {
	__try {
		ProbeForRead(Source, Size, 1);
		RtlCopyMemory(Destination, Source, Size);
		return TRUE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
}

BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask) {
	for (; *mask; ++base, ++pattern, ++mask) {
		if (*mask == 'x' && *base != *pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask) {
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i) {
		PVOID addr = &base[i];
		if (CheckMask(addr, pattern, mask)) {
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask) {
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (*(PINT)section->Name == 'EGAP' || memcmp(section->Name, ".text", 5) == 0) {
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match) {
				break;
			}
		}
	}

	return match;
}

PVOID GetKernelBase() {
	PVOID addr = 0;

	ULONG size = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return addr;
	}

	PSYSTEM_MODULE_INFORMATION modules = ExAllocatePool(NonPagedPool, size);
	if (!modules) {
		return addr;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, modules, size, 0))) {
		ExFreePool(modules);
		return addr;
	}

	if (modules->NumberOfModules > 0) {
		addr = modules->Modules[0].ImageBase;
	}

	ExFreePool(modules);
	return addr;
}