#include "stdafx.h"
#include <iostream>


bool KillProcessByName(const std::wstring& processName) {
	bool result = false;
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes) {
		if (std::wstring(pEntry.szExeFile) == processName) {
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				static_cast<DWORD>(pEntry.th32ProcessID));
			if (hProcess != NULL) {
				result = TerminateProcess(hProcess, 9);
				CloseHandle(hProcess);
				if (result) {
					std::wcout << L"Process " << processName << L" terminated successfully" << std::endl;
				}
				else {
					std::wcerr << L"Failed to terminate process " << processName << std::endl;
				}
			}
			else {
				std::wcerr << L"Failed to open process " << processName << std::endl;
			}
			break;
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return result;
}

INT main()
{

	LPCSTR  ProcessName = "notepad++.exe";
	std::wstring wProcessName = StrToWStr(ProcessName);

	LPCSTR  ModuleName = "mimetools.dll";
	//LPCSTR  DllPath = "C:\\Users\\tilln\\source\\repos\\OwnDriver\\x64\\Debug\\FirstInternalHack.dll";
	LPCSTR  DllPath = "basicentry.dll";
	
	//LPCSTR  DllPath = "C:\\Users\\tilln\\source\\repos\\OwnDriver\\x64\\Debug\\HelloWorld.dll";


	//KillProcessByName(wProcessName);
	//ShellExecuteA(NULL, "open", "C:\\Program Files\\Notepad++\\notepad++.exe", NULL, NULL, SW_SHOWNORMAL);
	//Sleep(500);



	process::Process process(StrToWStr(ProcessName));
	if (!process.Valid()) {
		errorf("Process '%s' not found \n", ProcessName);
		return 1;
	}

	wprintf(L"Process '%ls' found successfully\n", wProcessName.c_str());


	auto entry = Map::ExtendMap(process, StrToWStr(DllPath), StrToWStr(ModuleName));

	if (!entry) {
		return 1;
	}

	printf("\n[-] entry point: %p\n", entry);


	if (!Hijack::HijackViaHook(process, entry, L"user32.dll", "PeekMessageA")) {
		return 1;
	}




	return 0;

}

