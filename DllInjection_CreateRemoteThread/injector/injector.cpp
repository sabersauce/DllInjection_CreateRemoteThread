//download a url
//injector

//using CreateRemoteThread()

#include <tchar.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

#define DLL_NAME L"urldownload.dll"
wchar_t dllName[MAX_PATH];

BOOL
InjectDll(DWORD pID) {
	HMODULE hDll = GetModuleHandle(L"kernel32.dll");
	if (hDll == NULL) {
		wprintf(L"Get handle of kernel32.dll error.\n");
		return FALSE;
	}

	LPTHREAD_START_ROUTINE pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hDll, "LoadLibraryW");
	if (pThreadProc == NULL) {
		wprintf(L"Get address of LoadLibraryW() error.\n");
		return FALSE;
	}


	HANDLE hProcess = INVALID_HANDLE_VALUE;
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (hProcess == INVALID_HANDLE_VALUE) {
		wprintf(L"Open process error.\n");
		return FALSE;
	}

	DWORD bufSizeForDllName = (DWORD)(wcslen(dllName) + 1)*sizeof(wchar_t);
	LPVOID pRemoteBuf = VirtualAllocEx(hProcess, NULL, bufSizeForDllName, MEM_COMMIT, PAGE_READWRITE);
	if (pRemoteBuf == NULL) {
		wprintf(L"Memory Allocation failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}

	unsigned long bytesWritten = 0;
	if ((!WriteProcessMemory(hProcess, pRemoteBuf, dllName, bufSizeForDllName, &bytesWritten)) || bytesWritten != bufSizeForDllName) {
		wprintf(L"Write process memory error.\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);
	printf("%d", hThread);
	if (hThread == NULL) {
		wprintf(L"Create remote thread failed.\n");
		CloseHandle(hProcess);
		return FALSE;
	}
	
	if (WaitForSingleObject(hThread, INFINITE) != WAIT_OBJECT_0) {
		wprintf(L"Thread run failed.\n");
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return FALSE;
	}
	else {
		CloseHandle(hThread);
		CloseHandle(hProcess);
		return TRUE;
	}
}

int
_tmain(int argc, TCHAR *argv[]) {
	if (argc != 2) {
		if (argc != 1) wprintf(L"Wrong parameters.\n\n");
		wprintf(L"Usage:injector.exe <ProcessName>\n");
		return FALSE;
	}

	if (!GetModuleFileNameW(NULL, dllName, MAX_PATH)) {
		wprintf(L"Get file path error.\n");
		return FALSE;
	}
	wchar_t *pos=wcsrchr(dllName, L'\\');
	wcscpy(pos + 1, DLL_NAME);

	DWORD pID = -1;

	HANDLE snapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32W pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapShot == INVALID_HANDLE_VALUE) {
		wprintf(L"Create snapshot error.\n");
		return FALSE;
	}

	Process32FirstW(snapShot, &pe32);
	do {
		if (!wcscmp(pe32.szExeFile, argv[1])) {
			pID = pe32.th32ProcessID;
		}
	} while (Process32NextW(snapShot, &pe32));
	if (pID == -1) {
		wprintf(L"Process not found.\n");
		CloseHandle(snapShot);
		return FALSE;
	}

	if (InjectDll(pID)) {
		wprintf(L"Injection completed successfully.\n");
		return TRUE;
	}
	else {
		wprintf(L"Injection failed.\n");
		return FALSE;
	}
}