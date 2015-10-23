//download a url
//urldownload.dll

//using CreateRemoteThread()

#include <Windows.h>
#include <tchar.h>

#pragma comment(lib,"urlmon.lib")

#define URL L"https://www.baidu.com/robots.txt"

HINSTANCE hInst = NULL;

DWORD WINAPI
ThreadProc(LPVOID lParam) {
	wchar_t path[MAX_PATH] = { 0 };
	if (GetModuleFileNameW(hInst, path, MAX_PATH)) {
		URLDownloadToFileW(NULL, URL, path, 0, NULL);
	}
	return TRUE;
}

BOOL WINAPI
DllMain(HINSTANCE hInstDll, DWORD reason, LPVOID lpvReserved) {
	switch (reason)
	{
//	case DLL_THREAD_ATTACH:
	case DLL_PROCESS_ATTACH:
		hInst = hInstDll;
		HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ThreadProc, NULL, 0, NULL);
		CloseHandle(hThread);
		break;
	}
	return TRUE;
}