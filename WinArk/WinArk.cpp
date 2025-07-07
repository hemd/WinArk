#include "stdafx.h"

#include "resource.h"
#include "Table.h"

#include "aboutdlg.h"
#include "MainFrame.h"
#include "DriverHelper.h"
#include "SymbolFileInfo.h"
#include "PEParser.h"
#include <filesystem>
#include <Helpers.h>
#include "SymbolHelper.h"
#include "SecurityHelper.h"
#include <atomic>
#include <wil/resource.h>
#include <future>

CAppModule _Module;
HWND _hMainWnd = nullptr;
AppSettings _Settings;

bool InitSymbols(std::wstring fileName) {
	WCHAR path[MAX_PATH] = {};
	::GetSystemDirectory(path, MAX_PATH);
	wcscat_s(path, L"\\");
	wcscat_s(path, fileName.c_str());
	PEParser parser(path);
	auto dir = parser.GetDataDirectory(IMAGE_DIRECTORY_ENTRY_DEBUG);
	if (!dir) {
		return false;
	}
	SymbolFileInfo info;
	auto entry = static_cast<PIMAGE_DEBUG_DIRECTORY>(parser.GetAddress(dir->VirtualAddress));
	ULONG_PTR VA = reinterpret_cast<ULONG_PTR>(parser.GetBaseAddress());
	info.GetPdbSignature(VA, entry);
	::GetCurrentDirectory(MAX_PATH, path);
	wcscat_s(path, L"\\Symbols");
	return info.SymDownloadSymbol(path);
}

void ClearSymbols() {
	WCHAR path[MAX_PATH];
	::GetCurrentDirectory(MAX_PATH, path);
	wcscat_s(path, L"\\Symbols");
	std::filesystem::remove_all(path);
}

// {A67605F7-BCFA-47F0-970D-92799D8F375E}
static const GUID iconGuid =
{ 0xa67605f7, 0xbcfa, 0x47f0, { 0x97, 0xd, 0x92, 0x79, 0x9d, 0x8f, 0x37, 0x5e } };

bool ShowBalloonTip(PCWSTR title, PCWSTR text, ULONG timeout) {
	NOTIFYICONDATA notifyIcon = { sizeof(NOTIFYICONDATA) };


	notifyIcon.uFlags = NIF_INFO | NIF_GUID;
	notifyIcon.hWnd = _hMainWnd;
	notifyIcon.uID = IDR_MAINFRAME;
	notifyIcon.guidItem = iconGuid;
	wcsncpy_s(notifyIcon.szInfoTitle, RTL_NUMBER_OF(notifyIcon.szInfoTitle), title, _TRUNCATE);
	wcsncpy_s(notifyIcon.szInfo, RTL_NUMBER_OF(notifyIcon.szInfo), text, _TRUNCATE);
	notifyIcon.uTimeout = timeout;
	notifyIcon.dwInfoFlags = NIIF_INFO;

	return Shell_NotifyIcon(NIM_MODIFY, &notifyIcon);
}

bool ShowIconNotication(PCWSTR title, PCWSTR text) {
	bool success = ShowBalloonTip(title, text, 10);
	return success;
}

bool AddNotifyIcon() {
	NOTIFYICONDATA notifyIcon = { sizeof(NOTIFYICONDATA) };
	notifyIcon.hWnd = _hMainWnd;
	notifyIcon.uID = IDR_MAINFRAME;
	notifyIcon.uFlags = NIF_ICON | NIF_GUID | NIF_TIP;
	notifyIcon.guidItem = iconGuid;

	return Shell_NotifyIcon(NIM_ADD, &notifyIcon);
}

bool RemoveNotifyIcon() {
	NOTIFYICONDATA notifyIcon = { sizeof(NOTIFYICONDATA) };

	notifyIcon.uFlags = NIF_GUID;
	notifyIcon.hWnd = _hMainWnd;
	notifyIcon.uID = IDR_MAINFRAME;
	notifyIcon.guidItem = iconGuid;

	return Shell_NotifyIcon(NIM_DELETE, &notifyIcon);
}

int Run(LPTSTR lpstrCmdLine = nullptr, int nCmdShow = SW_SHOWDEFAULT) {
	CMessageLoop theLoop;
	_Module.AddMessageLoop(&theLoop);

	std::future<bool> symbolInitFuture = std::async(std::launch::async, []() -> bool {
		std::string name = Helpers::GetNtosFileName();
		std::wstring osFileName = Helpers::StringToWstring(name);
		return InitSymbols(osFileName.c_str()) && InitSymbols(L"user32.dll") && InitSymbols(L"ntdll.dll")
			&& InitSymbols(L"win32k.sys") && InitSymbols(L"ci.dll") && InitSymbols(L"drivers\\fltmgr.sys");
		});

	if (!symbolInitFuture.get()) {
		// Symbol initialization failed
		return 0;
	}

	SymbolHelper::Init();

	InitColorSys();
	InitFontSys();
	InitPenSys();
	InitBrushSys();
	InitSchemSys();

	CMainFrame wndMain;
	_hMainWnd = wndMain.CreateEx(NULL);
	if (_hMainWnd == NULL) {
		ATLTRACE(_T("Main dialog creation failed!\n"));
		return 0;
	}
	AddNotifyIcon();

	ShowIconNotication(L"WinArk Initialization", L"WinArk Initialize successfully!");

	wndMain.ShowWindow(nCmdShow);

	int nRet = theLoop.Run();

	RemoveNotifyIcon();
	_Module.RemoveMessageLoop();
	return nRet;
}

bool CheckInstall(PCWSTR cmdLine) {
	bool success = true;

	auto hRes = ::FindResource(nullptr, MAKEINTRESOURCE(IDR_DRIVER), L"BIN");
	if (!hRes)
		return false;

	auto hGlobal = ::LoadResource(nullptr, hRes);
	if (!hGlobal)
		return false;

	auto size = ::SizeofResource(nullptr, hRes);
	void* pBuffer = ::LockResource(hGlobal);

	if (::wcsstr(cmdLine, L"install")) {
		success = DriverHelper::LoadDriver();
		if (!success)
			if (DriverHelper::InstallDriver(false, pBuffer, size))
				success = DriverHelper::LoadDriver();
		if (!success)
			AtlMessageBox(nullptr, L"Failed to install/load kernel driver", IDS_TITLE, MB_ICONERROR);
	}
	else if (::wcsstr(cmdLine, L"update")) {
		success = DriverHelper::UpdateDriver(pBuffer, size);
		if (!success) {
			AtlMessageBox(nullptr, L"Failed to update kernel driver", IDS_TITLE, MB_ICONERROR);
		}
	}
	return success;
}

LONG WINAPI SelfUnhandledExceptionFilter(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (EXCEPTION_ACCESS_VIOLATION == ExceptionInfo->ExceptionRecord->ExceptionCode) {
		// probably the network related thread failing during symbol loading when terminated abruptly
		::ExitThread(0);
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_EXECUTE_HANDLER;
}

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR lpstrCmdLine, int nCmdShow) {
	wil::unique_handle hSingleInstMutex{ ::CreateMutex(nullptr, FALSE, L"WinArkSingleInstanceMutex") };
	if (hSingleInstMutex && ::GetLastError() == ERROR_ALREADY_EXISTS) {
		MessageBox(nullptr, L"Please do not double start!!!", L"Error", MB_ICONERROR);
		return -1;
	}

	HRESULT hRes = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
	ATLASSERT(SUCCEEDED(hRes));
	// add flags to support other controls
	AtlInitCommonControls(ICC_BAR_CLASSES | ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES);

	hRes = _Module.Init(NULL, hInstance);
	ATLASSERT(SUCCEEDED(hRes));
	::SetPriorityClass(::GetCurrentProcess(), HIGH_PRIORITY_CLASS);
	::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

	::SetUnhandledExceptionFilter(SelfUnhandledExceptionFilter);

	SecurityHelper::EnablePrivilege(SE_SYSTEM_ENVIRONMENT_NAME, true); // 可以调用 SetFirmwareEnvironmentVariable 和 GetFirmwareEnvironmentVariable 等 API
	SecurityHelper::EnablePrivilege(SE_DEBUG_NAME, true);

	if (!CheckInstall(lpstrCmdLine))
		return 0;

	::SymSetOptions(SYMOPT_UNDNAME // 取消符号修饰
		| SYMOPT_CASE_INSENSITIVE
		| SYMOPT_AUTO_PUBLICS
		| SYMOPT_INCLUDE_32BIT_MODULES
		| SYMOPT_OMAP_FIND_NEAREST);
	::SymInitialize(::GetCurrentProcess(), nullptr, TRUE);

	int nRet = Run(lpstrCmdLine, nCmdShow);

	DriverHelper::LoadDriver(false);

	::SymCleanup(::GetCurrentProcess());
	_Module.Term();
	::CoUninitialize();

	return nRet;
}