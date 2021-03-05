#pragma once

#include <windows.h>
#include <string>

namespace injection {
	namespace standard {
		HANDLE open_process(DWORD process_id, ULONG flags);
		int inject(HANDLE process_handle, const wchar_t* dll_path);
		int inject(HANDLE process_handle, std::wstring dll_path);
	}

	namespace hook {
		int inject(DWORD thread_id, const wchar_t* dll_path, const char* export_name);
		int inject(DWORD thread_id, std::wstring dll_path, std::string export_name);
	}

	namespace manual_map { // note: requires message sent to window procedure, could be activated via SendMessageA or by hovering over the window with your mouse
		int inject(DWORD process_id, DWORD thread_id, const wchar_t* dll_path);
		int inject(DWORD process_id, DWORD thread_id, std::wstring dll_path);
	}
}