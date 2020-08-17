#pragma once

#include <windows.h>
#include <string>

namespace injection {
	namespace standard {
		HANDLE open_process(DWORD process_id, ULONG flags);
		int inject(HANDLE process_handle, const char* dll_path);
		int inject(HANDLE process_handle, std::string dll_path);
	}

	namespace hook {
		int inject(DWORD thread_id, const char* dll_path, const char* export_name);
		int inject(DWORD thread_id, std::string dll_path, std::string export_name);
	}

	namespace manual_map {
		int inject(DWORD process_id, DWORD thread_id, const char* dll_path);
		int inject(DWORD process_id, DWORD thread_id, std::string dll_path);
	}
}