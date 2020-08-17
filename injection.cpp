#include "injection.h"
#include "files.h"
#include "utilities.h"

#include <TlHelp32.h>
#include <DbgHelp.h>
#include <intrin.h>
#include <winnt.h>

namespace injection {
	// standard

	namespace standard {
		HANDLE open_process(DWORD process_id, ULONG flags) {
			return OpenProcess(flags, false, process_id);
		}

		int inject(HANDLE process_handle, const char* dll_path) {
			void* dll_path_address = VirtualAllocEx(process_handle, NULL, strlen(dll_path) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!dll_path_address)
				return -1;

			size_t bytes_written;
			if (!WriteProcessMemory(process_handle, dll_path_address, dll_path, strlen(dll_path) + 1, &bytes_written))
				return -2;

			void* loadlibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
			HANDLE thread_handle = CreateRemoteThread(process_handle, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadlibrary), dll_path_address, 0, NULL);
			if (!thread_handle)
				return -3;

			WaitForSingleObject(thread_handle, INFINITE);

			return 1;
		}

		int inject(HANDLE process_handle, std::string dll_path) {
			return inject(process_handle, dll_path.c_str());
		}
	}

	// hook

	namespace hook {
		int inject(DWORD thread_id, const char* dll_path, const char* export_name) {
			HMODULE dll = LoadLibraryExA(dll_path, NULL, DONT_RESOLVE_DLL_REFERENCES);
			if (!dll)
				return -1;

			void* export_address = GetProcAddress(dll, export_name);
			if (!export_address)
				return -2;

			char filename[260];
			DWORD got_filename = GetModuleFileNameA(dll, filename, 260);
			
			HHOOK hook = SetWindowsHookExA(WH_GETMESSAGE, reinterpret_cast<HOOKPROC>(export_address), dll, thread_id);
			if (!hook) {
				printf("%x\n", GetLastError());
				return -3;
			}

			while (!PostThreadMessageA(thread_id, WM_NULL, NULL, NULL))
				Sleep(100);

			return 1;
		}

		int inject(DWORD thread_id, std::string dll_path, std::string export_name) {
			return inject(thread_id, dll_path.c_str(), export_name.c_str());
		}
	}

	// manual map

	namespace manual_map {
		byte thread_hijack_shell[] = {
				0x51, // push rcx
				0x50, // push rax
				0x52, // push rdx
				0x48, 0x83, 0xEC, 0x20, // sub rsp, 0x20
				0x48, 0xB9, // movabs rcx, ->
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x48, 0xBA, // movabs rdx, ->
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x48, 0xB8, // movabs rax, ->
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xD0, // call rax
				0x48, 0xBA, // movabs rdx, ->
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x48, 0x89, 0x54, 0x24, 0x18, // mov qword ptr [rsp + 0x18], rdx
				0x48, 0x83, 0xC4, 0x20, // add rsp, 0x20
				0x5A, // pop rdx
				0x58, // pop rax
				0x59, // pop rcx
				0xFF, 0x64, 0x24, 0xE0 // jmp qword ptr [rsp - 0x20]
		};

		IMAGE_SECTION_HEADER* translate_raw_section(IMAGE_NT_HEADERS* nt, DWORD rva) {
			auto section = IMAGE_FIRST_SECTION(nt);
			for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
				if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize)
					return section;
			}

			return NULL;
		}

		void* translate_raw(char* base, IMAGE_NT_HEADERS* nt, DWORD rva) {
			auto section = translate_raw_section(nt, rva);
			if (!section)
				return NULL;

			return base + section->PointerToRawData + (rva - section->VirtualAddress);
		}

		bool resolve_imports(char* base, IMAGE_NT_HEADERS* nt) {
			auto rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
			if (!rva)
				return true;

			auto import = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(translate_raw(base, nt, rva));
			if (!import)
				return true;

			for (; import->FirstThunk; ++import) {
				auto module_name = reinterpret_cast<char*>(translate_raw(base, nt, import->Name));
				if (!module_name)
					break;

				auto module = LoadLibraryA(module_name);
				if (!module)
					return false;

				for (auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(translate_raw(base, nt, import->FirstThunk)); thunk->u1.AddressOfData; ++thunk) {
					auto by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(translate_raw(base, nt, static_cast<DWORD>(thunk->u1.AddressOfData)));
					thunk->u1.Function = reinterpret_cast<UINT_PTR>(GetProcAddress(module, by_name->Name));
				}
			}

			return true;
		}

		void resolve_relocations(char* base, IMAGE_NT_HEADERS* nt, byte* mapped) {
			auto& base_relocation = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (!base_relocation.VirtualAddress)
				return;

			auto reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(translate_raw(base, nt, base_relocation.VirtualAddress));
			if (!reloc)
				return;

			for (auto current_size = 0UL; current_size < base_relocation.Size; ) {
				auto count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				auto rdata = reinterpret_cast<WORD*>(reinterpret_cast<byte*>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
				auto rbase = reinterpret_cast<byte*>(translate_raw(base, nt, reloc->VirtualAddress));

				for (auto i = 0UL; i < count; ++i, ++rdata) {
					auto data = *rdata;
					auto type = data >> 12;
					auto offset = data & 0xFFF;

					if (type == IMAGE_REL_BASED_DIR64)
						*reinterpret_cast<PBYTE*>(rbase + offset) += (mapped - reinterpret_cast<PBYTE>(nt->OptionalHeader.ImageBase));
				}

				current_size += reloc->SizeOfBlock;
				reloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(rdata);
			}
		}

		int inject(DWORD process_id, DWORD thread_id, const char* dll_path) {
			auto buffer = files::load_binary(dll_path);
			auto dll = new char[buffer.length()]; memcpy(dll, buffer.data(), buffer.length());
			auto module = LoadLibraryExA(dll_path, NULL, DONT_RESOLVE_DLL_REFERENCES);

			IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dll);
			if (dos->e_magic != IMAGE_DOS_SIGNATURE)
				return -1;

			IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint64_t>(dll) + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
				return -2;

			/* write image to process */

			HANDLE process = standard::open_process(process_id, PROCESS_ALL_ACCESS);
			void* image = VirtualAllocEx(process, NULL, nt->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!image) {
				CloseHandle(process);
				return -3;
			}

			printf("allocate image: %p\n", image);

			// resolve imports
			if (!resolve_imports(dll, nt))
				return -4;

			// resolve relocations
			resolve_relocations(dll, nt, reinterpret_cast<byte*>(image));

			// copy headers to image
			WriteProcessMemory(process, image, dll, nt->OptionalHeader.SizeOfHeaders, NULL);

			printf("wrote headers to image\n");

			// copy sections to image
			IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);
			for (size_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
				printf("section[%i]: %s\n", i, section[i].Name);
				WriteProcessMemory(process, reinterpret_cast<void*>(reinterpret_cast<uint64_t>(image) + section[i].VirtualAddress),
					reinterpret_cast<void*>(reinterpret_cast<uint64_t>(dll) + section[i].PointerToRawData), section[i].SizeOfRawData, NULL);
			}

			/* execute image */

			void* loader = VirtualAllocEx(process, NULL, sizeof(thread_hijack_shell), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (!loader)
				return -5;

			HANDLE thread = OpenThread(THREAD_ALL_ACCESS, false, thread_id);
			auto shell = thread_hijack_shell;
			memcpy(shell + 9, &image, sizeof(void*));

			void* reason = reinterpret_cast<void*>(DLL_PROCESS_ATTACH);
			memcpy(shell + 19, &reason, sizeof(void*));

			void* entry_point = reinterpret_cast<void*>(reinterpret_cast<uint64_t>(image) + (reinterpret_cast<char*>(GetProcAddress(module, "DllMain")) - reinterpret_cast<char*>(module)));
			memcpy(shell + 29, &entry_point, sizeof(void*));

			CONTEXT ctx = {}; ctx.ContextFlags = CONTEXT_FULL;
			if (SuspendThread(thread) == -1 || !GetThreadContext(thread, &ctx)) {
				VirtualFreeEx(process, image, NULL, MEM_RELEASE); VirtualFreeEx(process, loader, NULL, MEM_RELEASE);
				CloseHandle(process); CloseHandle(thread);
				return -6;
			}

			printf("got ctx & suspended thread | rip: %p\n", ctx.Rip);

			memcpy(shell + 41, &ctx.Rip, sizeof(void*));
			if (!WriteProcessMemory(process, loader, shell, sizeof(thread_hijack_shell), NULL)) {
				VirtualFreeEx(process, image, NULL, MEM_RELEASE); VirtualFreeEx(process, loader, NULL, MEM_RELEASE);
				CloseHandle(process); CloseHandle(thread);
				return -7;
			}

			printf("wrote shell: %p\n", loader);
			system("pause");

			ctx.Rip = reinterpret_cast<uint64_t>(loader);
			if (!SetThreadContext(thread, &ctx) || ResumeThread(thread) == -1) {
				VirtualFreeEx(process, image, NULL, MEM_RELEASE); VirtualFreeEx(process, loader, NULL, MEM_RELEASE);
				CloseHandle(process); CloseHandle(thread);
				return -8;
			}

			printf("set thread context & resume'd thread\n");

			return 1;
		}

		int inject(DWORD process_id, DWORD thread_id, std::string dll_path) {
			return inject(process_id, thread_id, dll_path.c_str());
		}
	}
};