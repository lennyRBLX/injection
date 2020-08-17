#pragma once

#include <string>

namespace files {
	std::string get_directory();

	std::string get_tmp_directory();

	std::string read(const char* directory);

	bool write(const char* directory, const char* contents);

	bool append(const char* directory, const char* contents);

	bool create_directory(const char* string);

	bool delete_directory(const char* string);

	std::string load_binary(const char* filepath);

	bool write_binary(const char* filepath, const char* contents, size_t size);
}