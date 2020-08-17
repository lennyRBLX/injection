#pragma once

#include "files.h"

#include <Windows.h>
#include <fstream>
#include <filesystem>

namespace files {
	std::string get_directory() {
		char buffer[MAX_PATH];
		GetModuleFileNameA(NULL, buffer, MAX_PATH);

		std::string::size_type position = std::string(buffer).find_last_of("\\/");
		return std::string(buffer).substr(0, position);
	}

	std::string get_tmp_directory() {
		return std::filesystem::temp_directory_path().generic_string();
	}

	std::string read(const char* directory) {
		// get document contents
		std::ifstream file(directory, std::ios::in);
		std::string contents;

		char current_character = file.get();
		while (file.good()) {
			contents += current_character;
			current_character = file.get();
		}

		file.close();

		return contents;
	}

	bool write(const char* directory, const char* contents) {
		std::ofstream file(directory, std::ofstream::out);
		file << contents;
		file.close();

		return true;
	}

	bool append(const char* directory, const char* contents) {
		std::string file_contents = read(directory);
		std::string new_contents(file_contents + (std::string(contents) + "\n").c_str());

		return write(directory, new_contents.c_str());
	}

	bool create_directory(const char* string) {
		return std::filesystem::create_directories(string);
	}

	bool delete_directory(const char* string) {
		return std::filesystem::remove(string);
	}

	std::string load_binary(const char* filepath) {
		std::ifstream ifs(filepath, std::ios::binary | std::ios::ate);
		std::string result;

		if (!ifs)
			return result;

		auto end = ifs.tellg();
		ifs.seekg(0, std::ios::beg);

		auto size = std::size_t(end - ifs.tellg());
		if (size == 0) // avoid undefined behavior 
			return {};

		result.resize(size);
		if (!ifs.read((char*)result.data(), result.size()))
			return result;

		return result;
	}

	bool write_binary(const char* filepath, const char* contents, size_t size) {
		std::ofstream ofs(filepath, std::ios::binary | std::ios::ate);
		if (!ofs || !ofs.write(contents, size))
			return false;

		return true;
	}
};