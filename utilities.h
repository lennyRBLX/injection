#pragma once

#include <string>
#include <vector>
#include <iostream>
#include <Windows.h>

#include "json.h"
#include "ntos.h"

namespace utils {
	std::string to_ascii(const wchar_t* string);

	std::wstring to_wide(const char* string);

	std::string to_hex(int number, size_t length = sizeof(int));

	std::string to_upper(std::string string);

	std::string to_lower(std::string string);

	float random(float minimum = 0, float maximum = 1, bool floor = false);

	int to_number(std::string string = "", bool is_hex = false);

	std::vector<std::string> split(std::string string, const char delimeter);

	std::string execute_silent_command(const char* cmd);

	std::string format_cookies(nlohmann::json object);

	int pattern_scan(const unsigned char* pattern, unsigned char wildcard, size_t len, const void* base, size_t size, void** ppFound, int iterations);

	SYSTEM_INFO get_sys_info();
}