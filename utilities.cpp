#pragma once

#include "utilities.h"

#include <sstream>
#include <ctype.h>
#include <random>
#include <cstdlib>
#include <iomanip>

std::string utils::to_ascii(const wchar_t* string) {
	size_t string_length = wcslen(string);
	std::string ascii_string(string_length, L'#');
	wcstombs(&ascii_string[0], string, string_length);

	return ascii_string;
}

std::wstring utils::to_wide(const char* string) {
	size_t string_length = strlen(string);
	std::wstring wide_string(string_length, L'#');
	mbstowcs(&wide_string[0], string, string_length);

	return wide_string;
}

std::string utils::to_hex(int i, size_t length) {
	std::stringstream stream;
	stream << std::setfill('0') << std::setw(length) << std::hex << i;
	return stream.str();
}

std::string utils::to_upper(std::string string)
{
	for (unsigned int i = 0; i < string.length(); i++)
	{
		string[i] = toupper(string[i]);
	}

	return string;
}

std::string utils::to_lower(std::string string)
{
	for (unsigned int i = 0; i < string.length(); i++)
	{
		string[i] = tolower(string[i]);
	}

	return string;
}

float utils::random(float minimum, float maximum, bool floor) {
	std::random_device device;
	std::mt19937 random_algorithm(device());
	std::uniform_real_distribution<> random_distance(minimum, maximum);

	float result = random_distance(random_algorithm);

	if (floor)
		result = floorf(result + 1);
	else
		return result;

	if (result > maximum)
		result = maximum;

	return result;
}

int utils::to_number(std::string string, bool is_hex) {
	std::stringstream stream;
	int number;

	if (is_hex)
		stream << std::hex << string;
	else
		stream << string;

	stream >> number;
	return number;
}

std::vector<std::string> utils::split(std::string string, const char delimeter)
{
	std::stringstream stream(string);
	std::string current_string;
	std::vector<std::string> split_strings;

	while (std::getline(stream, current_string, delimeter))
	{
		split_strings.push_back(current_string);
	}

	return split_strings;
}

std::string utils::execute_silent_command(const char* cmd) {
	std::string out;

	FILE* pipe = _popen(cmd, "r");
	if (pipe) {
		char buff[128] = { 0 };
		while (!feof(pipe)) {
			if (fgets(buff, 128, pipe)) {
				out.append(buff);
			}
		}
		_pclose(pipe);
	}

	return out;
}

std::string utils::format_cookies(nlohmann::json object) {
	std::string result = "Cookie: ";
	
	for (nlohmann::json::iterator it = object.begin(); it != object.end(); ++it) {
		std::string key = it.key(), value = it.value();

		result += key + std::string("=") + value + std::string("; ");
	}

	return result;
}

// bbsearchpattern
int utils::pattern_scan(const unsigned char* pattern, unsigned char wildcard, size_t len, const void* base, size_t size, void** ppFound, int iterations) {
	assert(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return 0;

	for (size_t i = 0; i < size - len; i++)
	{
		int found = 1;
		for (size_t j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((const unsigned char*)base)[i + j])
			{
				found = 0;
				break;
			}
		}

		if (found == 1 && iterations == 1)
		{
			*ppFound = (unsigned char*)base + i;
			return 1;
		}
		else if (found == 1) {
			--iterations;
		}
	}

	return 0;
}

SYSTEM_INFO utils::get_sys_info() {
	SYSTEM_INFO result = {};
	GetSystemInfo(&result);
	return result;
}