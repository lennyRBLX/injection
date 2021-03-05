#include "injection.h"

int main() {
	injection::standard::inject(injection::standard::open_process(0x15D4, PROCESS_ALL_ACCESS), L"test.dll");
	injection::hook::inject(0x1024, L"test.dll", "next_hk");
	injection::manual_map::inject(0x15D4, 0x1024, L"test.dll");
	return 0;
}