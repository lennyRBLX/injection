# injection
A resource with shellcode for x64 thread hijacking, as well as easy to use manual mapping, hook, and standard injection techniques. The shellcode has notes to what instructions are used, making x86 translation incredibly easy.

techniques:
- standard (internal LoadLibraryA call)
- hook (SetWindowsHookEx process hook)
- manual map (VirtualAllocEx & manually resolved PE elements, with full thread hijacking shell & code)
