#pragma once

#include <windows.h>
#include <tlhelp32.h>
#include <syscall.h>

namespace utilsMaster {

	class Utils {
	public:

		/* Relies on GetSSN and NtReadVirtualMemory to read memory, stores in buffer. */
		[[noinline]] LPVOID ReadMem(HANDLE hProcess, PVOID baseAddr, SIZE_T size) { /*[[noinline]] is not needed here but it doesn't worth anything to keep it ig */
			LPVOID buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
			if (!buf) return nullptr;

			SIZE_T bytesRead = 0;
			NTSTATUS status = NtReadVirtualMemory(hProcess, baseAddr, buf, size, &bytesRead);

			if (!NT_SUCCESS(status)) {
				HeapFree(GetProcessHeap(), 0, buf);
				return nullptr;
			}

			return buf;
		}
	}
}