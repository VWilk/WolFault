#pragma once

#include <windows.h>
#include <tlhelp32.h>

namespace scemaster {

	class sysc {
	public:

		[[noinline]] DWORD GetSSN() {
			HANDLE file = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", FILE_SHARE_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, 0); /* we need to fill the wide string argument to correctly open ntdll*/
			HANDLE MapA = CreateFileMappingA(file, NULL, PAGE_EXECUTE_READWRITE, 0, 0, NULL);

			LPVOID MapAddr = MapViewOfFile(MapA, NULL, FILE_MAP_ALL_ACCESS, 0, 0); /* [in] dwNumberOfBytesToMap. watchout for this argument i didn't understand it well (last argument)*/

			/* lets start walking file headers*/

			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)MapAddr; /* dos points to MapAddr value */

			IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)MapAddr + dos->e_lfanew);

			DWORD eatOffset = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			IMAGE_EXPORT_DIRECTORY* EAT_LinearAddr = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)MapAddr + eatOffset);

			DWORD* AddressofFunc = (DWORD*)((BYTE*)MapAddr + EAT_LinearAddr->AddressOfFunctions); /* scoping those variable to get a full linear address to fetch SSN from*/
			WORD* AddressOfNameOrdinal = (WORD*)((BYTE*)MapAddr + EAT_LinearAddr->AddressOfNameOrdinals); /* casting base + offset to pointers (addresses)*/
			DWORD* AddressOfNames = (DWORD*)((BYTE*)MapAddr + EAT_LinearAddr->AddressOfNames);


			for (DWORD i = 0; i <= EAT_LinearAddr->NumberOfFunctions; i++) {
				char* name = (char*)((BYTE*)MapAddr + AddressOfNames[i]); // base + dereferenced Name address

				if (strcmp(name, "NtReadVirtualMemory") == 0) {
					WORD ordinal = AddressOfNameOrdinal[i];
					DWORD funcN = AddressofFunc[ordinal];
					BYTE* stubptr = ((BYTE*)MapAddr + funcN); /* base + FuncN offset*/
					DWORD ssn = *(DWORD*)(stubptr + 4);  /* stub ptr + 4 to skip the opcode and we fetch 4 Bytes from the stubptr address to get the SSN*/

					return (DWORD)ssn;

				}

			}
			return NULL;

		}

		[[noinline]] NTSTATUS NtReadVirtualMemory(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress, _Out_ PVOID Buffer, _In_ SIZE_T NumberOfBytesToRead, _Out_opt_ PSIZE_T NumberOfBytesRead) {
			static DWORD ssn = GetSSN(); /* static keyword to only call it one time per NtReadVirtualMemory call, after value is cached, avoiding to have to copy the file AGAIN AND AGAIN */
			NTSTATUS syscallStatus;

			__asm {
				mov r10, rcx /* save ret IP(rcx) into r10 (cpu will "flush" rcx)*/
				mov eax, ssn /* we move our ssn into eax (syscall will fetch from here)*/
				syscall /* syscall with our SSN */
				mov syscallStatus, eax /* get what syscall returned from eax into syscallStatus */
			}

			return syscallStatus;
		}
		

		/* Relies on GetSSN and NtReadVirtualMemory to read memory, stores in buffer. */
		[[noinline]] LPVOID ReadMem(HANDLE hProcess, PVOID baseAddr, SIZE_T size) {
			LPVOID buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
			if (!buf) return nullptr;

			SIZE_T bytesRead = 0;
			NTSTATUS status = NtReadVirtualMemory(hProcess, baseAddr, buf, size, &bytesRead);

			if (!NT_SUCCESS(status) {
				HeapFree(GetProcessHeap(), 0, buf);
				return nullptr;
			}

			return buf;
		}

	};

}
