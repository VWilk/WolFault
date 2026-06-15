#pragma once

#include <windows.h>
#include <tlhelp32.h>

namespace scemaster {

	class sysc {

		[[noinline]] DWORD GetSSN() {
			HANDLE file = CreateFileW(L"C:\\Windows\\System32\\ntdll.dll", FILE_SHARE_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, 0); /* we need to fill the wide string argument to correctly open ntdll*/
			HANDLE MapA = CreateFileMappingA(file, PAGE_EXECUTE_READWRITE, 0, 0, 0);

			LPVOID MapAddr = MapViewOfFile(MapA, NULL, FILE_MAP_ALL_ACCESS, 0, 0); /* [in] dwNumberOfBytesToMap. watchout for this argument i didn't understand it well (last argument)*/

			/* lets start walking file headers*/

			IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)MapAddr; /* dos points to MapAddr value */

			IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)MapAddr + dos->e_lfanew);

			DWORD eatOffset = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			IMAGE_EXPORT_DIRECTORY* EAT_LinearAddr = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)MapAddr + eatOffset);

			DWORD* AddressofFunc = (DWORD*)((BYTE*)MapAddr + EAT_LinearAddr->AddressOfFunctions); /* scoping those variable to get a full linear address to fetch SSN from*/
			WORD* AddressOfNameOrdinal = (WORD*)((BYTE*)MapAddr+ EAT_LinearAddr->AddressOfNameOrdinals); /* casting base + offset to pointers (addresses)*/
			DWORD* AddressOfNames = (DWORD*)((BYTE*)MapAddr + EAT_LinearAddr->AddressOfNames);


			for (DWORD i = 0; EAT_LinearAddr->NumberOfFunctions; i++) {
				char* name = (char*)((BYTE*)MapAddr + AddressOfNames[i]); // base + dereferenced Name address

				if (strcmp(name, "NtReadVirtualMemory") == 0) {
					WORD ordinal = AddressOfNameOrdinal[i];
					DWORD funcN = AddressofFunc[ordinal];
					BYTE* stubptr = ((BYTE*)MapAddr + funcN); /* base + FuncN offset*/
					DWORD ssn = *(DWORD*)(stubptr + 1);  /* stub ptr + 1 to skip the opcode  and we fetch 4 Bytes from the stubptr address to get the SSN*/

					return (DWORD)ssn;

				}

			}
			return NULL;

		} 

		[[noinline]] bool InlineSyscall(DWORD ssn) { /* for tommorow */

		}



	};

}
