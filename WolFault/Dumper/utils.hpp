#pragma once

#include <windows.h>
#include <tlhelp32.h>
 // #include <C:\Users\lolo3\source\repos\main\syscall.h> CHANGE THAT SHIT :sob:
#include <ntdef.h>




namespace utilsMaster {
 //	using namespace scemaster;
	scemaster::Sysc Syscs;

	class Utils {
	public:


		class Mem {

			[[noinline]] LPVOID ReadMem(HANDLE hProcess, PVOID baseAddr, SIZE_T size) { /*[[noinline]] is not needed here but it doesn't worth anything to keep it ig */

				LPVOID buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
				if (!buf) return nullptr;

				SIZE_T bytesRead = 0;
				NTSTATUS status = Syscs.NtReadVirtualMemory(hProcess, baseAddr, buf, size, &bytesRead);


				if (!NT_SUCCESS(status)) {
					HeapFree(GetProcessHeap(), 0, buf);
					return nullptr;
				}

				return buf;
			}



			VOID FixSections(LPVOID Buffer) 
			{

				IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)Buffer;
				IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)Buffer + dos->e_lfanew);

				IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt); /* ((PIMAGE_SECTION_HEADER)((ULONG_PTR)(nt)+((LONG)__builtin_offsetof(IMAGE_NT_HEADERS, OptionalHeader))*/


				for (int i = 0; i <= nt->FileHeader.NumberOfSections; i++) {
					memmove((PVOID)((BYTE*)Buffer + (DWORD)nt->OptionalHeader.SizeOfHeaders), (BYTE*)Buffer + sections[i].VirtualAddress, sections[i].SizeOfRawData); /* replaced memcpy to memmove for safety reasons*/

					/* each iteration we align to the entry of the next section by adding size of  headers, then we increment sizeofheaders by size of raw data*/
				//	sections[i].PointerToRawData = nt->OptionalHeader.SizeOfHeaders;
					nt->OptionalHeader.SizeOfHeaders += sections[i].SizeOfRawData;

				}

			}

			VOID FixIAT(LPVOID Buffer) /* we could Fix the IAT entierly but we only want to read the file so we will use the resolved addresses*/
			{

				IMAGE_DOS_HEADER* ds = (IMAGE_DOS_HEADER*)Buffer;
				IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)Buffer + ds->e_lfanew); /* tommorow, need to think if we want IAT or not.*/
				
			}

		};

	};
}
