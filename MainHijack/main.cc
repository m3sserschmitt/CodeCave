/*
 * main.cc
 *
 *  Created on: May 22, 2018
 *      Author: rujas
 *
 *      change entry point of process dynamically
 * 		a new copy of this process is created in suspended state, and the code of main 
 * 		is overwritten with shellcode function;
 * 		when process is resumed, shellcode function run
 */

#include <windows.h>
#include <iostream>

using namespace std;
/*
typedef ULONG_PTR (WINAPI *__GetProcAddress)(HINSTANCE, LPCSTR);
typedef HINSTANCE (WINAPI *__LoadLibraryA)(LPCSTR);

typedef struct _MAP{
	__GetProcAddress _GetProcAddress;
	__LoadLibraryA _LoadLibraryA;

	CHAR Lib[32];
	CHAR Proc[32];
} MAP;
*/
static VOID __stdcall CodeCave()
{
	/*     do something     */
	// this code will be run when the copy process is resumed
}
static VOID CodeCave_end()
{
	return; // used to calculate the size of codecave function
}

INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR CmdLine, INT ShowConsole)
{
	DWORD_PTR CodeCaveSize;
	CONTEXT Context;
	PROCESS_INFORMATION pi;
	STARTUPINFO si;
	DWORD ImageBase;
	DWORD AddressOfEntryPoint;

	LPSTR localSzProc = new CHAR[260];
	HANDLE localProc = nullptr;

	IMAGE_DOS_HEADER *DOSHeader = nullptr;
	IMAGE_NT_HEADERS *NtHeaders = nullptr;
	IMAGE_OPTIONAL_HEADER *OptHeader = nullptr;

	// get name of executable
	if(!GetModuleFileNameA(nullptr, localSzProc, 260))
	{
		cout << "GetModuleFileNameA error" << endl;
		return EXIT_FAILURE;
	}

	ZeroMemory(&Context, sizeof(CONTEXT));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&si, sizeof(STARTUPINFO));

	si.cb = sizeof(STARTUPINFO);

	// create a copy process into suspended state
	if(CreateProcessA(nullptr, localSzProc, nullptr, nullptr, FALSE, CREATE_SUSPENDED | CREATE_NEW_CONSOLE, nullptr, nullptr, &si, &pi))
	{
		Context.ContextFlags = CONTEXT_FULL;
		// get main thread context
		if(!GetThreadContext(pi.hThread, &Context))
		{
			cout << "GetThreadContext error" << endl;
			return EXIT_FAILURE;
		}

		// get handle to this process
		if(!(localProc = GetModuleHandleA(nullptr)))
		{
			cout << "GetModuleHandle error" << endl;
			return EXIT_FAILURE;
		}

		// get DOS & NT headers of local process, and check signatures
		DOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(localProc);
		if(DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			cout << "Invalid DOS Signature" << endl;
			return EXIT_FAILURE;
		}

		NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(reinterpret_cast<PBYTE>(localProc) + DOSHeader->e_lfanew);
		if(NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			cout << "Invalid NtHeaders Signature" << endl;
			return EXIT_FAILURE;
		}

		OptHeader = &NtHeaders->OptionalHeader;

		// image base of local process
		ImageBase = OptHeader->ImageBase;

		// entry point of local process
		AddressOfEntryPoint = OptHeader->AddressOfEntryPoint;

		// calculate codecave size
		CodeCaveSize = (DWORD_PTR)CodeCave_end - (DWORD_PTR)CodeCave;

		// overwrite entry point into copy process
		if(!WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(ImageBase + AddressOfEntryPoint), reinterpret_cast<LPVOID>(CodeCave), CodeCaveSize, nullptr))
		{
			cout << "WriteProcessMemory error (1)" << endl;
			return EXIT_FAILURE;
		}

		// setup registers
		if(!WriteProcessMemory(pi.hProcess, reinterpret_cast<LPVOID>(Context.Ebx + 8), &ImageBase, 4, nullptr))
		{
			cout << "WriteProcessMemory error (2)" << endl;
			return EXIT_FAILURE;
		}

		// put new entry point address into EAX register
		Context.Eax = ImageBase + AddressOfEntryPoint;

		// set new thread context into copy process
		SetThreadContext(pi.hThread, &Context);

		// resume main thread;
		ResumeThread(pi.hThread);
	}else
	{
		cout << "CreateProcessA error" << endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
