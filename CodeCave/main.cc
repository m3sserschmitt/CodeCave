/*
 * main.cc
 *
 *  Created on: May 13, 2018
 *      Author: rujas
 *
 *      Code cave injection using CreateRemoteThread
 */

#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <iostream>

using namespace std;

BOOLEAN __stdcall CodeCave_1(HANDLE); //CreateRemoteThread technique;
//BOOLEAN __stdcall CodeCave_2(LPCSTR); //SetWindowsHook technique;
DWORD __stdcall GetProcessIdByName(LPCSTR);

INT APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrefInstance, LPSTR CmdLine, INT ShowConsole)
{
	// get process id;
	DWORD Id = GetProcessIdByName("explorer.exe");
	if(!Id)
	{
		printf("process not found\n");
		ExitProcess(EXIT_FAILURE);
	}

	printf("target process id: %lli\n", (long long int)Id);
	//try to open process
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Id);
	if(!hProc)
	{
		printf("process not opened\n");
		ExitProcess(EXIT_FAILURE);
	}

	// inject code
	BOOLEAN hResult = CodeCave_1(hProc);
	if(hResult)
		printf("Success!\n");
	else
		printf("Failure!\n");

	return EXIT_SUCCESS;
}

typedef struct _MAP
{
	typedef ULONG_PTR (WINAPI *__GetProcAddress)(_In_ HINSTANCE, _In_ LPCSTR);
	typedef HINSTANCE (WINAPI *__LoadLibraryA)(_In_ LPCSTR);
	typedef INT (WINAPI *__MessageBoxA)(_In_opt_ HWND, _In_opt_ LPCSTR, _In_opt_ LPCSTR, _In_ UINT);

	// this 2 API functions will be needed to show a message box from remote process
	__GetProcAddress _GetProcAddress;
	__LoadLibraryA _LoadLibraryA;

	CHAR Lib[32];
	CHAR Proc[32];

	// text to be shown from remote process
	CHAR Text[32];
	CHAR Caption[32];

} MAP;

// this function takes process name and return process ID
DWORD __stdcall GetProcessIdByName(LPCSTR szProcName)
{
	DWORD Id = 0;

	HANDLE Snapshot = CreateToolhelp32Snapshot(0x0002, 0);
	PROCESSENTRY32 pe32 = { 0 };

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Snapshot) return Id;

	if(Process32First(Snapshot, &pe32))
		do
		{

			if(!strcmp(pe32.szExeFile, szProcName))
			{
				Id = pe32.th32ProcessID;
				break;
			}

		}while(Process32Next(Snapshot, &pe32));

	CloseHandle(Snapshot);

	return Id;
}

// this function takes a process name as argument and return
// all threads of given process
vector<DWORD> __stdcall GetProcessThreadsByName(LPCSTR szProcName)
{
	vector <DWORD> Threads;

	DWORD Id = GetProcessIdByName(szProcName);
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, Id);
	THREADENTRY32 te32 = { 0 };

	if(!Snapshot) return Threads;
	te32.dwSize = sizeof(THREADENTRY32);

	if(Thread32First(Snapshot, &te32))
		do
		{
			Threads.push_back(te32.th32ThreadID);
		}while(Thread32Next(Snapshot, &te32));

	CloseHandle(Snapshot);

	return Threads;
}

// this code will be injected into remote process
static void __stdcall Shellcode(MAP *Arg)
{
	if(!Arg) return;

	// get addresses of API functions
	MAP::__GetProcAddress _GetProcAddress = Arg->_GetProcAddress;
	MAP::__LoadLibraryA _LoadLibraryA = Arg->_LoadLibraryA;

	// try to load the library
	HINSTANCE User32 = _LoadLibraryA(Arg->Lib);
	if(!User32) return;

	// create a mesage box
	MAP::__MessageBoxA _MessageBoxA = reinterpret_cast<MAP::__MessageBoxA>(_GetProcAddress(User32, Arg->Proc));

	// display the message box;
	_MessageBoxA(nullptr, Arg->Text, Arg->Caption, 0x00000040l);

	return;
}
static void __stdcall Shellcode_end()
{
	/* do nothing */
}
/*
static void __stdcall _Shellcode()
{

}
static void __stdcall _Shellcode_end()
{

}
*/
BOOLEAN __stdcall CodeCave_1(HANDLE hProcess)
{
	//check if process was opened successfully
	if(!hProcess) return FALSE;

	//address for code injection;
	LPVOID pTargetBase = nullptr;

	//address for Shellcode argument;
	LPVOID pArgument = nullptr;

	//size of code;
	DWORD_PTR ShellcodeSize = (DWORD_PTR)Shellcode_end - (DWORD_PTR)Shellcode;

	//check size of code;
	if(ShellcodeSize <=0) return FALSE;
	printf("Shellcode size: %lli\n", (long long int)ShellcodeSize);

	//try to allocate memory for code injection;
	if(!(pTargetBase = VirtualAllocEx(hProcess, nullptr, ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		return FALSE;
	printf("pTargetBase: 0x%p\n", pTargetBase);

	//try to allocate memory for Shellcode argument;
	if(!(pArgument = VirtualAllocEx(hProcess, nullptr, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
		return FALSE;
	printf("pArgument: 0x%p\n", pArgument);

	//writing code into target process...
	if(!WriteProcessMemory(hProcess, pTargetBase, reinterpret_cast<LPVOID>(Shellcode), ShellcodeSize, nullptr))
		return FALSE;
	printf("Shellcode injected\n");

	MAP Arg;
	// GetProcAddress is required to get the address of MessageBoxA
	Arg._GetProcAddress = (MAP::__GetProcAddress)GetProcAddress;
	// LoadLibraryA is required to load User32.dll
	Arg._LoadLibraryA = LoadLibraryA;

	printf("setting up arguments... ");

	// message to be shown from remote process
	strcpy(Arg.Caption, "Code Cave");
	strcpy(Arg.Text, "Hello From Code Cave!");

	// this dll is required in order to print the message into a message box
	strcpy(Arg.Lib, "User32.dll");

	// required to create a message box instance
	strcpy(Arg.Proc, "MessageBoxA");

	printf("DONE\n");

	//writing arguments into target process...
	PBYTE Buffer = new unsigned char[0x2000];\
	if(!Buffer)
		return FALSE;
	memcpy(Buffer, &Arg, 0x2000);

	if(!WriteProcessMemory(hProcess, pArgument, Buffer, 0x2000, nullptr))
		return FALSE;
	printf("Argument passed\n");

	// run code into remote process'
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pTargetBase), pArgument, 0, nullptr);

	if(!hThread)
		return FALSE;
	printf("Thread created\n");

	CloseHandle(hThread);
	return TRUE;
}
/*
BOOLEAN __stdcall CodeCave_2(LPCSTR szProcName)
{
	if(!szProcName)
		return FALSE;

	DWORD Id = GetProcessIdByName(szProcName);
	if(!Id) return FALSE;

	vector<DWORD> Threads = GetProcessThreadsByName(szProcName);
	if(!Threads.size()) return FALSE;

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Id);
	if(!hProc) return FALSE;



	return TRUE;
}
*/




