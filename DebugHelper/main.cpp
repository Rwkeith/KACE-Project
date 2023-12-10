#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <cstdint>
#include <windows.h>
#include <tlhelp32.h>
#include <PTEdit/ptedit_header.h>
#include <PTEdit/PTEditorLoader.h>

#define LOG_FILE_REL_PATH "../../KACE/Log.txt"
#define DEBUG_LOG_FILE_REL_PATH "../KACE/Log.txt"
#define LOG_FILE_PATH_USING_EXTENSION "KACE/Log.txt"

void CleanPageTable(UINT64 addr, UINT64 size, int pid)
{
	std::cout << "Cleaning data from PTE's starting at " << (void*)addr << " for length " << size << std::endl;
	ptedit_entry_t vm = {};
	int page_size = 0x1000;
	for (int i = 0; i < size; i += page_size)
	{
		vm = ptedit_resolve((void*)((uint64_t)addr + i), pid);
		// large page
		if (vm.pmd & (1 << PTEDIT_PAGE_BIT_PSE))
		{
			page_size = 0x200000;
			auto vm_pd = (uint64_t*)&vm.pd;
			*vm_pd = 0;
			ptedit_update((void*)((uint64_t)addr + i), pid, &vm);
		}
		else
		{
			page_size = 0x1000;
			printf("Address: %p  vm.pte: %p\n", addr + i, (void*)vm.pte);
			auto pte = (uint64_t*)&vm.pte;
			*pte = 0;
			ptedit_update((void*)((uint64_t)addr + i), pid, &vm);
		}
	}
}

DWORD GetProcessIdByName(const std::wstring& processName)
{
	DWORD  pid = 0;	 // Default to 0, indicating no process found
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 processEntry = {};
		processEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapshot, &processEntry))
		{
			do
			{
				if (std::wstring(processEntry.szExeFile) == processName)
				{
					pid = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapshot, &processEntry));
		}

		CloseHandle(snapshot);
	}

	return pid;
}

// Cleans the page table so we don't BSOD when the Kace process tears down.
int main(int argc, char** argv)
{
	// Get PID of Kace
	std::wstring processName = L"KACE.exe";
	DWORD		 pid = GetProcessIdByName(processName);
	if (pid != 0)
	{
		std::wcout << L"Process ID of " << processName << L": " << pid << std::endl;
	}
	else
	{
		std::wcout << L"Process " << processName << L" not found." << std::endl;
		std::cin.get();
		return 1;
	}

	if (ptedit_init())
	{
		printf("[ERROR] Failed to open PTEdit device, make sure you are running as administrator!\n");
		std::cin.get();
		return 1;
	}

	printf("[INFO] Opened PTEdit device!\n");
	std::string relativePath = LOG_FILE_PATH_USING_EXTENSION;	// LOG_FILE_REL_PATH;

	TCHAR buffer[MAX_PATH];
	DWORD dwRet;

	dwRet = GetCurrentDirectory(MAX_PATH, buffer);
	if (dwRet == 0)
	{
		std::cerr << "GetCurrentDirectory failed. Error: " << GetLastError() << std::endl;
	}
	else
	{
		std::wcout << L"Current directory: " << buffer << std::endl;
	}

	std::ifstream file(relativePath);
	if (!file)
	{
		std::cerr << "Unable to open file: " << relativePath << std::endl;
		std::cin.get();
		return 1;
	}

	std::regex pattern(R"(.+ at (0x[0-9A-Fa-f]{1,16}),(0x[0-9A-Fa-f]{1,16}),(LARGE|regular))");

	std::cout << "Looking for matches..." << std::endl;
    std::string line;
	while (std::getline(file, line))
	{
		std::smatch matches;
		if (std::regex_search(line, matches, pattern))
		{

			// matches[1] contains the first hex value
			// matches[2] contains the second hex value
			// matches[3] contains the string "LARGE" or "REGULAR"
			//
			// Convert matched hex strings to unsigned long long
			unsigned long long addr = std::stoull(matches[1].str(), nullptr, 16);
			unsigned long long size = std::stoull(matches[2].str(), nullptr, 16);

			// Cast to void*
			void* ptr = reinterpret_cast<void*>(addr);

			std::cout << "Found match: " << matches[1] << ", " << matches[2] << ", " << matches[3] << std::endl;

			if (matches[3].str() == "LARGE")
			{
				CleanPageTable(addr, size, pid);
			}
			else if (matches[3].str() == "regular")
			{
				CleanPageTable(addr, size, pid);
			}
			else
			{
				std::cout << "[ERROR] unknown Page type: " << matches[3] << std::endl;
			}
		}
	}
	file.close();

	ptedit_cleanup();
	std::cout << "Done." << std::endl;
	std::cout << "Press enter to exit." << std::endl;
	std::cin.get();
	return 0;
}