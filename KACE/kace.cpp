#include <Logger/Logger.h>
#include <MemoryTracker/memorytracker.h>
#include <PEMapper/pefile.h>

#include <intrin.h>

#include <SymParser/symparser.hpp>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <mutex>

#include "emulation.h"
#include "environment.h"
#include "ntoskrnl_provider.h"
#include "paging_emulation.h"
#include "provider.h"
#include "driver_buddy.h"

// This will monitor every read/write with a page_guard - SLOW - Better debugging
// #define MONITOR_ACCESS

using proxyCall = uint64_t(__fastcall*)(...);
proxyCall DriverEntry = nullptr;

#define READ_VIOLATION 0
#define WRITE_VIOLATION 1
#define EXECUTE_VIOLATION 8

uint64_t passthrough(...)
{
	return 0;
}

// POC STAGE, NEED TO MAKE THIS DYNAMIC - Most performance issue come from this, also for some reason i only got this to
// work in Visual studio, not outside of it.

uintptr_t lastPG = 0;

extern "C" void u_iret();

LONG ExceptionHandler(EXCEPTION_POINTERS* e)
{
	std::string mod_name = "ntoskrnl.exe";
	uintptr_t ep = (uintptr_t)e->ExceptionRecord->ExceptionAddress;

	if (e->ExceptionRecord->ExceptionCode == EXCEPTION_FLT_DIVIDE_BY_ZERO)
	{
		return EXCEPTION_CONTINUE_SEARCH;
	}
	else if (e->ExceptionRecord->ExceptionCode == EXCEPTION_PRIV_INSTRUCTION)
	{
		bool wasEmulated = false;

		wasEmulated = VCPU::PrivilegedInstruction::Parse(e->ContextRecord);

		if (wasEmulated)
		{
			return EXCEPTION_CONTINUE_EXECUTION;
		}
		else
		{
			Logger::Log("Failed to emulate instruction\n");

			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

	else if (e->ExceptionRecord->ExceptionCode = EXCEPTION_ACCESS_VIOLATION)
	{
		auto bufferopcode = (uint8_t*)e->ContextRecord->Rip;
		auto addr_access = e->ExceptionRecord->ExceptionInformation[1];
		bool wasEmulated = false;

		switch (e->ExceptionRecord->ExceptionInformation[0])
		{
			case WRITE_VIOLATION:

				wasEmulated = VCPU::MemoryWrite::Parse(addr_access, e->ContextRecord);

				if (wasEmulated)
				{
					// exceptionMutex.unlock();
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				DebugBreak();
				exit(0);
				break;

			case READ_VIOLATION:
				Environment::CheckCurrentContigRead(mod_name, addr_access);

				wasEmulated = VCPU::MemoryRead::Parse(addr_access, e->ContextRecord);

				if (wasEmulated)
				{
					return EXCEPTION_CONTINUE_EXECUTION;
				}

				if (e->ExceptionRecord->ExceptionInformation[1] == e->ExceptionRecord->ExceptionInformation[0] &&
					e->ExceptionRecord->ExceptionInformation[0] == 0)
				{
					return EXCEPTION_CONTINUE_SEARCH;
				}

				if (bufferopcode[0] == 0xCD && bufferopcode[1] == 0x20)
				{
					Logger::Log("\033[38;5;46m[Info]\033[0m Checking for Patchguard (int 20)\n");
					e->ContextRecord->Rip += 2;
					return EXCEPTION_CONTINUE_EXECUTION;
				}
				else if (bufferopcode[0] == 0x48 && bufferopcode[1] == 0xCF)
				{
					e->ContextRecord->Rip = (uintptr_t)u_iret;
					Logger::Log("\033[38;5;46m[Info]\033[0m IRET Timing Emulation\n");
					return EXCEPTION_CONTINUE_EXECUTION;
				}

				break;
			case EXECUTE_VIOLATION:

				auto rip = Provider::FindFuncImpl(addr_access);

				if (!rip)
					DebugBreak();

				e->ContextRecord->Rip = rip;
				return EXCEPTION_CONTINUE_EXECUTION;
				break;
		}
	}
  
	return EXCEPTION_CONTINUE_SEARCH;
}

const wchar_t* driverName = L"\\Driver\\vgk";
const wchar_t* registryBuffer = L"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\vgk";

DWORD FakeDriverEntry(LPVOID)
{
	Logger::Log("Calling the driver entrypoint\n");

	drvObj.Size = sizeof(drvObj);
	drvObj.DriverName.Buffer = (WCHAR*)driverName;
	drvObj.DriverName.Length = lstrlenW(driverName);
	drvObj.DriverName.MaximumLength = 16;

	RegistryPath.Buffer = (WCHAR*)registryBuffer;
	RegistryPath.Length = lstrlenW(RegistryPath.Buffer) * 2;
	RegistryPath.MaximumLength = lstrlenW(RegistryPath.Buffer) * 2;

	memset(&FakeKernelThread, 0, sizeof(FakeKernelThread));
	memset(&FakeSystemProcess, 0, sizeof(FakeSystemProcess));
	memset(&FakeKPCR, 0, sizeof(FakeKPCR));
	memset(&FakeCPU, 0, sizeof(FakeCPU));

	InitializeListHead(&FakeKernelThread.Tcb.Header.WaitListHead);
	InitializeListHead(&FakeSystemProcess.Pcb.Header.WaitListHead);

	__writegsqword(0x188, (DWORD64)&FakeKernelThread);	// Fake KTHREAD
	__writegsqword(0x18, (DWORD64)&FakeKPCR);			// Fake _KPCR
	__writegsqword(0x20, (DWORD64)&FakeCPU);			// Fake _KPRCB

	FakeKernelThread.Tcb.Process = (_KPROCESS*)&FakeSystemProcess;			 // PsGetThreadProcess
	FakeKernelThread.Tcb.ApcState.Process = (_KPROCESS*)&FakeSystemProcess;	 // PsGetCurrentProcess

	FakeKernelThread.Cid.UniqueProcess = (void*)4;	 // PsGetThreadProcessId
	FakeKernelThread.Cid.UniqueThread = (void*)0x8;	 // PsGetThreadId

	FakeKernelThread.Tcb.PreviousMode = 0;	// PsGetThreadPreviousMode
	FakeKernelThread.Tcb.State = 1;			//
	FakeKernelThread.Tcb.InitialStack = (void*)0x1000;
	FakeKernelThread.Tcb.StackBase = (void*)0x1500;
	FakeKernelThread.Tcb.StackLimit = (void*)0x2000;
	FakeKernelThread.Tcb.ThreadLock = 11;
	FakeKernelThread.Tcb.LockEntries = (_KLOCK_ENTRY*)22;
	FakeKernelThread.Tcb.MiscFlags |= 0x400;  // Make it a system thread

	FakeSystemProcess.UniqueProcessId = (void*)4;
	FakeSystemProcess.Protection.Level = 7;
	FakeSystemProcess.WoW64Process = nullptr;
	FakeSystemProcess.CreateTime.QuadPart = GetTickCount64();
	strcpy((char*)FakeSystemProcess.ImageFileName, "System");	//    +0x5a8 ImageFileName    : [15]  "System"

	FakeCPU.CurrentThread = (_KTHREAD*)&FakeKernelThread;
	FakeCPU.IdleThread = (_KTHREAD*)&FakeKernelThread;
	FakeCPU.CoresPerPhysicalProcessor = 2;
	FakeCPU.LogicalProcessorsPerCore = 2;
	FakeCPU.MajorVersion = 10;
	FakeCPU.MinorVersion = 0;
	FakeCPU.RspBase = __readgsqword(0x8);

	FakeKPCR.CurrentPrcb = &FakeCPU;
	FakeKPCR.NtTib.StackBase = (PVOID)__readgsqword(0x8);
	FakeKPCR.NtTib.StackLimit = (PVOID)__readgsqword(0x10);
	FakeKPCR.MajorVersion = 10;
	FakeKPCR.MinorVersion = 0;
	FakeKPCR.Used_Self = (void*)__readgsqword(0x30);  // Usermode TEB is actually in kernel gs:0x30
	FakeKPCR.Self = &FakeKPCR;

	__writeeflags(0x10286);

	LDR_DATA_TABLE_ENTRY* ldrentry =
		(LDR_DATA_TABLE_ENTRY*)MemoryTracker::AllocateVariable(sizeof(LDR_DATA_TABLE_ENTRY));
	drvObj.DriverSection = ldrentry;

	ldrentry->FullDllName.Buffer = (wchar_t*)L"c:\\Program Files\\Riot Vanguard\\vgk.sys";
	ldrentry->FullDllName.Length = lstrlenW(ldrentry->FullDllName.Buffer) * 2;
	ldrentry->FullDllName.MaximumLength = ldrentry->FullDllName.Length;

	InsertTailList(&Environment::PsLoadedModuleList->InLoadOrderLinks, &ldrentry->InLoadOrderLinks);

	MemoryTracker::TrackVariable(
		(uintptr_t)drvObj.DriverSection, sizeof(UINT64), "MainModule.DriverObject.DriverSectionLdrEntry");
	MemoryTracker::TrackVariable((uintptr_t)&drvObj, sizeof(drvObj), (char*)"MainModule.DriverObject");
	MemoryTracker::TrackVariable((uintptr_t)&FakeKPCR, sizeof(FakeKPCR), (char*)"KPCR");
	MemoryTracker::TrackVariable((uintptr_t)&FakeCPU, sizeof(FakeCPU), (char*)"CPU");

	// MemoryTracker::TrackVariable((uintptr_t)&RegistryPath, sizeof(RegistryPath), (char*)"MainModule.RegistryPath");

	MemoryTracker::TrackVariable((uintptr_t)&FakeSystemProcess, sizeof(FakeSystemProcess), (char*)"PID4.EPROCESS");
	MemoryTracker::TrackVariable((uintptr_t)&FakeKernelThread, sizeof(FakeKernelThread), (char*)"PID4.ETHREAD");

	// there's a long memory scan in ntoskrnl that BE does which takes a long time to emulate.
	std::string mod_name = "ntoskrnl.exe";
	Environment::SetMaxContigRead(mod_name, 50);

	auto result = DriverEntry(&drvObj, &RegistryPath);
	Logger::Log("Main Thread Done! Return = %llx\n", result);
	system("pause");
	return 0;
}

__forceinline void init_dirs()
{
	std::filesystem::path p = "c:\\";
	for (auto& key : {"\\kace", "\\ca", "\\ca", "\\windows"})
	{
		p += key;
		if (!std::filesystem::exists(p))
			std::filesystem::create_directory(p);
	}
}

BOOL EnableLockMemoryPrivilege()
{
	HANDLE			 hToken;
	LUID			 luid;
	TOKEN_PRIVILEGES tkp;

	// Open the process token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("OpenProcessToken failed with %u\n", GetLastError());
		return FALSE;
	}

	// Get the LUID for the Lock Pages in Memory privilege
	if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &luid))
	{
		printf("LookupPrivilegeValue failed with %u\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the Lock Pages in Memory privilege in the process token
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("AdjustTokenPrivileges failed with %u\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		printf("The Lock Pages in Memory privilege is not assigned to this process.\n");
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}

int main(int argc, char* argv[])
{
	Logger::InitializeLogFile("Log.txt");
	Logger::Log("Press enter after debugger is attached...");
	std::cin.get();

	_unlink("C:\\Windows\\vgkbootstatus.dat");
	AddVectoredExceptionHandler(true, ExceptionHandler);

	init_dirs();

	symparser::download_symbols("c:\\Windows\\System32\\ntdll.dll");

	MemoryTracker::Initiate();

	// needed to alloc large pages in usermode
	if (EnableLockMemoryPrivilege())
	{
		Logger::Log("Successfully enabled Lock Pages in Memory privilege.\n");
		// Now you can allocate large pages using VirtualAlloc
	}
	else
	{
		Logger::Log("Failed to enable Lock Pages in Memory privilege.\n");
		return 0;
	}

	auto		load_only_emu_mods = FALSE;
	auto		use_buddy = FALSE;
	std::string load_flag;
	std::string DriverPath;
	
	if (argc > 1)
		DriverPath = argv[1];
	else
		DriverPath = "C:\\emu\\easyanticheat_2.sys";

	if (argc > 2)
	{
		load_flag = argv[2];
		if (load_flag == "load_only_emu_mods")
		{
			Logger::Log("load_only_emu_mods flag specified, loading only modules from c:\\emu\\driver\\ \n");
			load_only_emu_mods = TRUE;
		}
	}

	PRTL_PROCESS_MODULE_INFORMATION_EX mod_info;

	if (argc > 3)
	{
		
		//  Working on PTE Manipulation for now...
		load_flag = argv[3];
		if (load_flag == "use_buddy")
		{
			Logger::Log("use_buddy flag specified, loading DriverBuddy...\n");
			use_buddy = TRUE;
			if (!DriverBuddy::Init(DriverPath))
			{
				return 0;
			}
		}
		

		std::string mod_name = "BEDaisy.sys";

		mod_info = Environment::GetSystemModuleInfo(mod_name);
		
		// set module address range from kernel to user		
	}

	/*
	Environment::InitializeSystemModules(load_only_emu_mods);
	
	
	ntoskrnl_provider::Initialize();

	VCPU::Initialize();
	PagingEmulation::SetupCR3();
	*/
	DWORD dwMode;

	auto hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	GetConsoleMode(hOut, &dwMode);
	dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);

	Logger::Log("Loading modules\n");

	// map usermode copies of ntoskrnl and fltmgr.sys
	std::string ntosk = "ntoskrnl.exe";
	auto		ntos_mod = Environment::GetSystemModuleInfo(ntosk);
	bool		is_kernel = true;
	bool		make_user_mode = false;
	bool		mirror = true;
	auto ntos = PEFile::Open((void*)ntos_mod->BaseInfo.ImageBase, ntosk,
				 ntos_mod->BaseInfo.ImageSize,
				 is_kernel,
				 make_user_mode,
				 mirror);

	std::string fltr = "fltrmgr.sys";
	auto		fltr_mod = Environment::GetSystemModuleInfo(fltr);
	auto		fltmgr = PEFile::Open((void*)fltr_mod->BaseInfo.ImageBase,
								  "ntoskrnl.exe",
								  fltr_mod->BaseInfo.ImageSize,
								  is_kernel,
								  make_user_mode,
								  mirror);

	make_user_mode = true;
	mirror = false;

	// set the UserSupervisor bit of the pages of the driver being emulated to usermode.
	auto MainModule = PEFile::Open((void*)mod_info->BaseInfo.ImageBase,
								   "BEDaisy",
								   mod_info->BaseInfo.ImageSize,
								   is_kernel,
								   make_user_mode,
								   mirror);
	
	// prove we can access originally allocated kernel memory in usermode!
	char test = *(char*)mod_info->BaseInfo.ImageBase;
	// MainModule->ResolveImport();

	// If it's in kernel say it's executable
	// also if it's the emulated module say it's executable
	ntos->SetExecutable(true);
	fltmgr->SetExecutable(true);
	MainModule->SetExecutable(true);

	// this will create the shadow buffer's and mark the memory of all PEFile objects created as PAGE_NO_ACCESS or PAGE_READ_WRITE
	// should we create a new class based off of PEFile called KernelRegion?
	// it needs to create userland mirrors of things
	// it needs to provide service for the exception handler and work with resolving symbols when available
	// maybe we can also determine our own symbols for things when they aren't in a PDB (kernel objects)
	
	PEFile::SetPermission();
	
	FakeDrvEntry PatchedDrvEntry = (FakeDrvEntry)(MainModule->GetEP() + (UINT64)mod_info->BaseInfo.ImageBase);

	// works, but need to pass args.
	// executes up to nt!__chkstk()
	PatchedDrvEntry();

	// we need to create the shadowbuffers of everything(asterisk) mapped into kernel
	// we can also do the absolute minimum (ntoskrnl) and create shadow buffers on demand
	// we can VirtualAlloc them in usermode, update the pfn's using PTEdit

	Logger::Log("Huzzah!\n");

	//auto MainModule = PEFile::Open(DriverPath, "MyDriver");
	
	// We don't need to resolve import's anymore..the driver is now loaded legitly(by us)
	//MainModule->ResolveImport();
	
	// Pretty sure we still need this for emulated driver to go to our exception handler.
	// Do we need to PAGE_NO_ACCESS the memory that stores the exception table and emulate that?
	// See the difference between 2 memory dumps before and after this is done
	//MainModule->SetExecutable(true);

	//PEFile::SetPermission();

	for (int i = 0; i < PEFile::LoadedModuleArray.size(); i++)
	{
		if (PEFile::LoadedModuleArray[i]->GetShadowBuffer())
		{
			MemoryTracker::AddMapping(PEFile::LoadedModuleArray[i]->GetMappedImageBase(),
									  PEFile::LoadedModuleArray[i]->GetVirtualSize(),
									  PEFile::LoadedModuleArray[i]->GetShadowBuffer());
		}
	}

	DriverEntry = (proxyCall)(MainModule->GetMappedImageBase() + MainModule->GetEP());

	Environment::kace_tid = GetCurrentThreadId();

	const HANDLE ThreadHandle = CreateThread(nullptr, 4096, FakeDriverEntry, nullptr, 0, nullptr);

	if (!ThreadHandle)
		return 0;

	while (true)
	{
		Sleep(1000);

		DWORD ExitCode;
		if (GetExitCodeThread(ThreadHandle, &ExitCode))
		{
			if (ExitCode != STILL_ACTIVE)
			{
				break;
			}
		}
	}

	CloseHandle(ThreadHandle);
	Logger::CloseLogFile();

	return 0;
}
