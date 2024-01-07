#include <filesystem>

#include <Logger/Logger.h>
#include "driver_buddy.h"
#include "loader.h"
#include "environment.h"

SC_HANDLE handle_driverbuddy_svc = nullptr;
SC_HANDLE handle_emulated_drv_svc = nullptr;
PVOID	  g_sharedMemory = nullptr;
HANDLE	  g_kernEvent = nullptr;
HANDLE	  g_userEvent = nullptr;
PCONTEXT  g_curr_ctx = nullptr;

int DriverBuddy::Error(const char* message)
{
	printf("%s (error=%d)\n", message, GetLastError());
	return 1;
}

// Loads DriverBuddy.sys
bool DriverBuddy::Init(std::string& driverPath)
{
	if (!loader::open_scm())
	{
		Error("[DriverBuddy] Failed to open scm, launch Visual Studio with Admin Privledges.");
		return false;
	}

	// Get current directory
	//
	char buf[MAX_PATH]{};
	GetCurrentDirectoryA(sizeof(buf), buf);

	// Build DriverBuddy.sys path
	//
	const auto path = std::string(buf) + "\\..\\x64\\debug\\DriverBuddy.sys";

	// Create / Find DriverBuddy service
	//
	handle_driverbuddy_svc = loader::create_service("DriverBuddy", "DriverBuddy", path);

	// is it already running?
	hDevice = CreateFile(L"\\\\.\\DriverBuddy",
						 GENERIC_READ | GENERIC_WRITE,
						 FILE_SHARE_READ | FILE_SHARE_WRITE,
						 nullptr,
						 OPEN_EXISTING,
						 0,
						 nullptr);

	if (hDevice != INVALID_HANDLE_VALUE)
	{
		StopService(false, handle_driverbuddy_svc);
	}

	// Load DriverBuddy.sys
	//
	handle_driverbuddy_svc ? loader::start_service(handle_driverbuddy_svc) : false;

	if (!handle_driverbuddy_svc)
	{
		Logger::Log("Failed to load DriverBuddy, is DriverBuddy.sys in your ..\\KACE\\ folder?\n");
		return false;
	}

	Logger::Log("[DriverBuddy] Service started successfully.\n");

	// we just started the service, now get the handle
	hDevice = CreateFile(L"\\\\.\\DriverBuddy",
						 GENERIC_READ | GENERIC_WRITE,
						 FILE_SHARE_READ | FILE_SHARE_WRITE,
						 nullptr,
						 OPEN_EXISTING,
						 0,
						 nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		Error("[DriverBuddy] Failed to open device\n");
		return false;
	}

	InitCommunication();

	/* Do this in the ListenerThread now
	// init shared memory for communication
	BOOL success = DeviceIoControl(hDevice,
								   IOCTL_DRIVER_BUDDY_INIT_SHARED_MEM,	// control code
								   0,
								   0,
								   nullptr,
								   0,
								   0,
								   nullptr);*/

	// is it already loaded?
	std::filesystem::path filePath(driverPath);
	std::string			  fileName = filePath.filename().string();

	auto mod_info = Environment::GetSystemModuleInfo(fileName);

	std::filesystem::path filePath2(std::string((const char*)mod_info->BaseInfo.FullPathName));
	std::string			  fileName2 = filePath2.filename().string();

	if (strcmp(fileName.c_str(), fileName2.c_str()))
	{
		if (!LoadEmulatedDrv(driverPath))
		{
			Logger::Log("Failed to load %s with DriverBuddy...\n", driverPath.c_str());
			return false;
		}
		Logger::Log("Successfully loaded %s\n", driverPath.c_str());
	}
	else
	{
		Logger::Log("%s is already loaded, skipping loading\n", driverPath.c_str());
	}

	return true;
}

bool DriverBuddy::LoadEmulatedDrv(std::string& driverPath)
{
	std::wstring wDrivName = {};
	size_t		 info[1];
	info[0] = GetCurrentProcessId();

	DWORD returned;

	BOOL success = DeviceIoControl(hDevice,
								   IOCTL_DRIVER_BUDDY_WATCH_DRIVER,	 // control code
								   (LPVOID)info,
								   sizeof(size_t),
								   nullptr,
								   0,
								   &returned,
								   nullptr);

	if (success)
	{
		Logger::Log("[DriverBuddy] Watching for %s...\n", driverPath.c_str());

		// load BEDaisy now...
		char buf[MAX_PATH]{};
		GetCurrentDirectoryA(sizeof(buf), buf);
		const auto path = std::string(buf) + "\\BEDaisy.sys";

		Logger::Log("[DriverBuddy] Created service for %s\n", driverPath.c_str());
		handle_emulated_drv_svc = loader::create_service("BEDaisy", "BEDaisy", path);
		Logger::Log("[DriverBuddy] Starting %s\n", driverPath.c_str());
		handle_emulated_drv_svc ? loader::start_service(handle_emulated_drv_svc) : false;
		Logger::Log("[DriverBuddy] Trying to prevent DriverEntry() from executing...\n");

		Logger::Log("[DriverBuddy] Waiting 3 seconds to give time for DriverEntry thread to return...\n");
		Sleep(3);

		Logger::Log("[DriverBuddy] Unpatching and unregistering LoadImageNotify routine...\n");
		success = DeviceIoControl(hDevice,
								  IOCTL_DRIVER_BUDDY_UNWATCH_UNPATCH_DRIVER,  // control code
								  nullptr,
								  0,  // input buffer and length
								  nullptr,
								  0,  // output buffer and length
								  &returned,
								  nullptr);

		if (!success)
		{
			Logger::Log("[DriverBuddy] Failed to unpatch and unregister callback...Did %s ever load?\n",
						driverPath.c_str());
			CloseHandle(hDevice);
			hDevice = 0;
			return false;
		}

		return true;
	}
	else
	{
		Logger::Log("[DriverBuddy] Failed to load emulated driver.\n");
		CloseHandle(hDevice);
		hDevice = 0;
		return false;
	}
}

bool DriverBuddy::ToggleSMAP(bool enable)
{
	DWORD returned;

	if (hDevice)
	{
		int cmd;
		if (enable)
			cmd = IOCTL_DRIVER_BUDDY_ENABLE_SMAP;
		else
			cmd = IOCTL_DRIVER_BUDDY_DISABLE_SMAP;

		auto success = DeviceIoControl(hDevice, cmd, nullptr, 0, nullptr, 0, &returned, nullptr);

		if (!success)
		{
			Error("[DriverBuddy] Failed to unpatch and unregister callback...\n");
			CloseHandle(hDevice);
			hDevice = 0;
			return false;
		}
	}

	return true;
}

void DriverBuddy::RingDoorBell()
{
	SetEvent(g_userEvent);
}

void DriverBuddy::WaitForBuddy()
{
	// wait for buddy to finish
	WaitForSingleObject(g_kernEvent, INFINITE);
	// CloseHandle(hEvent);
}

bool DriverBuddy::InitCommunication()
{
	// init kernel event
	WCHAR kernObjName[] = L"Global\\" KERNEL_ID;
	g_kernEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, kernObjName);

	if (g_kernEvent == NULL)
	{
		Logger::Log("[DriverBuddy] Failed to open event for DoorBell, error: %d\n", GetLastError());
		DebugBreak();
	}

	// init user event
	WCHAR userObjName[] = L"Global\\" USER_ID;
	g_userEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, userObjName);

	if (g_userEvent == NULL)
	{
		Logger::Log("[DriverBuddy] Failed to open event for DoorBell, error: %d\n", GetLastError());
		DebugBreak();
	}

	HANDLE hSection = CreateFileMapping(INVALID_HANDLE_VALUE,		// Use paging file
										NULL,						// Default security
										PAGE_READWRITE,				// Read/write access
										0,							// Maximum object size (high-order DWORD)
										0x1000,						// Maximum object size (low-order DWORD)
										L"Global\\" BUDDY_MEM_ID);	// Name of mapping object

	// init shared memory
	// HANDLE hSection = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, L"Global\\" BUDDY_MEM_ID);
	if (hSection == NULL)
	{
		DWORD error = GetLastError();
		Logger::Log("[DriverBuddy] Failed to open shared memory section, error: %d\n", error);
		DebugBreak();
		return false;
	}

	g_sharedMemory = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);

	if (g_sharedMemory == NULL)
	{
		DWORD error = GetLastError();
		Logger::Log("[DriverBuddy] Failed to map shared memory section, error: %d\n", error);
		CloseHandle(hSection);
		DebugBreak();
		return false;
	}

	Logger::Log("[DriverBuddy] Initialized communication.\n");
	return true;
}

void DriverBuddy::WriteSharedMemory(int cmd, PVOID data, size_t size)
{
	BUDDY_SHMEM* sharedMem = (BUDDY_SHMEM*)g_sharedMemory;
	sharedMem->cmd = (BUDDY_CMD)cmd;
	sharedMem->length = size;

	if (size > 0)
		memcpy(sharedMem->data, data, size);
}

bool DriverBuddy::Execute(PCONTEXT ctx)
{
	// WriteSharedMemory(BUDDY_CMD_EXECUTE, ctx, sizeof(CONTEXT));

	if (!g_curr_ctx)
	{
		BUDDY_SHMEM* sharedMem = (BUDDY_SHMEM*)g_sharedMemory;
		sharedMem->cmd = BUDDY_CMD_EXECUTE;
		sharedMem->length = sizeof(PCONTEXT);
		PCONTEXT** pCtxInSharedMem = (PCONTEXT**)(sharedMem->data);
		*pCtxInSharedMem = &g_curr_ctx;
	}

	g_curr_ctx = ctx;

#define LOWER_OFFSET 0x228
#define SIZE_ 0x258
	char tempBuff[SIZE_];
	// memcpy(tempBuff, ((void*)((DWORD64)ctx->Rsp - SIZE_)), LOWER_OFFSET);

	RingDoorBell();
	WaitForBuddy();

	// DWORD64 oldRet = *(DWORD64*)(ctx->Rsp);

	// memcpy(((void*)((DWORD64)ctx->Rsp - SIZE_)), tempBuff, LOWER_OFFSET);

	// Rip and Rax are set in DriverBuddy.sys

	// x64 calling convention
	// RCX, RDX, R8, R9, XMM0-XMM3(if FP) are used for the first 4 arguments

	// https://learn.microsoft.com/en-us/cpp/build/x64-software-conventions?view=msvc-170#x64-register-usage
	// Don't need to worry about preserving any registers in the context
	// ctx->Rip = *((DWORD64*)(pCtx->Rsp));
	// ctx->Rax = pCtx->Rax;

	// DEBUG FOR RETURNING 0 TO BE
	ctx->Rip = *((DWORD64*)(ctx->Rsp));	 // oldRet;	// *((DWORD64*)(ctx->Rsp));
	ctx->Rsp += 8;
	// ctx->Rax = 0;

	/* ctx->Rbp = new_ctx->Rbp;
	ctx->Rax = new_ctx->Rax;
	ctx->Rcx = new_ctx->Rcx;
	ctx->Rdx = new_ctx->Rdx;
	// ctx->R8 = new_ctx->R8;
	// ctx->R9 = new_ctx->R9;*/
	// free(new_ctx);
	return true;
}

// Unloads DriverBuddy.sys
bool DriverBuddy::StopService(bool delete_service, SC_HANDLE svc_handle)
{
	SERVICE_STATUS svc_status{};

	// Unload DriverBuddy.sys
	//
	bool success = loader::stop_service(svc_handle, &svc_status);

	// Service not started
	//
	if (!success && GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
		success = true;

	// Delete DriverBuddy service
	//
	if (delete_service)
	{
		success ? loader::delete_service(svc_handle) : false;
	}

	return success;
}
