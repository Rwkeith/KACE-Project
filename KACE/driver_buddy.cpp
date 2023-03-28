#include <Logger/Logger.h>
#include "driver_buddy.h"
#include "loader.h"

// #include "utils.h"

SC_HANDLE handle_driverbuddy_svc = nullptr;
SC_HANDLE handle_emulated_drv_svc = nullptr;

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
	const auto path = std::string(buf) + "\\DriverBuddy.sys";

	// Create / Find DriverBuddy service
	//
	handle_driverbuddy_svc = loader::create_service("DriverBuddy", "DriverBuddy", path);

	// is it already running?
	hDevice = CreateFile(L"\\\\.\\DriverBuddy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice != INVALID_HANDLE_VALUE)
	{
		DeInit(false);
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
	
	if (!LoadEmulatedDrv(driverPath))
	{
		Logger::Log("Failed to load %s with DriverBuddy...\n", driverPath.c_str());
		return false;
	}

	Logger::Log("Successfully loaded %s\n", driverPath.c_str());
	return true;
}

bool DriverBuddy::LoadEmulatedDrv(std::string& driverPath)
{
	hDevice = CreateFile(L"\\\\.\\DriverBuddy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		Error("[DriverBuddy] Failed to open device\n");
		return false;
	}

	DriverInfo data = {};

	std::wstring wDrivName = {};  // = UtilWidestringFromString(driverPath);
	data.driverName = wDrivName.c_str();

	DWORD returned;
	BOOL  success = DeviceIoControl(hDevice,
									IOCTL_DRIVER_BUDDY_WATCH_DRIVER,  // control code
									&data,
									sizeof(data),  // input buffer and length
									nullptr,
									0,	// output buffer and length
									&returned,
									nullptr);
	
	if (success)
	{
		printf("[DriverBuddy] Watching for %s...\n", driverPath.c_str());

		// load BEDaisy now...
		char buf[MAX_PATH]{};
		GetCurrentDirectoryA(sizeof(buf), buf);
		const auto path = std::string(buf) + "\\BEDaisy.sys";

		Logger::Log("[DriverBuddy] Created service for %s\n", driverPath.c_str());
		handle_emulated_drv_svc = loader::create_service("BEDaisy", "BEDaisy", path);
		Logger::Log("[DriverBuddy] Starting %s\n", driverPath.c_str());
		handle_emulated_drv_svc ? loader::start_service(handle_emulated_drv_svc) : false;
		
		Logger::Log("[DriverBuddy] Waiting 3 seconds to give time for DriverEntry thread to return...");
		Sleep(3);

		Logger::Log("[DriverBuddy] Unpatching and unregistering LoadImageNotify routine...\n");
		success = DeviceIoControl(hDevice,
								  IOCTL_DRIVER_BUDDY_UNWATCH_UNPATCH_DRIVER,  // control code
								  nullptr,
								  0,	 // input buffer and length
								  nullptr,
								  0,  // output buffer and length
								  &returned,
								  nullptr);

		if (!success)
		{
			Error("[DriverBuddy] Failed to unpatch and unregister callback...\n");
			CloseHandle(hDevice);
			hDevice = 0;
			return false;
		}

		return true;
	}
	else
	{
		Error("[DriverBuddy] Failed to load emulated driver.\n");
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

		auto success = DeviceIoControl(hDevice,
								  cmd,
								  nullptr,
								  0,
								  nullptr,
								  0,
								  &returned,
								  nullptr);
	
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

// Unloads DriverBuddy.sys
bool DriverBuddy::DeInit(bool delete_service)
{
	SERVICE_STATUS svc_status{};

	// Unload DriverBuddy.sys
	//
	bool success = loader::stop_service(handle_driverbuddy_svc, &svc_status);

	// Service not started
	//
	if (!success && GetLastError() == ERROR_SERVICE_NOT_ACTIVE)
		success = true;

	// Delete DriverBuddy service
	//
	if (delete_service)
	{
		success ? loader::delete_service(handle_driverbuddy_svc) : false;
	}

	return success;
}