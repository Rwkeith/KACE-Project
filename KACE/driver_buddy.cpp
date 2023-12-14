#include <filesystem>

#include <Logger/Logger.h>
#include "driver_buddy.h"
#include "loader.h"
#include "environment.h"

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
	const auto path = std::string(buf) + "\\..\\x64\\debug\\DriverBuddy.sys";

	// Create / Find DriverBuddy service
	//
	handle_driverbuddy_svc = loader::create_service("DriverBuddy", "DriverBuddy", path);

	// is it already running?
	hDevice = CreateFile(L"\\\\.\\DriverBuddy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

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
	// Find BEDaisy service (should always exist at this point)
	//
	auto handle_bedaisy_svc = loader::create_service("BEDaisy", "BEDaisy", driverPath);

	// If the emulated driver is still loaded, we should unload it.  It's in an unknown state from a previous run
	StopService(false, handle_bedaisy_svc);


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
								  0,	 // input buffer and length
								  nullptr,
								  0,  // output buffer and length
								  &returned,
								  nullptr);

		if (!success)
		{
			Logger::Log("[DriverBuddy] Failed to unpatch and unregister callback...Did %s ever load?\n", driverPath.c_str());
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

bool DriverBuddy::Execute(PCONTEXT ctx)
{		
		// generally all Windows system functions follow the x64 calling convention
		// RCX, RDX, R8, R9, XMM0-XMM3(if FP) are used for the first 4 arguments
		DWORD returned;

		void *ret = 0;

		if (hDevice)
		{
		auto success = DeviceIoControl(hDevice,
											  IOCTL_DRIVER_BUDDY_EXECUTE,
											  nullptr,
											  0,
											  ret, sizeof(ret),
											  &returned,
											  nullptr);
	
		if (!success)
		{
			Error("[DriverBuddy] Failed to execute call.\n");
			CloseHandle(hDevice);
			hDevice = 0;
			return false;
		}

		if (ret)
		{
			ctx->Rax = (DWORD64)ret;
			return true;
		}
		else
		{
			return false;
		}
	}

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