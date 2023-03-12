#include "driver_buddy.h"
#include "loader.h"
// #include "utils.h"

SC_HANDLE handle_driverbuddy_svc = nullptr;

int DriverBuddy::Error(const char* message)
{
	printf("%s (error=%d)\n", message, GetLastError());
	return 1;
}

// Loads DriverBuddy.sys
bool DriverBuddy::Init()
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

	// is it already loaded?
	hDevice = CreateFile(L"\\\\.\\DriverBuddy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice != INVALID_HANDLE_VALUE)
	{
		DeInit();
	}
	
	// Create DriverBuddy service
	//
	handle_driverbuddy_svc = loader::create_service("DriverBuddy", "DriverBuddy", path);

	// Load DriverBuddy.sys
	//
	return handle_driverbuddy_svc ? loader::start_service(handle_driverbuddy_svc) : false;
}

bool DriverBuddy::LoadEmulatedDrv(std::string& driverPath)
{
	hDevice = CreateFile(L"\\\\.\\DriverBuddy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE)
	{
		Error("[DriverBuddy] Failed to open device");
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
		CloseHandle(hDevice);
		
		// load BEDaisy now...
		
		return true;
	}
	else
	{
		Error("[DriverBuddy] Failed to load emulated driver.\n");
		CloseHandle(hDevice);
		return false;
	}
}

	// Unloads DriverBuddy.sys
//
bool DriverBuddy::DeInit()
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
	return success ? loader::delete_service(handle_driverbuddy_svc) : false;
}