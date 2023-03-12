#pragma once
#include <Windows.h>
#include <string>

#define DRIVER_BUDDY_DEVICE 0x8000
#define IOCTL_DRIVER_BUDDY_WATCH_DRIVER CTL_CODE(DRIVER_BUDDY_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct DriverInfo DriverInfo;

struct DriverInfo
{
	PCWSTR driverName;
};

namespace DriverBuddy
{
	inline HANDLE hDevice; 
	bool Init();
	bool LoadEmulatedDrv(std::string &driverPath);
	bool DeInit();
	int	 Error(const char* message);
}  // namespace DriverBuddy