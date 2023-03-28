#pragma once
#include <Windows.h>
#include <string>
#include <buddy_common.h>

typedef void (*FakeDrvEntry)();

namespace DriverBuddy
{
	inline HANDLE hDevice = 0; 
	bool		  Init(std::string &driverPath);
	bool		  LoadEmulatedDrv(std::string &driverPath);
	bool		  ToggleSMAP(bool enable);
	bool		  DeInit(bool delete_flag);
	int			  Error(const char* message);
}  // namespace DriverBuddy