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
	bool		  StopService(bool delete_flag, SC_HANDLE svc_handle);
	int			  Error(const char* message);
}  // namespace DriverBuddy