#pragma once
#include <Windows.h>
#include <string>
#include <buddy_common.h>

namespace DriverBuddy
{
	inline HANDLE hDevice; 
	bool Init();
	bool LoadEmulatedDrv(std::string &driverPath);
	bool DeInit(bool delete_flag);
	int	 Error(const char* message);
}  // namespace DriverBuddy