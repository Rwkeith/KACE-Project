#pragma once
#include <ntddk.h>

#define DRIVER_BUDDY_DEVICE 0x8000
#define IOCTL_DRIVER_BUDDY_WATCH_DRIVER CTL_CODE(DRIVER_BUDDY_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct DriverInfo DriverInfo;

struct DriverInfo
{
	PCWSTR driverName;
};