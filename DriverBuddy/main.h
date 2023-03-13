#pragma once
#include <ntddk.h>
#include "buddy_common.h"

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
void			  BuddyUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS		  BuddyCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS		  BuddyDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

void LoadImageNotifyRoutine(PUNICODE_STRING, HANDLE, PIMAGE_INFO);
EXTERN_C_END

