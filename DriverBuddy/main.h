#pragma once
#include <ntifs.h>
#include "buddy_common.h"

#define EP_OFFSET 0xA8

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
void			  BuddyUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS		  BuddyCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS		  BuddyDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

void LoadImageNotifyRoutine(PUNICODE_STRING, HANDLE, PIMAGE_INFO);

void ExecAddressWithCtx(PCONTEXT ctx);

EXTERN_C_END

