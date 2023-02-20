#pragma once

EXTERN_C_START
DRIVER_INITIALIZE DriverEntry;
void SampleUnload(_In_ PDRIVER_OBJECT DriverObject);
EXTERN_C_END