#pragma once
#include <ntifs.h>

EXTERN_C_START
void* InitSharedMemory();
void  ListenerThread(PVOID Context);
EXTERN_C_END
