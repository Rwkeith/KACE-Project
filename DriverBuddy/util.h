#pragma once
#include <ntddk.h>

EXTERN_C_START
void set_smap(int enable);
void set_cet(int enable);
void SetWP();
void ClearWP();
EXTERN_C_END