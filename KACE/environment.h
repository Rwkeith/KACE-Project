#pragma once
#include <unordered_map>
#include <windows.h>
#include "ntoskrnl_struct.h"
#include "utils.h"

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX {
    ULONG NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageCheckSum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

#define IMPORT_MODULE_DIRECTORY "c:\\emu\\driver\\"
#define SYSTEM_32_DIRECTORY "c:\\Windows\\System32\\"
#define SYSTEM_DRIVER_DIRECTORY "c:\\Windows\\System32\\drivers\\"

namespace Environment {
    inline std::unordered_map<uintptr_t, LDR_DATA_TABLE_ENTRY> environment_module{};
    inline PLDR_DATA_TABLE_ENTRY PsLoadedModuleList;

    int GetModuleCount(PRTL_PROCESS_MODULE_INFORMATION_EX module_list);
    PRTL_PROCESS_MODULE_INFORMATION_EX FilterSystemModules(PRTL_PROCESS_MODULE_INFORMATION_EX module_list, std::vector<std::string> filter_list);
    void InitializeSystemModules(bool load_only_emu_mods);
    void CheckPtr(uint64_t ptr);

    namespace ThreadManager {
        inline std::unordered_map<uintptr_t, _ETHREAD*> environment_threads{};

    }
} 