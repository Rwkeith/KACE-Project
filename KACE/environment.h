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

struct ProcessList {
    int NumberOfProcesses;
    int SizeOfArray;
    SYSTEM_PROCESS_INFORMATION* Array;
};

#define IMPORT_MODULE_DIRECTORY "c:\\emu\\driver\\"
#define SYSTEM_32_DIRECTORY "c:\\Windows\\System32\\"
#define SYSTEM_DRIVER_DIRECTORY "c:\\Windows\\System32\\drivers\\"

namespace Environment {
    inline std::vector<std::string> kace_module_whitelist;
    inline PRTL_PROCESS_MODULE_INFORMATION_EX kace_modules;
    inline unsigned int kace_modules_len;
    inline RTL_PROCESS_MODULES* kace_proc_modules = 0;
    inline unsigned long kace_proc_modules_len;
    inline unsigned long kace_proc_len;
    inline SYSTEM_PROCESS_INFORMATION* kace_processes;
    inline std::string ntoskrnl_path;
    inline std::unordered_map<uintptr_t, LDR_DATA_TABLE_ENTRY> environment_module{};
    inline PLDR_DATA_TABLE_ENTRY PsLoadedModuleList;
    
    bool IsEmuFile(std::string system_file);
    void InitKaceProcModuleList();

    SYSTEM_PROCESS_INFORMATION* FilterProcesses(SYSTEM_PROCESS_INFORMATION* ProcessList, std::vector<int>);
    RTL_PROCESS_MODULES* FilterProcessModules(RTL_PROCESS_MODULES* proc_mod_list, std::vector<std::string> &filter_list, bool use_as_whitelist);
    std::string GetSystemFilePath(std::string system_file, std::string absolute_path = {});
    std::string GetEmuPath(std::string system_file);
    bool IsEmuFile(std::string system_file);
    int GetModuleCount(PRTL_PROCESS_MODULE_INFORMATION_EX module_list);
    PRTL_PROCESS_MODULE_INFORMATION_EX FilterSystemModules(PRTL_PROCESS_MODULE_INFORMATION_EX module_list, std::vector<std::string> &filter_list, bool use_as_whitelist);
    void InitializeSystemModules(bool load_only_emu_mods);
    void InitializeProcesses();
    void CheckPtr(uint64_t ptr);

    namespace ThreadManager {
        inline std::unordered_map<uintptr_t, _ETHREAD*> environment_threads{};

    }
} 