#include "environment.h"
#include "utils.h"
#include <MemoryTracker/memorytracker.h>
#include <Logger/Logger.h>
#include <PEMapper/pefile.h>
#include <SymParser/symparser.hpp>
#include <filesystem>

namespace fs = std::filesystem;

using fnFreeCall = uint64_t(__fastcall*)(...);

template <typename... Params>
static NTSTATUS __NtRoutine(const char* Name, Params&&... params) {
    auto fn = (fnFreeCall)GetProcAddress(GetModuleHandleA("ntdll.dll"), Name);
    return fn(std::forward<Params>(params)...);
}



int Environment::GetModuleCount(PRTL_PROCESS_MODULE_INFORMATION_EX module_list) {
    if (module_list->NextOffset != sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX)) {
        return 1;
    }

    PRTL_PROCESS_MODULE_INFORMATION_EX temp = module_list;
    auto module_count = 0;
    while (temp->NextOffset == sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX)) {
        module_count += 1;
        temp = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)temp + temp->NextOffset);
    }

    return module_count;
}

RTL_PROCESS_MODULES* Environment::FilterProcessModules(RTL_PROCESS_MODULES* proc_mod_list, std::vector<std::string> &filter_list, bool use_as_whitelist) {
    auto mod_count = proc_mod_list->NumberOfModules;
    auto new_count = 0;

    std::vector<RTL_PROCESS_MODULE_INFORMATION*> new_proc_mod_list;
    auto temp_proc_mods = proc_mod_list->Modules;
    bool skip;

    if (use_as_whitelist)
        skip = true;
    else
        skip = false;

    for (int i = 0; i < mod_count; i++) {
        auto moduleName = (const char*)temp_proc_mods[i].FullPathName;
        while (strstr(moduleName, "\\"))
            moduleName++;

        for (auto name : filter_list) {
            if (!strcmp(name.c_str(), moduleName)) {
                if (use_as_whitelist)
                    skip = false;
                else
                    skip = true;
                break;
            }
        }

        if (!skip) {
            new_proc_mod_list.push_back(&temp_proc_mods[i]);
        }

        if (use_as_whitelist)
            skip = true;
        else
            skip = false;
    }

    auto new_proc_size = sizeof(uint32_t) + new_proc_mod_list.size() * sizeof(RTL_PROCESS_MODULE_INFORMATION);
    RTL_PROCESS_MODULES* new_proc_mods = (RTL_PROCESS_MODULES*)malloc(new_proc_size);
    memset(new_proc_mods, 0, new_proc_size);
    new_proc_mods->NumberOfModules = new_proc_mod_list.size();

    int i = 0;
    for (auto module : new_proc_mod_list) {
        memcpy(&new_proc_mods->Modules[i], module, sizeof(RTL_PROCESS_MODULE_INFORMATION));
        i++;
    }

    return new_proc_mods;
}

PRTL_PROCESS_MODULE_INFORMATION_EX Environment::FilterSystemModules(PRTL_PROCESS_MODULE_INFORMATION_EX module_list, std::vector<std::string> &filter_list, bool use_as_whitelist) {
    auto mod_count = GetModuleCount(module_list);
    auto new_count = 0;

    std::vector<PRTL_PROCESS_MODULE_INFORMATION_EX> new_mod_list;
    auto temp = module_list;
    bool skip;

    if (use_as_whitelist)
        skip = true;
    else
        skip = false;
    
    for (int i = 0; i < mod_count; i++) {
        auto file_name = (const char*)temp->BaseInfo.FullPathName + temp->BaseInfo.OffsetToFileName;
        for (auto name : filter_list) {
            if (!strcmp(name.c_str(), file_name)) {
                if (use_as_whitelist)
                    skip = false;
                else
                    skip = true;
                break;
            }
        }

        if (!skip) {
            new_mod_list.push_back(temp);
        }

        temp = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)temp + sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX));

        if (use_as_whitelist)
            skip = true;
        else
            skip = false;
    }
    
    PRTL_PROCESS_MODULE_INFORMATION_EX new_mod_info = new _RTL_PROCESS_MODULE_INFORMATION_EX[new_mod_list.size()];

    temp = new_mod_info;
    for (auto module : new_mod_list) {
        memcpy(temp, module, sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX));
        temp = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)temp + sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX));
    }

    return new_mod_info;
}

SYSTEM_PROCESS_INFORMATION* Environment::FilterProcesses(SYSTEM_PROCESS_INFORMATION* ProcList, unsigned int proclist_size,std::vector<int> filter) {
        
    std::vector<PSYSTEM_PROCESS_INFORMATION> new_proc_list;
    int number = 0;
    auto filtered_size = 0;
    auto temp = ProcList;
    auto proclist_end = (uint64_t)temp + proclist_size;

    // Get size
    while (temp) {
                
        if (std::find(filter.begin(), filter.end(), (uint64_t)temp->ProcessId) != filter.end()) {
            if (!temp->NextEntryOffset) {
                filtered_size += proclist_end - (uint64_t)temp;
            } else {
                filtered_size += temp->NextEntryOffset;
            }
            number++;
        }

        if (temp->NextEntryOffset == 0 || number == filter.size()) {
            break;
        }

        temp = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)temp + temp->NextEntryOffset);
    }
    
    auto newarray = malloc(filtered_size);

    temp = ProcList;
    auto temp_newarray = newarray;
    auto last_entry = temp_newarray;
    while (temp) {

        if (std::find(filter.begin(), filter.end(), (uint64_t)temp->ProcessId) != filter.end()) {
            if (temp->NextEntryOffset) {
                memcpy(temp_newarray, temp, temp->NextEntryOffset);
            } else {
                memcpy(temp_newarray, temp, proclist_end - (uint64_t)temp);
            }
            last_entry = temp_newarray;
            temp_newarray = (PVOID)((uintptr_t)temp_newarray + temp->NextEntryOffset);
            number--;
        }

        if (temp->NextEntryOffset == 0 || number == 0) {
            break;
        }

        temp = (SYSTEM_PROCESS_INFORMATION*)((uintptr_t)temp + temp->NextEntryOffset);
    }

    // Note: last valid entry's NextEntryOffset field will be 0
    ((SYSTEM_PROCESS_INFORMATION*)(last_entry))->NextEntryOffset = 0;

    kace_proc_len = filtered_size;

    return (SYSTEM_PROCESS_INFORMATION*)newarray;
}

// tries using the absolute path if given, then tries other system directories
// returns file path on success or empty std::string on fail    (system_file, (const char*)pMods->BaseInfo.FullPathName);
std::string Environment::GetSystemFilePath(std::string system_file, std::string absolute_path) {
    std::string file_path;
    if (absolute_path.length()) {
        file_path = absolute_path.c_str(); // (const char*)pMods->BaseInfo.FullPathName;
        auto sym_idx = file_path.find("SystemRoot", 0);
        if (sym_idx != std::string::npos) {
            file_path.replace(sym_idx, 10, "Windows");
        }

        sym_idx = file_path.find("\\??\\", 0);
        if (sym_idx != std::string::npos) {
            file_path.replace(sym_idx, 6, "");
        }
    }

    if (!fs::exists(file_path)) {
        file_path = std::string(SYSTEM_32_DIRECTORY) + system_file;
        if (!fs::exists(file_path)) {
            file_path = std::string(SYSTEM_DRIVER_DIRECTORY) + system_file;
            if (!fs::exists(file_path)) {
                DebugBreak();
                Logger::Log("Searched all known paths and still failed to find %s \n", system_file.c_str());
            }
        }
    }
    return file_path;
}

// returns file path on success or empty std::string on fail
std::string Environment::GetEmuPath(std::string system_file) { 
    std::string file_path = std::string(IMPORT_MODULE_DIRECTORY) + system_file;
    if (fs::exists(file_path)) {
        return file_path;
    } else
        return std::string("");
 }

bool Environment::IsEmuFile(std::string system_file) {
    std::string file_path = std::string(IMPORT_MODULE_DIRECTORY) + system_file;
    if (fs::exists(file_path)) {
        return true;
    } else
        return false;
 }

void Environment::InitKaceProcModuleList() {
    uint64_t len = 0;
    PVOID module_data = 0;
    auto ret = __NtRoutine("NtQuerySystemInformation", 0xB, 0, 0, &len);
    if (ret != 0) {
        module_data = malloc(len);
        memset(module_data, 0, len);
        ret = __NtRoutine("NtQuerySystemInformation", 0xB, module_data, len, &len);
    } else {
        DebugBreak();       // ???
    }

    kace_proc_modules = FilterProcessModules((RTL_PROCESS_MODULES*)module_data, kace_module_whitelist, true);
    kace_proc_modules_len = (kace_proc_modules->NumberOfModules * sizeof(RTL_PROCESS_MODULE_INFORMATION)) + sizeof(uint32_t);
    // free(module_data);
}


void Environment::InitializeSystemModules(bool load_only_emu_mods) {
    uint64_t len = 0;
    PVOID module_data = 0;
    auto ret = __NtRoutine("NtQuerySystemInformation", 0x4D, 0, 0, &len);
    if (ret != 0) {
        module_data = malloc(len);
        memset(module_data, 0, len);
        ret = __NtRoutine("NtQuerySystemInformation", 0x4D, module_data, len, &len);
    }

    PRTL_PROCESS_MODULE_INFORMATION_EX pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)module_data;

    auto mod_count = GetModuleCount((PRTL_PROCESS_MODULE_INFORMATION_EX)module_data);

    // create entries for modules
    for (int i = 0; i < mod_count; i++) {
        if (!strrchr((const char*)pMods->BaseInfo.FullPathName, '\\')) {
            break;
        }
        auto filename = strrchr((const char*)pMods->BaseInfo.FullPathName, '\\') + 1;

        std::string absolute_path = (const char*)pMods->BaseInfo.FullPathName;
        std::string found_path;


        // checks if file is in emu folder. Uses legit system file and gets pdb correlated to that system file.
        if (load_only_emu_mods) {
            if (IsEmuFile(filename)) {
                found_path = GetSystemFilePath(filename, absolute_path);
            }
        } else {
            found_path = GetSystemFilePath(filename, absolute_path);
        }

        // don't create an entry for modules we can't find on disk.  Maybe later when we have kernel primitives, we don't care and want to simulate the real environment as accurately as possible
        if (!found_path.length()) {
            Logger::Log("Skipping %s \n", filename);
            pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)pMods + pMods->NextOffset);
            continue;
        }

        if (!strcmp(filename, "ntoskrnl.exe")) {
            ntoskrnl_path = found_path;
        }

        kace_module_whitelist.push_back(filename);

        LDR_DATA_TABLE_ENTRY LdrEntry {};

        LdrEntry.EntryPointActivationContext = 0;
        LdrEntry.Flags = pMods->BaseInfo.Flags;
        LdrEntry.HashLinks = LIST_ENTRY();
        LdrEntry.LoadCount = 1;
        LdrEntry.LoadedImports = 100;
        LdrEntry.PatchInformation = 0;
        LdrEntry.SectionPointer = (ULONG)pMods->BaseInfo.Section;
        LdrEntry.SizeOfImage = pMods->BaseInfo.ImageSize;
        LdrEntry.TimeDateStamp = pMods->TimeDateStamp;
        LdrEntry.TlsIndex = 0;

        const std::wstring& WideFullDllName = UtilWidestringFromString((const char*)pMods->BaseInfo.FullPathName);
        RtlInitUnicodeString(&LdrEntry.FullDllName, WideFullDllName.c_str());

        const std::wstring& WideBaseDllName = UtilWidestringFromString((const char*)pMods->BaseInfo.FullPathName + pMods->BaseInfo.OffsetToFileName);
        RtlInitUnicodeString(&LdrEntry.BaseDllName, WideBaseDllName.c_str());

        LdrEntry.CheckSum = pMods->ImageCheckSum;

        // found_path is the real system file path
        auto pe_file = PEFile::Open(found_path, filename);

        LdrEntry.DllBase = (PVOID)pe_file->GetMappedImageBase();
        LdrEntry.EntryPoint = (PVOID)pe_file->GetMappedImageBase(); // TODO parse PE header?

        Logger::Log("PDB for %s\n", found_path.c_str());
        symparser::download_symbols(found_path);

        environment_module.insert(std::pair((uintptr_t)LdrEntry.DllBase, LdrEntry));

        pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)pMods + pMods->NextOffset);
    }

    kace_modules = FilterSystemModules((PRTL_PROCESS_MODULE_INFORMATION_EX)module_data, kace_module_whitelist, true);
    kace_modules_len = sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX) * GetModuleCount(kace_modules);

    // Links the entries together into a linked list, and initializes the list reference to PsLoadedModuleList.  An exported ntoskrnl symbol
    PLDR_DATA_TABLE_ENTRY head = 0;

    for (auto& [_, LdrEntry] : environment_module) {
        PLDR_DATA_TABLE_ENTRY TrackedLdrEntry = (PLDR_DATA_TABLE_ENTRY)MemoryTracker::AllocateVariable(sizeof(LDR_DATA_TABLE_ENTRY));

        memcpy(TrackedLdrEntry, &LdrEntry, sizeof(LdrEntry));

        if (!head) {
            head = TrackedLdrEntry;
            InitializeListHead(&head->InLoadOrderLinks);
        } else {
            InsertTailList(&head->InLoadOrderLinks, &TrackedLdrEntry->InLoadOrderLinks);
        }

        if (wcsstr(TrackedLdrEntry->BaseDllName.Buffer, L"ntoskrnl.exe"))
            PsLoadedModuleList = TrackedLdrEntry;

        std::string VariableName = std::string("LdrEntry.") + UtilStringFromWidestring(LdrEntry.BaseDllName.Buffer);

        Logger::Log("%s \n", VariableName.c_str());
        MemoryTracker::TrackVariable((uintptr_t)TrackedLdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), VariableName);
    }
    // free(module_data);
}

void Environment::InitializeProcesses() 
{
    uint64_t len = 0;
    PVOID module_data = 0;
    auto ret = __NtRoutine("NtQuerySystemInformation", 0x5, 0, 0, &len);
    if (ret != 0) {
        module_data = malloc(len);
        memset(module_data, 0, len);
        ret = __NtRoutine("NtQuerySystemInformation", 0x5, module_data, len, &len);
    }

    std::vector<int> TargetIDs;
    TargetIDs.emplace_back(0);
    TargetIDs.emplace_back(4);

    kace_processes = FilterProcesses((SYSTEM_PROCESS_INFORMATION*)module_data, len, TargetIDs);
}

void Environment::CheckPtr(uint64_t ptr) {
    for (auto it = environment_module.begin(); it != environment_module.end(); it++) {
        uintptr_t base = (uintptr_t)it->second.DllBase;

        if (base <= ptr && ptr <= base + it->second.SizeOfImage) {
            Logger::Log("Trying to access not overriden module : %wZ at offset %llx\n", it->second.FullDllName, ptr - base);
            DebugBreak();
            break;
        }
    }
    return;
} 