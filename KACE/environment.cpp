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

typedef struct _RTL_PROCESS_MODULE_INFORMATION_EX {
    ULONG NextOffset;
    RTL_PROCESS_MODULE_INFORMATION BaseInfo;
    ULONG ImageCheckSum;
    ULONG TimeDateStamp;
    PVOID DefaultBase;
} RTL_PROCESS_MODULE_INFORMATION_EX, *PRTL_PROCESS_MODULE_INFORMATION_EX;

#define IMPORT_MODULE_DIRECTORY "c:\\emu\\"
#define SYSTEM_32_DIRECTORY "c:\\Windows\\System32\\"
#define SYSTEM_DRIVER_DIRECTORY "c:\\Windows\\System32\\drivers\\"

/*
struct windows_module {
	ULONG Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR FullPathName[256];
	ULONG Checksum;
	ULONG Timestamp;
	PVOID Defaultbase;
	bool overriden;
};

*/





void Environment::InitializeSystemModules(bool load_only_emu_mods) {
    uint64_t len = 0;
    PVOID data = 0;
    auto ret = __NtRoutine("NtQuerySystemInformation", 0x4D, 0, 0, &len);
    if (ret != 0) {
        data = malloc(len);
        memset(data, 0, len);
        ret = __NtRoutine("NtQuerySystemInformation", 0x4D, data, len, &len);
    }
    PRTL_PROCESS_MODULE_INFORMATION_EX pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)data;

    while ((uint64_t)pMods <= (uint64_t)data + len - sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX)) {
        
        if (!strrchr((const char*)pMods->BaseInfo.FullPathName, '\\')) {
            break;
        }
        auto filename = strrchr((const char*)pMods->BaseInfo.FullPathName, '\\') + 1;
        LDR_DATA_TABLE_ENTRY LdrEntry{};

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
        
        std::string file_path = std::string(IMPORT_MODULE_DIRECTORY) + filename;

        if (!load_only_emu_mods) {
            file_path = (const char*)pMods->BaseInfo.FullPathName;
            auto sym_idx = file_path.find("SystemRoot", 0);
            if (sym_idx != std::string::npos) {
                file_path.replace(sym_idx, 10, "Windows");
            }

            sym_idx = file_path.find("\\??\\", 0);
            if (sym_idx != std::string::npos) {
                file_path.replace(sym_idx, 6, "");
            }

            if (!fs::exists(file_path)) {
                Logger::Log("Failed to find module %s \n", file_path.c_str());
                file_path = std::string(SYSTEM_32_DIRECTORY) + filename;
                if (!fs::exists(file_path)) {
                    file_path = std::string(SYSTEM_DRIVER_DIRECTORY) + filename;
                    if (!fs::exists(file_path)) {
                        DebugBreak();
                        Logger::Log("Searched all known paths and still failed to find %s \n", filename);

                    }
                }
            }
        }

        if (fs::exists(file_path)) {
            auto pe_file = PEFile::Open(file_path, filename);

            LdrEntry.DllBase = (PVOID)pe_file->GetMappedImageBase();
            LdrEntry.EntryPoint = (PVOID)pe_file->GetMappedImageBase(); // TODO parse PE header?


            Logger::Log("PDB for %s\n", file_path.c_str());
            symparser::download_symbols(file_path);

            environment_module.insert(std::pair((uintptr_t)LdrEntry.DllBase, LdrEntry));
        } else {
            if (load_only_emu_mods) {
                Logger::Log("Warning: Unable to find %s in %s. Ignoring and not adding to module list.\n", filename, IMPORT_MODULE_DIRECTORY);
            } else {
                Logger::Log("Warning: Couldn't find %s in any driver directories. Ignoring and not adding to module list\n", filename);
            }
            
            //LdrEntry.DllBase = (PVOID)pMods->BaseInfo.ImageBase;
            //LdrEntry.EntryPoint = (PVOID)pMods->BaseInfo.ImageBase; // TODO parse PE header?

            // @todo: @es3n1n: resolve NT path to DOS path here and cache pdb
            //
        }

       
                
        if (pMods->NextOffset != sizeof(_RTL_PROCESS_MODULE_INFORMATION_EX))
            break;

        pMods = (PRTL_PROCESS_MODULE_INFORMATION_EX)((uintptr_t)pMods + pMods->NextOffset);
        
    }

    

    PLDR_DATA_TABLE_ENTRY head = 0;
    
 
    for (auto& [_, LdrEntry] : environment_module) {
        PLDR_DATA_TABLE_ENTRY TrackedLdrEntry = (PLDR_DATA_TABLE_ENTRY)MemoryTracker::AllocateVariable(sizeof(LDR_DATA_TABLE_ENTRY));


        memcpy(TrackedLdrEntry, &LdrEntry, sizeof(LdrEntry));

        if (!head) {
            head = TrackedLdrEntry;
            InitializeListHead(&head->InLoadOrderLinks);
        }
        else {
            InsertTailList(&head->InLoadOrderLinks, &TrackedLdrEntry->InLoadOrderLinks);
        }

        if (wcsstr(TrackedLdrEntry->BaseDllName.Buffer, L"ntoskrnl.exe"))
            PsLoadedModuleList = TrackedLdrEntry;

        std::string VariableName = std::string("LdrEntry.")
            + UtilStringFromWidestring(LdrEntry.BaseDllName.Buffer);
        
        MemoryTracker::TrackVariable((uintptr_t)TrackedLdrEntry, sizeof(LDR_DATA_TABLE_ENTRY), VariableName);
    }
   
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