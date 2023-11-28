#include "pefile.h"
#include <Logger/Logger.h>

#include <PTEdit/ptedit_header.h>
#include <PTEdit/PTEditorLoader.h>

#include <SymParser\symparser.hpp>
#include <filesystem>

#define IMPORT_MODULE_DIRECTORY "c:\\emu\\driver\\"

namespace fs = std::filesystem;

std::unordered_map<std::string, PEFile*> PEFile::moduleList_namekey;
std::vector<PEFile*>					 PEFile::LoadedModuleArray;

PEFile* PEFile::FindModule(uintptr_t ptr)
{
	for (int i = 0; i < LoadedModuleArray.size(); i++)
		if (LoadedModuleArray[i]->GetMappedImageBase() <= ptr &&
			ptr <= LoadedModuleArray[i]->GetMappedImageBase() + LoadedModuleArray[i]->GetVirtualSize())
			return LoadedModuleArray[i];
	return 0;
}

PEFile* PEFile::FindModule(std::string name)
{
	for (auto& c : name)
		c = tolower(c);

	if (moduleList_namekey.contains(name))
	{
		return moduleList_namekey[name];
	}
	return 0;
}

void PEFile::ParseHeader()
{
	pDosHeader = (PIMAGE_DOS_HEADER)mapped_buffer;
	pNtHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)mapped_buffer + pDosHeader->e_lfanew);
	pOptionalHeader = &pNtHeaders->OptionalHeader;
	pImageFileHeader = &pNtHeaders->FileHeader;
	pImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)pImageFileHeader + sizeof(IMAGE_FILE_HEADER) +
												  pImageFileHeader->SizeOfOptionalHeader);

	virtual_size = pOptionalHeader->SizeOfImage;
	imagebase = pOptionalHeader->ImageBase;
	entrypoint = pOptionalHeader->AddressOfEntryPoint;
}

void PEFile::ParseSection()
{
	sections.clear();

	for (int i = 0; i < pImageFileHeader->NumberOfSections; i++)
	{
		char name[9] = {0};
		strncpy_s(name, (char*)pImageSectionHeader[i].Name, 8);

		SectionData data = {0};

		data.characteristics = pImageSectionHeader[i].Characteristics;
		data.virtual_address = pImageSectionHeader[i].VirtualAddress;
		data.virtual_size = pImageSectionHeader[i].Misc.VirtualSize;
		data.raw_size = pImageSectionHeader[i].SizeOfRawData;
		data.raw_address = pImageSectionHeader[i].PointerToRawData;

		while (sections.contains(std::string(name)))
		{
			name[strlen(name) - 1] = name[strlen(name) - 1] + 1;
		}

		sections.insert(std::pair(std::string(name), data));
	}
}

void PEFile::ParseImport()
{
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(
		mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pImageImportDescriptor->Name; pImageImportDescriptor++)
	{
		PCHAR pDllName = makepointer<PCHAR>(mapped_buffer, pImageImportDescriptor->Name);

		// Original thunk
		PIMAGE_THUNK_DATA pOriginalThunk = NULL;
		if (pImageImportDescriptor->OriginalFirstThunk)
			pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->OriginalFirstThunk);
		else
			pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

		// IAT thunk
		PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

		for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++)
		{
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
			{}
			else
			{
				ImportData			  id;
				PIMAGE_IMPORT_BY_NAME pImageImportByName =
					makepointer<PIMAGE_IMPORT_BY_NAME>(mapped_buffer, pOriginalThunk->u1.AddressOfData);

				id.library = pDllName;
				id.name = pImageImportByName->Name;
				id.rva = pIATThunk->u1.Function;

				imports_rvakey.insert(std::pair(id.rva, id));
				imports_namekey.insert(std::pair(id.name, id));
			}
		}
	}
}

void PEFile::ParseExport()
{
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return;

	PIMAGE_EXPORT_DIRECTORY pImageExportDescriptor = makepointer<PIMAGE_EXPORT_DIRECTORY>(
		mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	if (!pImageExportDescriptor->NumberOfNames || !pImageExportDescriptor->AddressOfFunctions)
		return;
	PDWORD fAddr = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfFunctions);
	PDWORD fNames = (PDWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNames);
	PWORD  fOrd = (PWORD)((LPBYTE)mapped_buffer + pImageExportDescriptor->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImageExportDescriptor->NumberOfNames; i++)
	{
		LPSTR pFuncName = (LPSTR)((LPBYTE)mapped_buffer + fNames[i]);
		if (pFuncName && fOrd[i])
		{
			exports_namekey.insert(std::pair(pFuncName, fAddr[fOrd[i]]));
			exports_rvakey.insert(std::pair(fAddr[fOrd[i]], pFuncName));
		}
	}
}

PEFile::PEFile(std::string filename, std::string name, uintmax_t size)
{
	if (size)
	{
		mapped_buffer = (unsigned char*)LoadLibraryExA(filename.c_str(), NULL, DONT_RESOLVE_DLL_REFERENCES);
		Logger::Log("Loaded %s at 0x%p\n", filename.c_str(), mapped_buffer);
		if (mapped_buffer)
		{
			this->isExecutable = false;
			this->filename = filename;
			this->name = name;

			ParseHeader();
			ParseSection();
			ParseImport();
			ParseExport();
		}
	}
}

SIZE_T RoundUpToLargePageSize(SIZE_T size, SIZE_T largePageSize)
{
	return (size + largePageSize - 1) / largePageSize * largePageSize;
}

PEFile::PEFile(void* image_base, std::string name, uintmax_t size, bool is_kernel, bool make_user_mode, bool mirror)
{
	if (!ptedit_initialized)
	{
		if (ptedit_load(true))
		{
			Logger::Log("Failed to load PTEdit for page table manipulation...\n");
			return;
		}

		if (ptedit_init())
		{
			Logger::Log("Failed to open PTEdit device\n");
			return;
		}
		ptedit_initialized = true;
	}
	
	ptedit_entry_t vm = {};
	// the kernel driver is loaded normally (sc start...) and now we want to execute it.
	// driver entry was patched to return 0, to prevents from executing.  Now, it will be emulated in usermode.
	// Need to make 
	if (is_kernel && make_user_mode)
	{
		// make it usermode
		for (int i = 0; i < size; i += 0x1000)
		{
			vm = ptedit_resolve((void*)((uint64_t)image_base + i), 0);
			vm.pml4 |= (1ull << 2);
			vm.pgd |= (1ull << 2);
			vm.pdpt |= (1ull << 2);
			vm.pd |= (1ull << 2);
			vm.pte |= (1ull << 2);
			vm.valid |= PTEDIT_VALID_MASK_PTE;
			vm.valid |= PTEDIT_VALID_MASK_PGD;
			vm.valid |= PTEDIT_VALID_MASK_P4D;
			vm.valid |= PTEDIT_VALID_MASK_PMD;
			vm.valid |= PTEDIT_VALID_MASK_PUD;
			ptedit_update((void*)((uint64_t)image_base + i), 0, &vm);
		}
		mapped_buffer = (unsigned char*)image_base;
		Logger::Log("%s pfn attributes are now usermode.\n", name.c_str());
	}

	if (is_kernel && mirror)
	{
		SIZE_T largePageSize = GetLargePageMinimum();
		SIZE_T calc_size = RoundUpToLargePageSize(size, largePageSize);

		// first page a larger page?  may need to handle case of mix of large/small pages.  currently treats entire buffer as one or the other.
		vm = ptedit_resolve((void*)((uint64_t)image_base), 0);
		if (vm.pmd & PTEDIT_PAGE_BIT_PSE)
		{
			mapped_buffer = (unsigned char*)VirtualAlloc(NULL, calc_size, MEM_RESERVE | MEM_LARGE_PAGES, PAGE_READWRITE);
		}
		else
		{
			mapped_buffer = (unsigned char*)VirtualAlloc(NULL, calc_size, MEM_RESERVE, PAGE_READWRITE);
		}
		
		if (mapped_buffer == NULL)
		{
			DWORD dwError = GetLastError();
			Logger::Log("Unable to allocate memory for usermode! PEFile: %s\n", name.c_str());
			Logger::Log("VirtualAlloc failed with error code %d\n", dwError);
			return;
		}
		
		Logger::Log("Allocated usermode memory for %s at 0x%p\n", name.c_str(), mapped_buffer);
	

		// map the PFN's from the kernel pages to the new usermode pages
		// this way, the usermode pages now reference the actual used host data on the machine
		
		int page_size = 0x1000;
		for (int i = 0; i < size; i += page_size)
		{
			vm = ptedit_resolve((void*)((uint64_t)image_base + i), 0);
			
			// large page?
			if (vm.pmd & PTEDIT_PAGE_BIT_PSE)
			{
				page_size = 0x200000;
				ptedit_entry_t dest_vm = ptedit_resolve((void*)((uint64_t)mapped_buffer + i), 0);
				
				// if it's a large page, the deepest level entry is a pd
				size_t pde = vm.pd;
				size_t pde_pfn = (pde & 0xFFFFFFFFFF000) >> 12;
				auto   dest_vm_pd = (gpt_ptedit_pmd_large_t*)&dest_vm.pd;
				// update dest pfn
				
				*(size_t*)dest_vm_pd |= pde_pfn << 12;

				// dest_vm_pd->pfn = pde_pfn;
				dest_vm_pd->size = 1;
				dest_vm_pd->present = 1;
				ptedit_update((void*)((uint64_t)mapped_buffer + i), 0, &dest_vm);

				// assumes we have a pte?  we don't if we are a large page
				// ptedit_pte_set_pfn(mapped_buffer + i, 0, ptedit_cast(vm.pd, ptedit_pte_t));
			}
			else
			{
				page_size = 0x1000;
				// regular page
				size_t pfn = ptedit_pte_get_pfn((void*)((UINT64)image_base + i), 0);
				if (!pfn)
				{
					Logger::Log("Warning, no pfn found within image bound at 0x%p\n", mapped_buffer);
				}
				ptedit_pte_set_pfn(mapped_buffer + i, 0, pfn);
			}
			
		}
		auto test = (char*)(*mapped_buffer);
		int test2 = 1 + 1;
	}

	if (size)
	{
		this->isExecutable = false;
		this->filename = filename;
		this->name = name;

		ParseHeader();
		ParseSection();
		ParseImport();
		ParseExport();
	}
}

void PEFile::ResolveImport()
{
	if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
		pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
		return;

	PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = makepointer<PIMAGE_IMPORT_DESCRIPTOR>(
		mapped_buffer, pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pImageImportDescriptor->Name; pImageImportDescriptor++)
	{
		PCHAR pDllName = makepointer<PCHAR>(mapped_buffer, pImageImportDescriptor->Name);

		PEFile* importModule = nullptr;
		char	tmpName[256] = {0};
		strcpy_s(tmpName, pDllName);
		for (int nl = 0; nl < strlen(tmpName); nl++)
			tmpName[nl] = tolower(tmpName[nl]);
		if (!moduleList_namekey.contains(tmpName))
		{
			Logger::Log("Loading %s...\n", pDllName);
			importModule = PEFile::Open(std::string(IMPORT_MODULE_DIRECTORY) + pDllName, pDllName);
		}
		else
		{
			importModule = moduleList_namekey[tmpName];
		}
		auto			  modulebase = importModule->GetMappedImageBase();
		PIMAGE_THUNK_DATA pOriginalThunk = NULL;
		if (pImageImportDescriptor->OriginalFirstThunk)
			pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->OriginalFirstThunk);
		else
			pOriginalThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);

		PIMAGE_THUNK_DATA pIATThunk = makepointer<PIMAGE_THUNK_DATA>(mapped_buffer, pImageImportDescriptor->FirstThunk);
		DWORD			  oldProtect = 0;
		MEMORY_BASIC_INFORMATION mbi;
		VirtualQuery(pIATThunk, &mbi, sizeof(mbi));
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect);
		for (; pOriginalThunk->u1.AddressOfData; pOriginalThunk++, pIATThunk++)
		{
			FARPROC lpFunction = NULL;
			if (IMAGE_SNAP_BY_ORDINAL(pOriginalThunk->u1.Ordinal))
			{
				DebugBreak();
			}
			else
			{
				PIMAGE_IMPORT_BY_NAME pImageImportByName =
					makepointer<PIMAGE_IMPORT_BY_NAME>(mapped_buffer, pOriginalThunk->u1.AddressOfData);
				pIATThunk->u1.Function = modulebase + importModule->GetExport(pImageImportByName->Name);
				// Logger::Log("Resolved %s::%s to %llx\n", pDllName, pImageImportByName->Name, pIATThunk->u1.Function);
			}
		}
		VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
	}
}

uint64_t PEFile::GetImageBase()
{
	return imagebase;
}

uint64_t PEFile::GetMappedImageBase()
{
	return (uint64_t)mapped_buffer;
}

uint64_t PEFile::GetVirtualSize()
{
	return virtual_size;
}

ImportData* PEFile::GetImport(std::string name)
{
	if (imports_namekey.contains(name))
	{
		return &imports_namekey[name];
	}
	return 0;
}

ImportData* PEFile::GetImport(uint64_t rva)
{
	if (imports_rvakey.contains(rva))
	{
		return &imports_rvakey[rva];
	}
	return 0;
}

uint64_t PEFile::GetExport(std::string name)
{
	if (name.empty())
		return 0;
	if (exports_namekey.contains(name))
	{
		return exports_namekey[name];
	}
	return 0;
}

const char* PEFile::GetExport(uint64_t rva)
{
	if (exports_rvakey.contains(rva))
	{
		return exports_rvakey[rva].c_str();
	}
	return 0;
}

std::unordered_map<uint64_t, std::string> PEFile::GetAllExports()
{
	return exports_rvakey;
}

uintmax_t PEFile::GetEP()
{
	return entrypoint;
}

__forceinline uint64_t find_pattern(uint64_t start, size_t size, const uint8_t* binary, size_t len)
{
	size_t bin_len = len;
	auto   memory = (const uint8_t*)(start);

	for (size_t cur_offset = 0; cur_offset < (size - bin_len); cur_offset++)
	{
		auto has_match = true;
		for (size_t pos_offset = 0; pos_offset < bin_len; pos_offset++)
		{
			if (binary[pos_offset] != 0 && memory[cur_offset + pos_offset] != binary[pos_offset])
			{
				has_match = false;
				break;
			}
		}

		if (has_match)
			return start + cur_offset;
	}

	return 0;
}

using RtlInsertInvertedFunctionTable = int(__fastcall*)(PVOID BaseAddress, uintmax_t uImageSize);

void PEFile::SetExecutable(bool isExecutable)
{
	this->isExecutable = isExecutable;
	auto sym = symparser::find_symbol("c:\\Windows\\System32\\ntdll.dll", "RtlInsertInvertedFunctionTable");
	if (!sym || !sym->rva)
		__debugbreak();
	auto rtlinsert = reinterpret_cast<RtlInsertInvertedFunctionTable>((uint64_t)LoadLibraryA("ntdll.dll") + sym->rva);
	rtlinsert(mapped_buffer, virtual_size);
}

void PEFile::CreateShadowBuffer()
{
	// MEMORY_BASIC_INFORMATION mbi;
	DWORD oldProtect = 0;
	shadow_buffer = (unsigned char*)_aligned_malloc(this->GetVirtualSize(), 0x10000);
	if (!shadow_buffer)
	{
		Logger::Log("Unable to allocate memory for shadow buffer! PEFile: %s\n", filename.c_str());
		return;
	}
	
	memcpy(shadow_buffer, mapped_buffer, this->GetVirtualSize());
	auto sections = this->sections;
	for (auto section = sections.begin(); section != sections.end(); section++)
	{
		auto sectionName = section->first;
		auto sectionData = section->second;
		if (sectionData.characteristics & 0x80000000 || sectionData.characteristics & 0x40000000)
		{
			if (sectionName != ".edata")
			{
				Logger::Log("Hooking READ/WRITE %s of %s\n", sectionName.c_str(), this->name.c_str());
				VirtualProtect(
					mapped_buffer + sectionData.virtual_address, sectionData.virtual_size, PAGE_NOACCESS, &oldProtect);
			}
		}

		if ((sectionData.characteristics & 0x20000000) || (sectionData.characteristics & 0x00000020))
		{
			Logger::Log("Hooking EXECUTE %s of %s\n", sectionName.c_str(), this->name.c_str());
			VirtualProtect(
				mapped_buffer + sectionData.virtual_address, sectionData.virtual_size, PAGE_READONLY, &oldProtect);
		}
	}

	// Logger::Log("%llx\n", result);
}

uintptr_t PEFile::GetShadowBuffer()
{
	return (uintptr_t)shadow_buffer;
}
void PEFile::SetPermission()
{
	for (int i = 0; i < LoadedModuleArray.size(); i++)
	{
		if (!LoadedModuleArray[i]->isExecutable)
		{
			LoadedModuleArray[i]->CreateShadowBuffer();
		}
	}
}

// disables, enables access of a section that a given address is located in
bool PEFile::SetRead(std::string& mod_name, bool enable, uintptr_t addr)
{
	DWORD oldProtect = 0;
	for (int i = 0; i < LoadedModuleArray.size(); i++)
	{
		if (LoadedModuleArray[i]->name == mod_name)
		{
			auto sections = LoadedModuleArray[i]->sections;
			auto rva = addr - LoadedModuleArray[i]->GetMappedImageBase();
			for (auto section = sections.begin(); section != sections.end(); section++)
			{
				auto sectionName = section->first;
				auto sectionData = section->second;

				if ((rva >= sectionData.virtual_address) &&
					(rva <= (sectionData.virtual_address + sectionData.virtual_size)))
				{
					if (enable)
					{
						Logger::Log(
							"Unhooking r/w of %s of %s\n", sectionName.c_str(), LoadedModuleArray[i]->name.c_str());
						VirtualProtect(LoadedModuleArray[i]->mapped_buffer + sectionData.virtual_address,
									   sectionData.virtual_size,
									   PAGE_READWRITE,
									   &oldProtect);
						return true;
					}
					else
					{
						Logger::Log(
							"Rehooking r/w %s of %s\n", sectionName.c_str(), LoadedModuleArray[i]->name.c_str());
						VirtualProtect(LoadedModuleArray[i]->mapped_buffer + sectionData.virtual_address,
									   sectionData.virtual_size,
									   PAGE_NOACCESS,
									   &oldProtect);
						return true;
						;
					}
				}
			}
		}
	}
	Logger::Log("Unable to locate rva within a section.\n");
	return false;
	DebugBreak();
}

PEFile* PEFile::Open(std::string path, std::string name)
{
	if (!fs::exists(path))
	{
		Logger::Log("Path given is not valid: %s\n", path.c_str());
		DebugBreak();
	}

	auto size = std::filesystem::file_size(path);

	if (size)
	{
		auto loadedModule = new PEFile(path, name, size);
		loadedModule->isExecutable = false;
		LoadedModuleArray.push_back(loadedModule);

		for (auto& c : name)
			c = tolower(c);

		moduleList_namekey.insert(std::pair(name, loadedModule));

		return loadedModule;
	}
	else
	{
		return 0;
	}
}

// on r/w/x, the emulated driver should go to our exception handler.  No need to mark as PAGE_NO_ACCES, PAGE_READ_WRITE
// however, we still need a shadow buffer.
// We allocate our shadow buffer, and assign the PFN's of the kernel module, to our usemode PFN's.
PEFile* PEFile::Open(void* image_base, std::string name, int image_size, bool is_kernel, bool make_user_mode, bool mirror)
{
	if (!image_base)
	{
		Logger::Log("Image base is 0...\n");
		DebugBreak();
	}

	auto size = image_size;

	if (size)
	{
		auto loadedModule = new PEFile(image_base, name, size, is_kernel, make_user_mode, mirror);
		loadedModule->isExecutable = false;
		LoadedModuleArray.push_back(loadedModule);

		for (auto& c : name)
			c = tolower(c);

		moduleList_namekey.insert(std::pair(name, loadedModule));

		return loadedModule;
	}
	else
	{
		return 0;
	}
}
