![alt text](https://drive.google.com/uc?export=view&id=1qgfpXdotNpEWSKo2I_O2puZFFBchPjrG)

# <p align="center">Driver Buddy</p>

## Emulation Flow

* A helper driver is loaded first *DriverBuddy(tm)*
  - Intercepts driver loading with a registered load handler and patches DriverEntry temporarily to skip kernel exeuction
  - Modifies PTE entries of loaded driver to be usermode pages 

* The 'emulated' kernel driver is now legitimately loaded into kernel memory.
  - This allows the kernel structures of the driver to now be created normally.
  - Driver now has real kernel addresses.  This circumvents checks to see if it's running in userland by checking $RIP

* Imports are mapped to the real kernel functions.
  - Again circumvents checks that could be made by the Driver to infer the environment it's running in.

* DriverEntry to be emulated is patched to return before it's instrumented by us.
  - In order to instrument the loaded kernel driver with Kace, the PTE's of the driver are changed to usermode.

* Bug fixes and improvements
  - Some improvements to reimplementations of Nt/ZwSystemQueryInfo which allows you to filter out/hide your other loaded driver's (implemented with old method, but filtering will be needed later on again for new method)

## Functional Diagram
![alt text](https://drive.google.com/uc?export=view&id=1yxhjL3jBhpJIJbLO9AvpUxS4kEja9qJs)


## Developer Guide

### Requirements
Note: May be preferred to run in VM during some kernel related debugging and development.  (Will run MUCH slower depending on HW)

- OS: Windows 10 22H2 Build 19045 (some builds may have issues finding symbols from msft servers, which Kace depends on for logging)
- IDE: VS2022, Windows 10 SDK 10.0.22621.0
- Dependecies:  [WDK 10.0.22621](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

*Make sure Visual Studio is always ran as administrator when running Kace through VS's debugger!*


### VCPKG configuration
Make sure you have vcpkg included in VS2022 installation (should be installed by default)

Note: If you go into Kace project configuration properties and there isn't an option for vcpkg, then run `vcpkg integrate install` in Developer Powershell and restart VS.

1. In Developer Powershell, root project directory `vcpkg x-update-baseline --add-initial-baseline`, then `vcpkg install`  (enables baseline feature)

You should now be able to `Build Solution`

### Windows configuration

In an elevated shell:
- Enable test signing `bcdedit /set testsigning on` (to load unsigned drivers)
- Enable kernel debugging `bcdedit /debug on` (needed in some cases when unable to load an unsigned driver)
- Add user to 'Lock pages in memory' local policy  (allows large page allocations in usermode)
    * windows key + R: `secpol.msc`
    * Local Policies -> User Rights Assignment -> Lock pages in memory
    * Add your account

### Additional Project Configuration

In Visual Studio KACE project properties update *Debugging->Command Arguments* to `c:\emu\BEDaisy.sys load_only_emu_mods use_buddy`

### Emulating BattleEye

 - Run the Regedit file `BEDaisy.reg` (project root). This provides the driver configuration settings for scm to load BEDaisy.
 - Go into `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BEDaisy` and change `ImagePath` to the path where BEDaisy.sys is located.  E.g. `c:\emu\BEDaisy.sys`

## Development and Debugging

When running in VS Debugger, in Exception Settings disable `0xc000005 Access Violation` else the debugger will break on access violations to variables that are tracked.

Use an up to date Windows 10 Build.  Tested on Build 19044.

## General Usage
Specify a path for driver you want to emulate.  Optional flag `load_only_emu_mods` will only load modules in `C:\emu\` folder.
```shell
.\KACE.exe <path_to_driver>  [load_only_emu_mods]
```

## Credits

Waryas for base concept and code.
