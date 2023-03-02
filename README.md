![alt text](https://drive.google.com/uc?export=view&id=1qgfpXdotNpEWSKo2I_O2puZFFBchPjrG)

# Anti Cheat Buddy
Continuation of the original KACE project from waryas and friends


## Functional Diagram
![alt text](https://drive.google.com/uc?export=view&id=1yxhjL3jBhpJIJbLO9AvpUxS4kEja9qJs)


## Developer Guide
Specify a path for driver you want to emulate.  Optional flag `load_only_emu_mods` will only load modules in `C:\emu\` folder.
```shell
.\KACE.exe <path_to_driver>  [load_only_emu_mods]
```

When running in VS Debugger, in Exception Settings disable `0xc000005 Access Violation` else the debugger will break on access violations to variables that are tracked.

Use an up to date Windows 10 Build.  Tested on Build 19044.
