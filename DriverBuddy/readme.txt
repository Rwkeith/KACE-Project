## Setup

Enable test signing and reboot

`bcdedit /set testsigning on`


Currently set to load BEDaisy.  Put built DriveryBuddy.sys in the KACE\KACE\ project folder

Put BEDaisy.sys in the system root, C:\ directory



Dev Helpers:
`sc create sample type= kernel binPath= C:\<SubPath>\KACE\KACE\Driver.sys`

`sc create BEDaisy type= kernel binPath= C:\BEDaisy.sys`

sc start sample
sc stop sample
