# OpSec-VirusTotal.ps1

## Requirements

* Install SysMon

see Sysinternals
Register SysMon service

```cmd
Sysmon.exe -accepteula -i -h md5 -l
```

* Install SQLite module

see https://github.com/RamblingCookieMonster/PSSQLite

```Powershell
install-module pssqlite
```