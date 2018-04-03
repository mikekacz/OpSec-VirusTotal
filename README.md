# OpSec-VirusTotal.ps1

Script that get hashes of the files that run on the system (SysMon), saves the to DB (SQLite) and then checks with VirusTotal.

## Requirements

* Install SysMon

Register SysMon service

```cmd
Sysmon.exe -accepteula -i -h md5 -l
```

* Install SQLite module

from https://github.com/RamblingCookieMonster/PSSQLite

```Powershell
install-module pssqlite
```