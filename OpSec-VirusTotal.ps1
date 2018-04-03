#requires -module pssqlite

$SQLite_path = "C:\SysinternalsSuite\hash.sqlite"
$timeStamp = Get-Date

Import-Module PSSQLite

if (-not (Test-Path $SQLite_path))
{
    $Query = "CREATE TABLE NAMES (hash TEXT PRIMARY KEY, path TEXT, status TEXT, count INTEGER)" #size to be changed is different hash used
    Invoke-SqliteQuery -Query $Query -DataSource $SQLite_path
}

#get events from event list - created by sysinternals
$events = Get-WinEvent -ProviderName 'Microsoft-Windows-Sysmon' | ? id -eq 1

#get sql-lite DB


#add new events to DB


#in case of new entries send email