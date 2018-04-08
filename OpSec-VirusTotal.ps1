#requires -module pssqlite

$SQLite_path = "C:\SysinternalsSuite\hash.sqlite"
.config.ps1

Import-Module PSSQLite

if (-not (Test-Path $SQLite_path))
{
    $Query = "CREATE TABLE Hashes (hash TEXT PRIMARY KEY, path TEXT, status TEXT, count INTEGER)" #size to be changed is different hash used TODO: add lastEntry field
    Invoke-SqliteQuery -Query $Query -DataSource $SQLite_path
}

#get events from sql-lite DB
$eventsDB = @(Invoke-SqliteQuery -DataSource $SQLite_path -Query "SELECT * FROM Hashes")

#get events from event list - created by sysinternals
$timeStamp = Get-Date #timestamp of event capture
$eventsOS = Get-WinEvent -ProviderName 'Microsoft-Windows-Sysmon' | Where-Object id -eq 1 #id for SYSMON event 'Process Create' TODO: startDate and endDate
Write-Debug -Message @($eventsOS).count.ToString()

#group OS events 
$eventsOSgrouped = $eventsOS | Select-Object @{n='hash'; e={$_.properties[15].value.split('=')[1]}}, @{n='path'; e={$_.properties[3].value}}, timeCreated | Group-Object hash

$eventsToProcess = @()
foreach ($evntGroup in $eventsOSgrouped)
{
    $entry = "" | Select-Object hash, path, status, count, lastEntry
    #get hash
    $entry.hash = $evntGroup.name
    $entry.path = $evntGroup.Group[0].path
    $entry.count = $evntGroup.count
    $entry.lastEntry = $evntGroup.group[-1].timeCreated.toOAdate()
    $entry.status = 'new' #TODO: what if already exist in DB and current pass

    #check if existis in eventsDB

    $eventsToProcess += $entry
}
#add new events to DB


#in case of new entries send email