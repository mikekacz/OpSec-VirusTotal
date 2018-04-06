#requires -module pssqlite

$SQLite_path = "C:\SysinternalsSuite\hash.sqlite"
.config.ps1

Import-Module PSSQLite

if (-not (Test-Path $SQLite_path))
{
    $Query = "CREATE TABLE Hashes (hash TEXT PRIMARY KEY, path TEXT, status TEXT, count INTEGER)" #size to be changed is different hash used
    Invoke-SqliteQuery -Query $Query -DataSource $SQLite_path
}

#get events from sql-lite DB
$eventsDB = @(Invoke-SqliteQuery -DataSource $SQLite_path -Query "SELECT * FROM Hashes")

#get events from event list - created by sysinternals
$timeStamp = Get-Date #timestamp of event capture
$eventsOS = Get-WinEvent -ProviderName 'Microsoft-Windows-Sysmon' | Where-Object id -eq 1 #id for SYSMON event 'Process Create' TODO: startDate and endDate
Write-Debug -Message @($eventsOS).count.ToString()

#group OS events 
$eventsOSgrouped = $eventsOS | Select-Object @{n='hash'; e={$_.properties[15].value.split('=')[1]}}, @{n='path'; e={$_.properties[3].value}} | Group-Object hash

# foreach ($evnt in $eventsOS)
# {
#     $entry = "" | Select-Object hash, path, status, count
#     #get hash
#     $entry.hash =''
#     $entry.path =''
#     $entry.status = 'new' #TODO: what if already exist in DB and current pass

# }
#add new events to DB


#in case of new entries send email