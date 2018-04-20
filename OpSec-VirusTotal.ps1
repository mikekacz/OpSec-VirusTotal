#requires -module pssqlite
#requires -runAsAdministrator

$SQLite_path = "C:\SysinternalsSuite\hash.sqlite"
.\config.ps1

Import-Module PSSQLite

function Find-ItemInDB
{
    Param ($hash)

    $isIn = $hash -in $eventsDBhash
    if ($isIn)
    { return 'exists'}
    else { return 'not exists'}
}

function Get-VTFileReport
{
    param ($hash)
    if ($virusTotalAPIkey -eq '') {throw "VT API key missing"}

    $URI = 'https://www.virustotal.com/vtapi/v2/file/report?apikey='+$virusTotalAPIkey+'&resource='+$hash
    try 
    {
        $response = Invoke-WebRequest -uri $uri -Method get
        $data = $response.content | ConvertFrom-Json
    }
    catch 
    { 
        $response = new-object psobject -property @{'StatusCode' = 000}
        $data = new-object psobject -property @{'positives' = ''; 'total' = ''; 'permalink' = '' }
    }

    if ($response.StatusCode -eq 200)
    {
        $status = "OK"
        if ($data.positives -lt $positivesThreshold) {$result = 'Clean'} else {$result = 'NOT Clean'}
    }
    else {
        $status = "try later"
        $result = 'not checked'
    }

    return new-object psobject -property @{'status' = $status; 'result' = $result; 'positives' = $data.positives ; 'total' = $data.total ;'permalink' = $data.permalink }
}

if (-not (Test-Path $SQLite_path)) #create DB file if not existing
{
    $Query = "CREATE TABLE Hashes (hash TEXT PRIMARY KEY, path TEXT, count INTEGER, result TEXT, positives INTEGER, total INTEGER, permalink TEXT, lastEntry FLOAT)"  #Table to store hashes
    Invoke-SqliteQuery -Query $Query -DataSource $SQLite_path
    $query = "CREATE TABLE Log (lastEntry FLOAT PRIMARY KEY, status TEXT)" #Table to store each run
    Invoke-SqliteQuery -Query $Query -DataSource $SQLite_path
}

#get events from sql-lite DB
$eventsDB = @(Invoke-SqliteQuery -DataSource $SQLite_path -Query "SELECT * FROM Hashes")
$eventsDBhash = @($eventsDB.hash)
$eventsDBlog = Invoke-SqliteQuery -DataSource $SQLite_path -Query "SELECT * FROM Log WHERE lastEntry = (SELECT MAX(lastEntry) FROM Log);" 

#get events from event list - created by sysinternals
if ($eventsDBlog -eq $null) {$startDate = [Datetime]::MinValue} else {$startDate= [Datetime]::FromOADate($eventsDBlog.lastEntry)}
$endDate = Get-Date #timestamp of event capture

#id for SYSMON event 'Process Create'
$eventsOS = Get-WinEvent -FilterHashtable @{ProviderName="Microsoft-Windows-Sysmon"; ID='1'; StartTime=$startDate; EndTime = $endDate}
Write-Debug -Message @($eventsOS).count.ToString()

$query = "INSERT INTO Log (lastEntry, status) VALUES ($($endDate.toOADate()),'test' )"
Invoke-SqliteQuery -DataSource $SQLite_path -Query $query

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
    $entry.status = Find-ItemInDB -hash $entry.hash

    $eventsToProcess += $entry
}

#check hashes
$i = 0
foreach ($newEvent in $eventsToProcess)
{
    Write-Progress -Activity "checking hashes" -CurrentOperation $newEvent.path -PercentComplete $($i*100/$eventsToProcess.count)
    $i++
    if ($newEvent.status -eq 'exists')
    {
        #find item in DB
        $index = $eventsDBhash.IndexOf($newEvent.hash)
        $newEvent.status = "to be updated in DB"
        $newEvent.count += $eventsDB[$index].count

        #update items in DB
        $query = "UPDATE Hashes SET count='$($newEvent.count)', lastEntry='$($newEvent.lastEntry)' WHERE hash='$($newEvent.hash)';"        
        Invoke-SqliteQuery -DataSource $SQLite_path -Query $query
    }
    elseif ($newEvent.status -eq 'not exists')
    {
        $newEvent | add-member -membertype noteproperty -name result -value $null
        $newEvent | add-member -membertype noteproperty -name positives -value $null
        $newEvent | add-member -membertype noteproperty -name total -value $null
        $newEvent | add-member -membertype noteproperty -name permalink -value $null

        do {
            $hashInfo = Get-VTFileReport -hash $newEvent.hash
            if ($hashInfo.status -ne 'OK') {Start-Sleep -Seconds $virusTotalCheckFrequency}
            else {
                $newEvent.status = "to be added to DB"
                $newEvent.result = $hashInfo.result
                $newEvent.positives = $hashInfo.positives
                $newEvent.total = $hashInfo.total
                $newEvent.permalink = $hashInfo.permalink
                if ($newEvent.result -ne "Clean") {Write-Warning -Message $($newEvent.path)}
            }
        } until ($hashInfo.status -eq 'OK')

        #add new items to DB
        $query = "INSERT INTO Hashes (hash, path, count, lastEntry, result, positives, total, permalink) VALUES ('$($newEvent.hash)', '$($newEvent.path)', '$($newEvent.count)', '$($newEvent.lastEntry)', '$($newEvent.result)', '$($newEvent.positives)', '$($newEvent.total)', '$($newEvent.permalink)')"
        $Query
        Invoke-SqliteQuery -DataSource $SQLite_path -Query $query
    }
    else
    {
        
    }
} #foreach

#in case of new entries send email
$eventsToProcess | Where-Object ($_.result -ne 'Clean') {
    #send email
    
}