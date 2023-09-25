<#
   Interesting events derived from NSA's Spotting the Adversary document:
   https://apps.nsa.gov/iaarchive/library/ia-guidance/security-configuration/applications/assets/public/upload/Spotting-the-Adversary-with-Windows-Event-Log-Monitoring.pdf 

   In addition to NSA's STA document, this script also looks for logon activity outside of normal hours
#>

########################### Section 1: Gather logs ###############################
###--->>> Set up environment
$computers = $args[0]

if(!$args){
    Write-Output "You have not supplied any arguments for computers to scan.  Defaulting to localhost for computer."
    $computers = "localhost"
}

foreach($a in $args){
    if($a -eq '-maximumnoise'){
        $maximumnoise = $True
        Write-Output "Running in maximum noise mode.  Re-run without -maximum flag if you wish to view minimal output, excluding logs with S-1-0-0, S-1-5-18, and new kernel filter driver events."
        Read-Host -Prompt "Press any key to continue..."
    }
}

if(!$minimalnoise){
    write-output "Running in minimum noise mode.  Re-run with -maximumnoise flag to filter out common logon SIDs and kernel filter driver events."
    Read-Host -Prompt "Press any key to continue..."
}

###--->>> Main function
function getInterestingEvents ( $computer ) {

    write-host "Gathering logs on: "
    write-host $computer

    ###--->>> Getting interesting security events

    # Spotting the adversary, page 26, section 4.5
    $windowsfirewallevents = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -FilterHashTable @{ LogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"; ID = 2004,2005,2006,2033,2009 } | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($windowsfirewallevents){ 
        $windowsfirewallevents | foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Windows Firewall Events" 
        }
    }

    # Spotting the adversary, page 30, section 4.11
    # JPK: 9-4-2022. Removed event id 2001, because PCN and PIN systems cannot retrieve Defender updates via the Internet due to our firewall
    #$windowsdefenderevents = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -FilterHashTable @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; ID = 1005,1006,1008,1010,2001,2003,2004,3002,5008 } | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    $windowsdefenderevents = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -FilterHashTable @{ LogName = "Microsoft-Windows-Windows Defender/Operational"; ID = 1005,1006,1008,1010,2003,2004,3002,5008 } | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($windowsdefenderevents){ 
        $windowsdefenderevents | foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Windows Defender Events" 
        }
    }

    # Spotting the adversary, page 32, section 4.15
    $successfulptheventspin = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -ProviderName 'Microsoft-Windows-Security-Auditing' `
    -FilterXPath "*[System[EventID=4624] and System[Level=4 or Level=0] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM'] and EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON'] and EventData[Data[@Name='TargetDomainName']!='AMPINANC']]" `
    | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($successfulptheventspin){
        $successfulptheventspin = foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Successful Pass The Hash Events PIN" 
        }
    }

    # Spotting the adversary, page 32, section 4.15
    $successfulptheventspcn = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -ProviderName 'Microsoft-Windows-Security-Auditing' `
    -FilterXPath "*[System[EventID=4624] and System[Level=4 or Level=0] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM'] and EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON'] and EventData[Data[@Name='TargetDomainName']!='PRBATM.PCN']]" `
    | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($successfulptheventspcn){
        $successfulptheventspcn | foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Successful Pass The Hash Events PCN" 
        }
    }

    # Spotting the adversary, page 33, section 4.15
    $failedptheventspin = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -ProviderName 'Microsoft-Windows-Security-Auditing' `
    -FilterXPath "*[System[EventID=4624] and System[Level=4 or Level=0] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM'] and EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON'] and EventData[Data[@Name='TargetDomainName']!='AMPINANC']]" `
    | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($failedptheventspin){
        $failedptheventspin = foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Failed Pass The Hash Events PIN" 
        }
    }

    # Spotting the adversary, page 33, section 4.15
    $failedptheventspcn = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -ProviderName 'Microsoft-Windows-Security-Auditing' `
    -FilterXPath "*[System[EventID=4624] and System[Level=4 or Level=0] and EventData[Data[@Name='LogonType']='3'] and EventData[Data[@Name='AuthenticationPackageName']='NTLM'] and EventData[Data[@Name='TargetUserName']!='ANONYMOUS LOGON'] and EventData[Data[@Name='TargetDomainName']!='PRBATM.PCN']]" `
    | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($failedptheventspcn){
        $failedptheventspcn | foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Failed Pass The Hash Events PCN" 
        }
    }

    # Spotting the adversary, page 34, section 4.16
    $rdpconnections = Get-WinEvent -ErrorAction Silentlycontinue -computername $computer -ProviderName 'Security' `
    -FilterXPath "*[System[EventID=4624 or EventID=4634] and System[Level=4 or Level=0] and EventData[Data[@Name='LogonType']='10'] and EventData[Data[@Name='AuthenticationPackageName']='Negotiate']]" `
    | Select TimeCreated, Id, Message, LogName, MachineName, UserId
    if($rdpconnections){
        $rdpconnections | foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "RDP Connections" 
        }
    }

    if ($maximumnoise){
        # Not specifically in STA document, but logons outside of business hours should be scrutinized 
        #   Suspicious user activity is covered in Spotting The Adversary, page 28, section 4.8 
        $abnormaltimeevents = Get-EventLog -ErrorAction Silentlycontinue -LogName Security -computername $computer | ?{
                # Show events that are outside of business hours `
                #Midnight to 3:59AM
                $_.TimeGenerated -match "0[0-3]:[0-5][0-9]:[0-5][0-9]" `
            -or `
                #6:30PM to 7:59PM
                $_.TimeGenerated -match "1[8-9]:[3-5][0-9]:[0-5][0-9]" `
            -or `
                #8PM to Midnight
                $_.TimeGenerated -match "2[0-3]:[0-5][0-9]:[0-5][0-9]" `
            -and `
            ( `
                    # Account login with explicit credentials `
                    $_.InstanceID -like '4648' `
                -or `
                    # Failed User account login `
                    $_.InstanceID -like '4625' `
                -or `
                    # Successful user account login `
                    $_.InstanceID -like '4624' `
            ) `
            -and `
            (
                    # SID is NOT S-1-0-0 or S-1-5-18
                    # https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
                    # https://superuser.com/questions/890347/windows-security-log-shows-mysterious-user-logins
                    $_.Message -notmatch 'S-1-0-0' `
                -and `
                    $_.Message -notmatch 'S-1-5-18' `
            ) `
        } `
        | Select TimeGenerated, InstanceID, Message, Source, MachineName, username
        if($abnormaltimeevents){
            $abnormaltimeevents | foreach-object{ 
                Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Abnormal Time Events" 
            }
        }
    }
    else
    { 
        # Not specifically in STA document, but logons outside of business hours should be scrutinized 
        #   Suspicious user activity is covered in Spotting The Adversary, page 28, section 4.8 
        $abnormaltimeevents = Get-EventLog -ErrorAction Silentlycontinue -LogName Security -computername $computer | ?{
                # Show events that are outside of business hours `
                #Midnight to 3:59AM
                $_.TimeGenerated -match "0[0-3]:[0-5][0-9]:[0-5][0-9]" `
            -or `
                #6:30PM to 7:59PM
                $_.TimeGenerated -match "1[8-9]:[3-5][0-9]:[0-5][0-9]" `
            -or `
                #8PM to Midnight
                $_.TimeGenerated -match "2[0-3]:[0-5][0-9]:[0-5][0-9]" `
            -and `
            ( `
                    # Account login with explicit credentials `
                    $_.InstanceID -like '4648' `
                -or `
                    # Failed User account login `
                    $_.InstanceID -like '4625' `
                -or `
                    # Successful user account login `
                    $_.InstanceID -like '4624' `
            ) `
        } `
        | Select TimeGenerated, InstanceID, Message, Source, MachineName, username
        if($abnormaltimeevents){
            $abnormaltimeevents | foreach-object{ 
                Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Abnormal Time Events" 
            }
        }
    }

    if($maximumnoise){
        $secevents = Get-EventLog -ErrorAction Silentlycontinue -LogName Security -computername $computer | ?{
                    # Spotting the adversary, page 28, section 4.8 `
                    # Security-enabled group modification `
                    $_.InstanceID -like '4735' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # User added to privileged group `
                    $_.InstanceID -like '4728' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # User added to privileged group `
                    $_.InstanceID -like '4732' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # User added to privileged group `
                    $_.InstanceID -like '4756' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # Account lockout `
                    $_.InstanceID -like '4740' `
                -or `
                    # Spotting the adversary, page 26, section 4.6 `
                    # Audit Log was cleared `
                    $_.InstanceID -like '1102' `
                -or `
                    # Spotting the adversary, page 29, section 4.9 `
                    # Detected an invalid image hash of a file `
                    $_.InstanceID -like '5038' `
                -or `
                    # Spotting the adversary, page 29, section 4.9 `
                    # Detected an invalid page hash of an image file `
                    $_.InstanceID -like '6281' `
                -and `
                (
                        # SID is NOT S-1-0-0 or S-1-5-18
                        # https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
                        # https://superuser.com/questions/890347/windows-security-log-shows-mysterious-user-logins
                        $_.Message -notmatch 'S-1-0-0' `
                    -and `
                        $_.Message -notmatch 'S-1-5-18' `
                ) `
        } `
        | Select TimeGenerated, InstanceID, Message, Source, MachineName
        if($secevents){
            $secevents | foreach-object{ 
                Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Security Log Events" 
            }
        }
    }
    else {
        $secevents = Get-EventLog -ErrorAction Silentlycontinue -LogName Security -computername $computer | ?{
                    # Spotting the adversary, page 28, section 4.8 `
                    # Security-enabled group modification `
                    $_.InstanceID -like '4735' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # User added to privileged group `
                    $_.InstanceID -like '4728' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # User added to privileged group `
                    $_.InstanceID -like '4732' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # User added to privileged group `
                    $_.InstanceID -like '4756' `
                -or `
                    # Spotting the adversary, page 28, section 4.8 `
                    # Account lockout `
                    $_.InstanceID -like '4740' `
                -or `
                    # Spotting the adversary, page 26, section 4.6 `
                    # Audit Log was cleared `
                    $_.InstanceID -like '1102' `
                -or `
                    # Spotting the adversary, page 29, section 4.9 `
                    # Detected an invalid image hash of a file `
                    $_.InstanceID -like '5038' `
                -or `
                    # Spotting the adversary, page 29, section 4.9 `
                    # Detected an invalid page hash of an image file `
                    $_.InstanceID -like '6281' `
        } `
        | Select TimeGenerated, InstanceID, Message, Source, MachineName
        if($secevents){
            $secevents | foreach-object{ 
                Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "Security Log Events" 
            }
        }
    }
    ###--->>> Getting interesting application events
    $appevents = Get-EventLog -ErrorAction Silentlycontinue -LogName Application -computername $computer | ?{
            # Spotting the adversary, page 27, section 4.7 `
            # New Application Installation `
            $_.InstanceID -like '903' `
        -or `
            # Spotting the adversary, page 27, section 4.7 `
            # New Application Installation `
            $_.InstanceID -like '904' `
        -or `
            # Spotting the adversary, page 27, section 4.7 `
            # New Application Installation `
            $_.InstanceID -like '907' `
        -or `
            # Spotting the adversary, page 27, section 4.7 `
            # New Application Installation `
            $_.InstanceID -like '908' `
    } `
    | Select TimeGenerated, InstanceID, Message, Source, MachineName, username
    if($appevents){
        $appevents | foreach-object{ 
            Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "App Log Events" 
        }
    }

    ###--->>> Getting interesting system events
    if($minimalnoise){
            $sysevents = Get-EventLog -ErrorAction Silentlycontinue -LogName System -computername $computer | ?{
                # Spotting the adversary, page 26, section 4.6 `
                # Event log was cleared `
                $_.InstanceID -like '104' `
            -or `
                # Spotting the adversary, page 27, section 4.7 `
                # New Windows Service `
                $_.InstanceID -like '7045' `
            -or `
                # Spotting the adversary, page 29, section 4.9 `
                # Failed Kernel Driver loading `
                $_.InstanceID -like '219' `
        } `
        | Select TimeGenerated, InstanceID, Message, Source, MachineName, username
        if($sysevents){
            $sysevents | foreach-object{ 
                Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "System Log Events" 
            }
        }
    }
    else{
            $sysevents = Get-EventLog -ErrorAction Silentlycontinue -LogName System -computername $computer | ?{
                # Spotting the adversary, page 26, section 4.6 `
                # Event log was cleared `
                $_.InstanceID -like '104' `
            -or `
                # Spotting the adversary, page 27, section 4.7 `
                # New Kernel Filter Driver `
                $_.InstanceID -like '6' `
            -or `
                # Spotting the adversary, page 27, section 4.7 `
                # New Windows Service `
                $_.InstanceID -like '7045' `
            -or `
                # Spotting the adversary, page 29, section 4.9 `
                # Failed Kernel Driver loading `
                $_.InstanceID -like '219' `
        } `
        | Select TimeGenerated, InstanceID, Message, Source, MachineName, username
        if($sysevents){
            $sysevents | foreach-object{ 
                Add-member -InputObject $_ -NotePropertyName "SpottingTheAdversaryType" -NotePropertyValue "System Log Events" 
            }
        }
    }

    $allevents = $secevents + $appevents + $sysevents + $abnormaltimeevents + $windowsdefenderevents + $successfulptheventspcn + $successfulptheventspin + $failedptheventspcn + $failedptheventspin + $rdpconnections

    $allevents | export-csv -path "$($computer)_suspiciousevents.csv" -NoTypeInformation
}

foreach ($comp in $computers) {
    getInterestingEvents $comp
}

########################### Section 2: Cleanup ###############################
###--->>> Format spreadsheets, convert to XLSX and then clean up old CSV files 
$files = gci | where-object { $_.name -match "\.csv" }

function Save-CSVasExcel ($file) {
        $CSVFile = $file
    
        function Resolve-FullPath ([string]$Path) {    
            if ( -not ([System.IO.Path]::IsPathRooted($Path)) ) {
                # $Path = Join-Path (Get-Location) $Path
                $Path = "$PWD\$Path"
            }
            [IO.Path]::GetFullPath($Path)
        }

        function Release-Ref ($ref) {
            ([System.Runtime.InteropServices.Marshal]::ReleaseComObject([System.__ComObject]$ref) -gt 0)
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
        
        $CSVFile = Resolve-FullPath $CSVFile
        $xl = New-Object -ComObject Excel.Application

        $wb = $xl.workbooks.open($CSVFile)
        $xlOut = $CSVFile -replace '\.csv$', '.xlsx'
        
        # can comment out this part if you don't care to have the columns autosized
        $ws = $wb.Worksheets.Item(1)
        $range = $ws.UsedRange 
        [void]$range.EntireColumn.Autofit()

        $num = 1
        $dir = Split-Path $xlOut
        $base = $(Split-Path $xlOut -Leaf) -replace '\.xlsx$'
        $nextname = $xlOut
        while (Test-Path $nextname) {
            $nextname = Join-Path $dir $($base + "-$num" + '.xlsx')
            $num++
        }

        $wb.SaveAs($nextname, 51)

        $xl.Quit()
        $null = $ws, $wb, $xl | % {Release-Ref $_}
}

foreach ($f in $files ) {
    Save-CSVasExcel $f
    Remove-Item $f
}
