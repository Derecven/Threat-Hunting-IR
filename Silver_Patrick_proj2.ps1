<#
 6677 - Threat Hunting and Incident Response
 Author: Patrick G. Silver
 Last Update: 4/18/2023
 File: Silver_Patrick_proj2.txt

 Description: PowerShell script: Retreives data from a Windows-based computer to be used for IR purposes
              Prompts investigator for their name, case #/description, and preferred output path/name for the report
              Run-Time: During test it took approximately 2 minutes to run

              * RUN AS ADMINISTRATOR *
#>

#*************** REFERENCES ***************
#https://learn.microsoft.com/en-us/dotnet/api/microsoft.visualbasic.interaction?redirectedfrom=MSDN&view=net-7.0#methods
#https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-path?view=powershell-7.3 
#https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/start-job?view=powershell-7.3
#https://learn.microsoft.com/en-us/dotnet/api/system.io.directory?view=net-7.0

#*************** EXECUTION POLICY ***************
# Checks the Execution Policy on the machine, set to Unrestricted (Reverts at the end of script)
<#
$currentExecutionPolicy = Get-ExecutionPolicy

# If the execution policy is not Unrestricted, set it to Unrestricted
if ($currentExecutionPolicy -ne "Unrestricted") {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -ErrorAction Continue
    Write-Host "Execution policy has been set to Unrestricted."
} else {
    Write-Host "Execution policy is already Unrestricted."
}
#>

<#
   ******************** EVENT ID LIST ***********************
    Event ID 4625: Failed logon attempt to the system
    Event ID 4648: Successful logon with alternate credentials
    Event ID 4634: Successful logon to the system
    Event ID 4720 and 4742: User or computer account created
    Event ID 4732: User added to security group
    Event ID 4688: Process created on the system
    Event ID 4103: PowerShell pipeline executed with user context
    Event ID 4104: PowerShell script blocked from execution
    Event ID 7035, 7045: Service Control Manager status change
    Event ID 1074: System Shutdown or Restart initiated.
#>

#*************** VARIABLES ***************

[void][Reflection.Assembly]::LoadWithPartialName("Microsoft.VisualBasic") #Function to simplify calls for prompt boxes 

$PSVERSION = $PSVersionTable.PSVersion.ToString()   # POWERSHELL VERSION 
$DATE = Get-Date                                    # DATE AND TIME
$TIMEZONE = [TimeZoneInfo]::Local.DisplayName       # TIME ZONE
$COMPUTERNAME = $env:COMPUTERNAME                   # COMPUTER NAME

$DAYS = "-30"                                       #Get-EventLog filtering (How many days back?)
$NEWEST_NUM = 15                                    #How many of those filtered entries should show?

#Event ID Lists - What event log IDs are searched 
$EVENT_IDS_SECURITY = @(4624, 4625, 4648, 4634, 4720, 4742, 4732, 4688) 
$EVENT_IDS_SYSTEM = @(7035, 7045, 1074)
$EVENT_IDS_POWERSHELL = @(4103, 4104)

# INVESTIGATOR NAME
$msgBody = "Enter your name: "
$msgTitle = "Investigator Name Entry"
$INVESTIGATOR = [Microsoft.VisualBasic.Interaction]::InputBox($msgBody,$msgTitle)  #INVESTIGATOR NAME

# DESCRIPTION
$msgBody = "Description/Case # for which the report is being created: "
$msgTitle = "Description Entry"
$DESCRIPTION = [Microsoft.VisualBasic.Interaction]::InputBox($msgBody,$msgTitle)   #REPORT DESCRIPTION

# OUTPUT FILE NAME
$msgBody = "Enter the report file path and report name (e.g C:\output.txt): "
$msgTitle = "Report Output Path Entry"
$OUTPUT_FILE = [Microsoft.VisualBasic.Interaction]::InputBox($msgBody,$msgTitle)   #OUTPUT FILE PATH


#*************** HEADER/FILE CREATION ***************

$DIRECTORY_PATH = Split-Path -Path $OUTPUT_FILE -Parent
if (-not (Test-Path -Path $DIRECTORY_PATH)) {
    New-Item -ItemType Directory -Path $DIRECTORY_PATH  # Create the directory path if investigator's provided path does not exist
}


if (-not (Test-Path -Path $OUTPUT_FILE)) {
    New-Item -ItemType File -Path $OUTPUT_FILE          # Create the output file if it does not exist

} else {
        # IF THE FILE DOES EXIST PROMPT TO OVERWRITE
        $msgBoxButtons = New-Object System.Windows.Forms.MessageBoxButtons
        $msgBoxResult = [System.Windows.Forms.MessageBox]::Show("The output file already exists. Do you want to overwrite it?", "Overwrite Confirmation", $msgBoxButtons::YesNo, [System.Windows.Forms.MessageBoxIcon]::Question)

        if ($msgBoxResult -ne "Yes") {    # IF THE USER DOES NOT WANT TO OVERWRITE, exit the script (Does not overwrite the file)
            [System.Windows.Forms.MessageBox]::Show(" File not overwritten. Operation canceled.", "Overwrite Prompt", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            exit
        } else {
        # IF USER WANTS TO OVERWRITE FILE, CLEAR FILE CONTENTS
        Clear-Content $OUTPUT_FILE #Clears content of file, but item remains 
        }
}

#$rootDir = ([IO.DirectoryInfo] $OUTPUT_FILE).Parent    #Root directory of user specified input file
#echo $rootDir.FullName

function Write-Report-Header{

    # Header Information
    Write-Output "Computer name:  $COMPUTERNAME" | Out-File  $OUTPUT_FILE -Append 
    Write-Output "Date and Time:  $DATE"         | Out-File  $OUTPUT_FILE -Append
    Write-Output "Time Zone:      $TIMEZONE"     | Out-File  $OUTPUT_FILE -Append
    Write-Output "Investigator:   $INVESTIGATOR" | Out-File  $OUTPUT_FILE -Append
    Write-Output "Report output:  $OUTPUT_FILE"  | Out-File  $OUTPUT_FILE -Append
    Write-Output "PS Version:     $PSVERSION"    | Out-File  $OUTPUT_FILE -Append
    Write-Output "Description:    $DESCRIPTION"  | Out-File  $OUTPUT_FILE -Append
}


#*************** FUNCTIONS ***************

function Get-ComputerDataInfo {

    Write-Output "`n******** Computer Info ********" | Out-File $OUTPUT_FILE -Append
    Get-ComputerInfo | Out-File $OUTPUT_FILE -Append #Grabs generic computer info 

    Write-Output "******** BIOS Info ********" | Out-File $OUTPUT_FILE -Append
    Get-WmiObject -class Win32_BIOS | Out-File $OUTPUT_FILE -Append

    Write-Output "******** Storage Drives ********" | Out-File $OUTPUT_FILE -Append
    Get-CimInstance -ClassName Win32_LogicalDisk | Out-File $OUTPUT_FILE -Append

    # Grab machine's patch/hotfix history - checks for antivirus
    Write-Output "******** Hotfixes/Patches ********" | Out-File $OUTPUT_FILE -Append
    Get-HotFix | Out-File $OUTPUT_FILE -Append

    # Gets a list of running processes and sorts by start time 
    Write-Output "******** Process list ********" | Out-File $OUTPUT_FILE -Append
    Get-Process | 
        Select-Object `
            ID,
            ProcessName,
            StartTime,
            Path | 
        Sort-Object StartTime -Descending |
        Format-Table `
            @{Label="ID"; Expression={$_.ID}; Width=8},
            @{Label="Process Name"; Expression={$_.ProcessName}; Width=23},
            @{Label="Start Time"; Expression={$_.StartTime}; Width=23},
            @{Label="Path"; Expression={$_.Path}; Width=90} | 
        Out-File $OUTPUT_FILE -Append

    # Gets a list of child processes and their corresponding parent processes (shows IDs)
    Write-Output "******** Parent/Children Process IDs ********" | Out-File $OUTPUT_FILE -Append
    Get-CIMInstance -ClassName win32_process |
        Select ProcessID, ParentProcessID | 
        Format-Table -Auto |
    Out-File $OUTPUT_FILE -Append

    # Gets a list of services
    Write-Output "******** Service list ********" | Out-File $OUTPUT_FILE -Append
    Get-Service | 
        Select-Object `
            Status,
            StartType,
            Name,
            DisplayName |
        Sort-Object Status -Descending | 
        Format-Table -AutoSize |
        Out-File $OUTPUT_FILE -Append
        
    # Check for new scheduled tasks
    Write-Output "******** Scheduled Tasks ********" | Out-File $OUTPUT_FILE -Append
    Get-ScheduledTask | 
        Select-Object `
            Taskname,
            TaskPath,
            State,
            Author,
            Actions,
            Triggers,
            Description | 
        Sort-Object Taskname |
        Out-File $OUTPUT_FILE -Append

    # Check for any running jobs
    Write-Output "******** Scheduled Jobs ********" | Out-File $OUTPUT_FILE -Append
    Get-ScheduledJob | Out-File $OUTPUT_FILE -Append

}

function Get-NetworkInfo {

    # Gets list of network connections 
    Write-Output "`n******** Network Connections ********" | Out-File $OUTPUT_FILE -Append
    Get-NetTCPConnection |
        Select-Object -Property `
            LocalAddress,
            LocalPost,
            RemoteAddress,
            RemotePort,
            OwningProcess,
            State |
        Format-Table -Auto |
        Out-File $OUTPUT_FILE -Append
     
    # Grab machine's network adapter info
    Write-Output "******** Network Adapters ********" | Out-File $OUTPUT_FILE -Append
    Get-NetIPConfiguration | Out-File $OUTPUT_FILE -Append

    #Grab machine's network firewall settings
    Write-Output "******** Network Global Firewall Settings ********" | Out-File $OUTPUT_FILE -Append
    Get-NetFirewallSetting | Out-File $OUTPUT_FILE -Append

    #Grab machine's network neighbor cache entries 
    Write-Output "******** Network Neighbor Cache ********" | Out-File $OUTPUT_FILE -Append
    Get-NetNeighbor | Out-File $OUTPUT_FILE -Append

    # Checks DNS Cache
    Write-Output "******** DNS Cache ********" | Out-File $OUTPUT_FILE -Append
    Get-DnsClientCache | Out-File $OUTPUT_FILE -Append
}


# Grab the lists of users and GPO
function Get-UserList {

    # Gets a list of all the local groups on machine
    Write-Output "******** List of Groups ********" | Out-File $OUTPUT_FILE -Append
    Get-LocalGroup | Out-File $OUTPUT_FILE -Append

    # Gets a list of local users on machine 
    Write-Output "******** Local Users ********" | Out-File $OUTPUT_FILE -Append
    Get-LocalGroupMember -Group "Users" | Out-File $OUTPUT_FILE -Append

    # Gets a list of local adminstrators on the machine   
    Write-Output "******** Local Administrators ********" | Out-File $OUTPUT_FILE -Append
    Get-LocalGroupMember -Group "Administrators" | Out-File $OUTPUT_FILE -Append

    # Gets a list of guest accounts
    Write-Output "******** Guests ********" | Out-File $OUTPUT_FILE -Append
    Get-LocalGroupMember -Group "Guests" | Out-File $OUTPUT_FILE -Append

    # Gets a list of users with remote access 
    Write-Output "******** Remote Desktop Users ********" | Out-File $OUTPUT_FILE -Append
    Get-LocalGroupMember -Group "Remote Desktop Users" | Out-File $OUTPUT_FILE -Append

    #Domain user accounts and admins
    #Get-ADUser
    #Get-ADGroupMember Administrators
    
    #Get GPO report list for computer 
    #Get-GPO -All 
    #Ran into an error, need to test with machine connected to a domain
    #Get-ADDefaultDomainPasswordPolicy
}

# Grab specific registry keys
function Get-RegistryInfo {

    # Checks for Remote desktop setting (RDP) 
    Write-Output "`n******** Remote Desktop Setting - Registry ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" | Out-File $OUTPUT_FILE -Append
    Write-Output "`nfDenyTSConnections:" | Out-File $OUTPUT_FILE -Append
    Get-ItemPropertyValue `
        "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections `
        -ErrorAction SilentlyContinue |
    Out-File $OUTPUT_FILE -Append

    # Keys/values under Run
    Write-Output "`n******** Run keys (Current user) - Registry ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Out-File $OUTPUT_FILE -Append
    Get-ItemProperty `
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
        -ErrorAction SilentlyContinue |
    Out-File $OUTPUT_FILE -Append

    # Recently Opened documents from file explorer
    Write-Output "******** Recently Opened Documents - Registry ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" | Out-File $OUTPUT_FILE -Append
    Get-ItemProperty `
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" `
        -ErrorAction SilentlyContinue | 
    Out-File $OUTPUT_FILE -Append
     
    Write-Output "`n******** Access Point List - Registry ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" | Out-File $OUTPUT_FILE -Append
    Get-ItemProperty `
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" `
        -ErrorAction SilentlyContinue | 
    Out-File $OUTPUT_FILE -Append

    # TypedURLS registry location 
    Write-Output "`n******** TypedURLS - Registry ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs" | Out-File $OUTPUT_FILE -Append
    Get-ItemProperty `
        "HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\TypedURLs" `
        -ErrorAction SilentlyContinue | 
    Out-File $OUTPUT_FILE -Append

    # network shares and mount points
    Write-Output "`n******** Mounted Devices List - Registry ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: HKEY_LOCAL_MACHINE\System\MountedDevices" | Out-File $OUTPUT_FILE -Append
    Get-ItemProperty `
        "HKEY_LOCAL_MACHINE\System\MountedDevices" `
        -ErrorAction SilentlyContinue | 
    Out-File $OUTPUT_FILE -Append
}

# Get event log information for a single ID
function Get-EventInfo {
    param(
        [int]$InstanceId,
        [DateTime]$After,
        [int]$NewestNum,
        [string]$OutputFile
    )
    Get-EventLog Security `
        -InstanceId $InstanceId `
        -After $After.AddDays([int]$Days) `
        -Newest ([int]$NewestNum) `
        -ErrorAction SilentlyContinue | 
    Select-Object `
        EventID, 
        TimeGenerated, 
        Message |
    Format-Table `
        -Property @{Label="ID"; Expression={$_.EventID};  Width=4},
        @{Label="Time Generated"; Expression={$_.TimeGenerated};  Width=22},
        @{Label="Message"; Expression={$_.Message};  Width=50} | 
    Out-File $OutputFile -Append
}

# Gets event logs for multiple event IDs
function Get-MultipleEventLogs {
    param(
        [int[]]$EventIDs,
        [DateTime]$AfterDate,
        [int]$NewestNum,
        [string]$OutputFile
    )

    foreach ($eventID in $eventIDs) {
        Write-Output "`n******** Event ID $eventID ********" | Out-File $OutputFile -Append
        Get-EventInfo -InstanceId $eventID -After $AfterDate.AddDays([int]$Days) -NewestNum $NewestNum -OutputFile $OutputFile
    }
}


function Get-Apps-FileShares {

    # Gets a list of installed programs 
    Write-Output "`n******** Installed Applications ********" | Out-File $OUTPUT_FILE -Append
    Get-WmiObject -Class Win32_Product |
        Select-Object `
            Name,
            Version,
            Vendor,
            InstallDate,
            InstallSource,
            PackageName,
            LocalPackage,
            IdentifyingNumber `
            -ErrorAction SilentlyContinue |
        Out-File $OUTPUT_FILE -Append

    # Checks for file shares on machines
    #Write-Output "******** File-Shares ********" | Out-File $OUTPUT_FILE -Append
    #Get-Files-Shares | Out-File $OUTPUT_FILE -Append
    #Not recognized when tested   
}

# Chekcs specific directorys for new files/updated items
function Get-RecentItems{

# Checks for new items in startup folders
    Write-Output "`n******** New files in Startup folder ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" | Out-File $OUTPUT_FILE -Append
    
    $StartupFolderConent = `
    Get-ChildItem `
        -Path "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp" `
        -Force `
        -Recurse `
        -ErrorAction SilentlyContinue     
    Add-Content -Path $OUTPUT_FILE -Value $StartupFolderConent                                
       
    Write-Output "`n******** User Startup Folder Diff ********" | Out-File $OUTPUT_FILE -Append
    Write-Output "PATH: $env:USERPROFILE\Start Menu\Programs\Startup\" | Out-File $OUTPUT_FILE -Append
    Get-ChildItem `
        -Path "$env:USERPROFILE\Start Menu\Programs\Startup\" `
        -Force `
        -Recurse `
        -ErrorAction SilentlyContinue |
        Diff -ReferenceObject $StartupFolderConent |
    Out-File $OUTPUT_FILE -Append

    
    # Check for files that were last created/updated within C:\ drive
    Write-Output "`n*********************************************************************" | Out-File $OUTPUT_FILE -Append
    Write-Output "`n******** Recently Created/Updated Files - C:\ ********" | Out-File $OUTPUT_FILE -Append
    Get-Childitem `
        -Path "C:\" `
        -Force `
        -Recurse `
        -ErrorAction SilentlyContinue | 
        Where-Object { $_.LastWriteTime -gt ($DATE).AddMinutes(-5) } |  
        Format-Table -AutoSize | 
    Out-File $OUTPUT_FILE -Append

    # Check for files that were last created/updated within current user's AppData folder 
    Write-Output "`n******** Recently Updated Files - C:\Users\$env:CURRENTUSER\AppData\ ********" | Out-File $OUTPUT_FILE -Append
    Get-Childitem `
        -Path "C:\Users\$env:CURRENTUSER\AppData\" `
        -Force `
        -Recurse `
        -ErrorAction SilentlyContinue |  
        Where-Object { $_.LastWriteTime -gt ($DATE).AddMinutes(-5) } | 
    Out-File $OUTPUT_FILE -Append
}
 

#*************** MAIN ***************
 
    Write-Report-Header
    Get-ComputerDataInfo
    Get-NetworkInfo
    Get-UserList
    Get-RegistryInfo
    Get-MultipleEventLogs -EventIDs $EVENT_IDS_SECURITY -AfterDate $DATE -NewestNum $NEWEST_NUM -OutputFile $OUTPUT_FILE
    Get-MultipleEventLogs -EventIDs $EVENT_IDS_SYSTEM -AfterDate $DATE -NewestNum $NEWEST_NUM -OutputFile $OUTPUT_FILE
    Get-MultipleEventLogs -EventIDs $EVENT_IDS_POWERSHELL -AfterDate $DATE -NewestNum $NEWEST_NUM -OutputFile $OUTPUT_FILE
    Get-Apps-FileShares
    Get-RecentItems

# Reverting the execution policy back (Only enable if using the Execution policy block at the top)
#Set-ExecutionPolicy -ExecutionPolicy $currentExecutionPolicy -Scope CurrentUser #Reverts execution policy to original value 

