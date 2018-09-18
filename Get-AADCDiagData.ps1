<#
.SYNOPSIS
    Get diagnostic data of Azure AD Connect
.PARAMETER days
    Days to save run-history
.PARAMETER logpath
    Path to save the output
.PARAMETER dumpAllData
    Get all dump details
.PARAMETER AllDataMode
    File format of run-history: "TXT" or "XML"
.PARAMETER TraceON
    Get network trace when this parameter is set to True
.EXAMPLE
    C:\PS> Get-AADCDiagData.ps1 -logpath .\AADCLOG
    Get diagnostic data to the specified directory
.EXAMPLE
    C:\PS> Powershell.exe -ExecutionPolicy RemoteSigned -File .\Get-AADCDiagData.ps1
    Run the script when running script is restricted
#>

Param([int] $days = 7,
    [string] $logpath = "c:\AADCLOG",
    [ValidateSet($True, $False)] $dumpAllData = $False,
    [ValidateSet("TXT", "XML")] $AllDataMode = "TXT",
    [bool]$TraceON = $False
)

$Global:GetRunHistoryColumnName = ""  
$Global:GetRunHistoryColumnData = ""
$Global:GetRunHistoryErrorStackData = ""
$Global:GetRunStepNumber = 0 


#
# Define functions
#
function NotExists([String]$path) {
    return -not (test-path $path)
}

function BuildRunHistoryData( [System.Object]$xmlobject, [string]$columnname, [int]$i ) { 
    if ($xmlobject -eq $null) { 
        if ( $Global:GetRunHistoryColumnData -eq "" ) { 
            $Global:GetRunHistoryColumnData = $getdata 
        } 
        else { 
            $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData + "`t" + $getdata 
        }
    } 
    else {
        if ( $Global:GetRunHistoryColumnName -eq "" ) { 
            $Global:GetRunHistoryColumnName = $xmlobject[$columnname].Name 
        }
        else { 
            if ( -not $Global:GetRunHistoryColumnName.Contains($columnname) ) { 
                if (( -not $xmlobject[$columnname].Name -eq "" ) -or ( -not $xmlobject.Name -eq "" )) { 
                    $NewColumnName = if ( $xmlobject[$columnname].Name -eq $null ) { $xmlobject.Name } else { $xmlobject[$columnname].Name } 
                    $Global:GetRunHistoryColumnName = $Global:GetRunHistoryColumnName.Trim() + "`t" + $NewColumnName
                }
            } 
        } 
 
        switch ($i) { 
            0 { $getdata = $xmlobject[$columnname].InnerText } 
            1 { $getdata = $xmlobject[$columnname].InnerXML } 
            2 { $getdata = $xmlobject[$columnname].OuterXML } 
            3 { $getdata = $xmlobject[$columnname].type } 
            4 { $getdata = $xmlobject[$columnname].Value } 
            5 { $getdata = $xmlobject.Value } 
        } 
 
        if ( $columnname.ToLower() -eq "call-stack" ) { 
            #$getdata = $getdata.Replace(" ", "") 
            $getdata = $getdata.Replace("`n", "`r`n")
            $getdata = $getdata.Replace("`r`r`n", "`r`n") 
        } 

        if ($columnname -eq "call-stack") {
            $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "`r`n-----------START CALL STACK----------`r`n" + $getdata + "`r`n-----------END CALL STACK----------`r`n`r`n"           
            if ($Global:GetRunHistoryColumnData.Contains("Please See RUNHISTORY_SyncErrorDetail.TXT") ) {
            }
            else {
                $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData + "`t" + "Please See RUNHISTORY_SyncErrorDetail.TXT"
            }
        }
        else {
            if ( $Global:GetRunHistoryColumnData -eq "" ) { 
                $Global:GetRunHistoryColumnData = $getdata 
            }
            else { 
                $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData + "`t" + $getdata 
            } 
        }
    } 
} 

function GetSyncHistoryLog {
    param(
        [parameter(Mandatory = $True)][string]$OutLogFilePath
    )
    # First Step
    $ErrorActionPreference = "silentlycontinue"
    
    # Set log file location 
    $OutLogFile = $OutLogFilePath + "\" + $env:COMPUTERNAME + "_SyncHistorySummary.txt"
    $ErrorLogFile = $OutLogFilePath + "\" + $env:COMPUTERNAME + "_SyncHistoryError.txt"
    $CSErrorLogFile = $OutLogFilePath + "\" + $env:COMPUTERNAME + "_CSErrorObject.txt"
    $MVErrorLogFile = $OutLogFilePath + "\" + $env:COMPUTERNAME + "_MVErrorObject.txt"

    # Get hitory from wmi
    $history = Get-WmiObject -class "MIIS_RunHistory" -namespace root\MicrosoftIdentityintegrationServer 
    $history | ft RunNumber, MaName, RunProfile, RunStatus, RunStartTime, RunEndTime, PSComputerName -AutoSize -Wrap | Out-File -FilePath $OutLogFile -Append

    # Output only error log
    foreach ($obj in $history) {
        
        
        if ($obj.RunStatus -ne "success") {
            # Output Summary
            $obj.RunDetails().ReturnValue | Out-File -FilePath $ErrorLogFile -Append
            
            # Output CS Detail 
            [xml]$xml = $obj.RunDetails().ReturnValue
            $maname = $xml."run-history"."run-details"."ma-name"
            $dn = $xml."run-history"."run-details"."step-details"."synchronization-errors"."export-error"."dn"
            $csObject = Get-ADSyncCSObject -ConnectorName $maname -DistinguishedName $dn
            $csObject | Out-File  -FilePath $CSErrorLogFile -Append
            $csObject.Lineage | Out-File  -FilePath $CSErrorLogFile -Append

            # Output MV Detail
            Get-ADSyncMVObject -Identifier $csObject.ConnectedMVObjectId | fl * | Out-File  -FilePath $MVErrorLogFile -Append          
        } 
    }

    # Last Step
    $ErrorActionPreference = "Continue"
}

function GetNetworkTrace {
    param(
        [parameter(Mandatory = $True)][string]$OutLogFilePath
    )
    # First Step
    $ErrorActionPreference = "silentlycontinue"

    # Set log file location 
    $ETLLogFile = $OutLogFilePath + "\NetTrace.etl"
    $HealthLogFile = $OutLogFilePath + "\OutPutofTestHealth.txt"
    $SyncLogFile = $OutLogFilePath + "\OutPutofTestSync.txt"
    $HealthProxyFile = $OutLogFilePath + "\HealthProxyConfig.txt"
    $MachineconfigFile = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
    $NetStatFile = $OutLogFilePath + "\Netstat.txt"

    # Start Trace
    ipconfig /flushdns
    netsh trace start scenario=InternetClient capture=yes maxsize=1024 tracefile=$ETLLogFile

    # TestSync
    Start-ADSyncSyncCycle -PolicyType Delta | Out-File -FilePath $SyncLogFile -Append
    Get-Date | Out-File -FilePath $SyncLogFile -Append
    sleep 60

    # Test Health Connectivity
    Test-AzureADConnectHealthConnectivity -Role Sync -ShowResult | Out-File -FilePath $HealthLogFile -Append
    Get-Date | Out-File -FilePath $HealthLogFile -Append
    
    # Stop Trace
    netsh trace stop

    # Colect some config
    Get-AzureADConnectHealthProxySettings | Out-File -FilePath $HealthProxyFile -Append
    Copy-Item -Path $MachineconfigFile -Destination $OutLogFilePath
    netstat -ano | Out-File -FilePath $NetStatFile -Append

    # Last Step
    $ErrorActionPreference = "Continue"
}

#
# Set output path
#
if (NotExists("$logpath")) {
    new-item -ItemType Directory -Path $logpath
}
$logpath = Resolve-Path $logpath
Write-Host "OutPut Direcroy : " $logpath -ForegroundColor Green
$datetime = Get-Date -Format yyyyMMdd-HHmmss
$logpath = $logpath + "\" + $datetime

#
# Get AADC configuration
#
new-item -ItemType Directory -Path $logpath\config

Get-ADSyncAutoUpgrade > $logpath\config\ADSyncAutoUpgrade.txt
(Get-ADSyncGlobalSettings).Parameters | select Name, Value > $logpath\config\ADSyncGlobalSettings.txt
Get-ADSyncScheduler > $logpath\config\ADSyncScheduler.txt
Get-ADSyncSchedulerConnectorOverride > $logpath\config\ADSyncSchedulerConnectorOverride.txt
Get-ADSyncServerConfiguration -Path $logpath\config\Serverconfig
Get-ADSyncRule | FL > $logpath\config\ADSyncRule.txt

#
# Get Conecter Space info
#
$Connecters = $null

$csexportPath = $env:programfiles + "\Microsoft Azure AD Sync\BIN"
if (NotExists("$logpath\CSEXPORT")) {
    new-item -ItemType Directory -Path $logpath\CSEXPORT
}
Set-Location -Path $csexportPath
$ConnectersXML = Get-ChildItem -path $logpath\config\Serverconfig\Connectors -Filter *.xml

$ConnecterName = @()
foreach ($Connceterfile in $ConnectersXML) {
    $tempXML = [XML](get-content -path $logpath\config\Serverconfig\Connectors\$Connceterfile -Encoding UTF8)
    $ConnecterName = $tempXML.'ma-data'.'name'
    $trimName = $ConnecterName -replace " ", "_"
    .\csexport.exe $ConnecterName $logpath\CSEXPORT\error_export_$trimName.xml /f:e 
    .\csexport.exe $ConnecterName $logpath\CSEXPORT\error_import_$trimName.xml /f:i
    .\csexport.exe $ConnecterName $logpath\CSEXPORT\Pending_export_$trimName.xml /f:x
    .\csexport.exe $ConnecterName $logpath\CSEXPORT\Pending_import_$trimName.xml /f:m 
}

#
# Get eventlog and system info
#
if (NotExists("$logpath\EVENTLOG")) {
    new-item -ItemType Directory -Path $logpath\EVENTLOG
}
Set-Location -Path $logpath\eventlog

wevtutil epl system $logpath\EVENTLOG\SystemEvent.evtx
wevtutil epl Application $logpath\EVENTLOG\AppliEvent.evtx
msinfo32 /nfo $logpath\EVENTLOG\system.nfo


#
# Get trace log
#
if (NotExists("$logpath\AADCTRACE")) {
    new-item -ItemType Directory -Path $logpath\AADCTRACE
}
$tracePath = $env:programdata + "\AADConnect"

copy-item $tracePath $logpath\AADCTRACE -Recurse

#
# Get network trace
#
if ($TraceON -eq $True) {
    if (NotExists("$logpath\NETTRACE")) {
        new-item -ItemType Directory -Path $logpath\NETTRACE
    }
    GetNetworkTrace -OutLogFilePath $logpath\NETTRACE
}

#
# Get run history
#
if (NotExists("$logpath\RUNHISTORY")) {
    new-item -ItemType Directory -Path $logpath\RUNHISTORY
}

Set-Location -Path $logpath\RUNHISTORY

GetSyncHistoryLog -OutLogFilePath $logpath\RUNHISTORY

$OutFileHistory = ".\RUNHISTORY_CSV.csv" 
$OutFileCompleteRunHistory = ".\RUNHISTORY_ALL.txt" 
$OutXmlCompleteRunHistory = ".\RUNHISTORY_ALL.xml"
$OutErrorStackHistory = ".\RUNHISTORY_SyncErrorDetail.TXT"

$RunStartDate = (Get-Date (Get-Date).AddDays(-$days) -Format yyyy-MM-dd) 
$GetRunStartTime = "RunStartTime > '{0}'" -f $RunStartDate
try {
    $GetRunHistoryNotSuccess = Get-WmiObject -class "MIIS_RunHistory" -namespace root\MicrosoftIdentityintegrationServer -Filter $GetRunStartTime
}
catch {
    Write-Error "There was a problem calling WMI Namespace 'root\MicrosoftIdentityintegrationServer'. Exiting."
    return
}


if ( $GetRunHistoryNotSuccess -ne $null ) { 
    $sRunHistoryString = "" 
    $GetRunHistoryData = "" 
    $RunHistoryNames = ""
    $xmlData = @()
    $totalItems = $GetRunHistoryNotSuccess.Count
    $i = 0
	
    foreach ( $RHERR in $GetRunHistoryNotSuccess ) { 

        Write-Progress -Activity "Exporting Run History" -percentComplete ($i / $totalItems * 100)
	
        [xml]$gRunHistory = $RHERR.RunDetails().ReturnValue 
        $gRunHistoryRunDetails = $gRunHistory.DocumentElement["run-details"] 
        BuildRunHistoryData $gRunHistoryRunDetails "ma-name" 0 
        BuildRunHistoryData $gRunHistoryRunDetails "ma-id" 0 
        BuildRunHistoryData $gRunHistoryRunDetails "run-profile-name" 0 
        BuildRunHistoryData $gRunHistoryRunDetails "security-id" 0 
        # step-details ( could have multiple steps, so we will need to loop through ) 
        $GetRunStepDetails = $gRunHistoryRunDetails["step-details"] 
        # step-details information 
        $Global:GetRunStepNumber = $GetRunStepDetails.Attributes.Item(0).Value 
 
        for ( [int]$iCounter = 0; $iCounter -lt $GetRunStepNumber; $iCounter++ ) { 
            
            if ( $iCounter -gt 0 ) { 
                $GetRunStepDetails = $GetRunStepDetails.NextSibling 
            } 
            
            # step-details 
            BuildRunHistoryData $GetRunStepDetails.Attributes.Item(0) $GetRunStepDetails.Attributes.Item(0).Name 5 
            BuildRunHistoryData $GetRunStepDetails "step-result" 0 
            BuildRunHistoryData $GetRunStepDetails "start-date" 0 
            BuildRunHistoryData $GetRunStepDetails "end-date" 0 
 
            # MA Connection Information 
            $GetMAConnection = $GetRunStepDetails["ma-connection"] 
            BuildRunHistoryData $GetMAConnection "connection-result" 0 
            BuildRunHistoryData $GetMAConnection "server" 0 
 
            # Step-Description 
            $GetRunStepDescription = $GetRunStepDetails["step-description"] 
            BuildRunHistoryData $GetRunStepDescription "partition" 0 
            BuildRunHistoryData $GetRunStepDescription "step-type" 3 
 
            # Custom Data 
            $GetCustomData = $GetRunStepDescription["custom-data"] 
            BuildRunHistoryData $GetCustomData.FirstChild "batch-size" 0 
            BuildRunHistoryData $GetCustomData.FirstChild "page-size" 0 
            BuildRunHistoryData $GetCustomData.FirstChild "time-limit" 0 
 
            # inbound-flow-counters 
            BuildRunHistoryData $GetRunStepDetails "inbound-flow-counters" 1 
            BuildRunHistoryData $GetRunStepDetails "export-counters" 1 
 
            # Synchronization Errors 
            $GetSynchronizationErrors = $GetRunStepDetails["synchronization-errors"] 
 
            if ( -not $GetSynchronizationErrors.IsEmpty ) { 
                #BuildRunHistoryData $GetSynchronizationErrors.FirstChild "error-type" 0 
                #BuildRunHistoryData $GetSynchronizationErrors.FirstChild "algorithm-step" 0 
                
                foreach ($errors in $GetSynchronizationErrors.ChildNodes) {
                    $GetSyncErrorInfo = $errors."extension-error-info" 
                    if ( $GetSyncErrorInfo -ne $null ) { 
                        $Global:GetRunHistoryErrorStackData = "++++++++++`r`nMA-NAME :" + $gRunHistoryRunDetails.'ma-name' + "`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "CS GUID :" + $Errors.'cs-guid' + "`r`n" 
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "DN :" + $Errors.'dn' + "`r`n" 
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Sync Start Date :" + $gRunHistoryRunDetails.'step-details'.'start-date' + "`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Sync End Date :" + $gRunHistoryRunDetails.'step-details'.'end-date' + "`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "First Error Occurred :" + $Errors.'first-occurred' + "`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Date Error Occurred :" + $Errors.'date-occurred' + "`r`n" 
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Error Type :" + $Errors.'error-type' + "`r`n"

                        BuildRunHistoryData $GetSyncErrorInfo "call-stack" 0 
                        if ($Global:GetRunHistoryErrorStackData -ne "") {
                            $Global:GetRunHistoryErrorStackData| OUT-FILE -Append $OutErrorStackHistory         
                        }

                    } 
                    if ( -not $RunHistoryNames.Contains("call-stack") ) { 
                        $RunHistoryNames = $GetRunHistoryColumnName 
                    } 
                }
            } 

            if ( $GetRunStepNumber -gt 1 ) { 
                $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData + "`n`t`t`t" 
            } 
        } 
 
        if ($sRunHistoryString -eq "") {
            $sRunHistoryString = $Global:GetRunHistoryColumnData 
        }
        else { 
            $sRunHistoryString = $sRunHistoryString + "`r" + $GetRunHistoryColumnData 
        } 


        $Global:GetRunHistoryColumnData = ""
        $Global:GetRunHistoryErrorStackData = ""
 
        if ($RunHistoryNames -eq "") { 
            $RunHistoryNames = $GetRunHistoryColumnName 
        }
        else { 
            $RunHistoryNames = $RunHistoryNames 
        }
        if ($dumpAllData -eq $true) {
            if ($AllDataMode -eq "TXT") {
                $RHERR.RunDetails() | Out-File -Append $OutFileCompleteRunHistory
            }
            $xmlData += $RHERR.RunDetails()
        }
        $i++
    }
 
    if ($GetRunHistoryData -eq "") {
        $RunHistoryNames | Out-File -Append $OutFileHistory 
    } 
    $GetRunHistoryData = $sRunHistoryString 
    $GetRunHistoryData | Out-File -Append $OutFileHistory 
    $sRunHistoryString = "" 
    $RunHistoryNames = "" 
    if (($dumpAllData -eq $true) -and ($AllDataMode -eq "XML")) {
        $xmlData | Export-Clixml $OutXmlCompleteRunHistory
    }
}

Set-Location -Path $PSScriptRoot