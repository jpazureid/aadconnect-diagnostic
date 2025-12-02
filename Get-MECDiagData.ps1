<#
    .Synopsis
    Version 10.2.0

    .DESCRIPTION
    Collect Microsoft Entra Connectlogs.

    .PARAMETER Logpath
    Specifies the log path. It's not mandatory. Default value is c:\MECLOG.
    
    .EXAMPLE
    .\Get-MECDiagData.ps1 -Logpath C:\Tmp

    .PARAMETER NetTrace
    Specifies boolean for custom trace.
    
    .EXAMPLE
    .\Get-MECDiagData.ps1 -NetTrace $true

    .PARAMETER GetObjDomainName,GetObjADdn,DomainAdminName and DomainAdminPassword
    Specifies distinguishName of AD object in order to collect it's CS information and MV information.

    .EXAMPLE
    .\Get-MECDiagData.ps1 -GetObjDomainName "contoso.com" -GetObjADdn "CN=user01,OU=users,DC=contoso,DC=com" -DomainAdminName "consoto\admin01" -DomainAdminPassword "Password"

#>

param(
    [string] $Logpath = "c:\MECLOG",
    [bool]$NetTrace,
    [string]$GetObjDomainName,
    [string]$GetObjADdn,
    [string]$DomainAdminName,
    [string]$DomainAdminPassword
)

#region Functions

function Get-HistoryLog {
    $runhitsoryPath = $global:Logpath + "\" + "RUNHISTORY"
    if(Test-path $runhitsoryPath){}else{New-item -ItemType Directory -Path $runhitsoryPath }
    
    $runProfileResultOutFile = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_Get-ADSyncRunProfileResult.csv"
    $runStepSuccessResultOutFile = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_Get-ADSyncRunStepSuccessResult.txt"
    $runStepErrorResultOutFile = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_Get-ADSyncRunStepErrorResult.txt"


    $runHistory = Get-ADSyncRunProfileResult | Select-Object RunNumber,RunHistoryId,ConnectorName,RunProfileName,Result,StartDate,EndDate
    $runHistory | Export-Csv -Path $runProfileResultOutFile -NoTypeInformation
        
    $successResults = $runHistory |  Where-Object{$_.Result -eq "success"}
    foreach($successResult in $successResults){
        $successStepResult = Get-ADSyncRunStepResult -RunHistoryId $successResult.RunHistoryId
        Write-Output "## SuccessStepResultAll" | Out-File -FilePath $runStepSuccessResultOutFile -Append
        $successStepResult | Out-File -FilePath $runStepSuccessResultOutFile -Append
        Write-Output "## ConnectorDiscoveryErrors" | Out-File -FilePath $runStepSuccessResultOutFile -Append
        $successStepResult.ConnectorDiscoveryErrors | Out-File -FilePath $runStepSuccessResultOutFile -Append
        Write-Output "## SyncErrors" | Out-File -FilePath $runStepSuccessResultOutFile -Append
        $successStepResult.SyncErrors | Out-File -FilePath $runStepSuccessResultOutFile -Append
        Write-Output "## MvRetryErrors" | Out-File -FilePath $runStepSuccessResultOutFile -Append
        $successStepResult.MvRetryErrors | Out-File -FilePath $runStepSuccessResultOutFile -Append
    }
        
        
    $errorResults = $runHistory |  Where-Object{$_.Result -ne "success"} | Select-Object -First 10
    foreach($errorResult in $errorResults){
        $errorResultStep = Get-ADSyncRunStepResult -RunHistoryId $errorResult.RunHistoryId
        Write-Output "## ErrorStepResultAll" | Out-File -FilePath $runStepErrorResultOutFile -Append
        $errorResultStep | Out-File -FilePath $runStepErrorResultOutFile -Append
        Write-Output "## ConnectorDiscoveryErrors" | Out-File -FilePath $runStepErrorResultOutFile -Append
        $errorResultStep.ConnectorDiscoveryErrors | Out-File -FilePath $runStepErrorResultOutFile -Append
        Write-Output "## MvRetryErrors" | Out-File -FilePath $runStepErrorResultOutFile -Append
        $errorResultStep.MvRetryErrors | Out-File -FilePath $runStepErrorResultOutFile -Append
            
        Write-Output "## SyncErrors" | Out-File -FilePath $runStepErrorResultOutFile -Append
        $runprofileErrorXml = $errorResultStep.SyncErrors.SyncErrorsXml
        $runprofileErrorXml  | Out-File -FilePath $runStepErrorResultOutFile -Append
            
        $xmlRunprofileError = [xml]$runprofileErrorXml
        $csImportErrorDns = $xmlRunprofileError."synchronization-errors"."import-error"."dn"
        $csSynchronizationErrorDns = $xmlRunprofileError."synchronization-errors"."synchronization-error"."dn"
        $csExportErrorDns = $xmlRunprofileError."synchronization-errors"."export-error"."dn"
        $csErrorConnectorName = $errorResult.ConnectorName

        if($null -ne $csImportErrorDns){
            foreach($csImportErrorDn in $csImportErrorDns){
                Get-ObjectInfo -ConnectorName $csErrorConnectorName -Dn $csImportErrorDn    
            }
        } elseif($null -ne $csSynchronizationErrorDns){
            foreach($csSynchronizationErrorDn in $csSynchronizationErrorDns){
                Get-ObjectInfo -ConnectorName $csErrorConnectorName -Dn $csSynchronizationErrorDn    
                
            }
        } elseif($null -ne $csExportErrorDns){
            foreach($csExportErrorDn in $csExportErrorDns){
                Get-ObjectInfo -ConnectorName $csErrorConnectorName -Dn $csExportErrorDn    
                
            }            
        }
                           
    }

    
}

function Get-NetworkTrace{
    $netTracePath = $global:Logpath + "\" + "NETTRACE"
    if(Test-path $netTracePath){}else{New-item -ItemType Directory -Path $netTracePath }
    

    $etlLogFile = $netTracePath + "\NetTrace.etl"
    $schannelTraceLogFile = $netTracePath + "\SchannelTrace.etl"
    $operationLog = $netTracePath + "\OperationLog.txt"
    

    ## Start Trace
    logman create trace "ds_security" -ow -o $schannelTraceLogFile -p "{44492B72-A8E2-4F20-B0AE-F1D437657C92}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
    logman update trace "ds_security" -p "Microsoft-Windows-Schannel-Events" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "{37D2C3CD-C5D4-4587-8531-4696C44244C8}" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "{37D2C3CD-C5D4-4587-8531-4696C44244C8}" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "Schannel" 0xffffffffffffffff 0xff -ets

    netsh trace start traceFile=.\Netmondummy.etl capture=yes report=disabled
    netsh trace stop
    del Netmondummy.etl
    netsh trace start capture=yes scenario=InternetClient_dbg maxsize=2048 tracefile=$etlLogFile


    ipconfig /flushdns
    klist purge
    klist purge -li 0x3e7
    klist purge -li 0x3e4

    Write-Host "Please start steps. You can press enter when you finish all steps....." -ForegroundColor Green -BackgroundColor Black
    $startDate = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    $startDate + " Trace Start." | Out-File -FilePath $operationLog -Append
    $psrPath = $netTracePath + "\psr.zip"
    psr /start /sc 1 /maxsc 100 /gui 0 /output $psrPath
    
    $answer =  Read-Host 
    Write-Host "Stopped all trace logs. Please wait for a while." -ForegroundColor Green -BackgroundColor Black


    ## Stop Trace
    $endDate = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    $endDate + " Trace End." | Out-File -FilePath $operationLog -Append
    psr /stop
    logman stop "ds_security" -ets
    netsh trace stop

}

function Get-CSinfo{
    param(
        $ConnectorName,$ObjectDn
    )

    $objPath = $global:Logpath + "\" + "OBJECT"
    if(Test-path $objPath){}else{New-item -ItemType Directory -Path $objPath }

    $csObjectFile = $objPath + "\Get-ADSyncCSObject_" + $objectDn + ".txt"
    $csObjet = Get-ADSyncCSObject -ConnectorName $ConnectorName -DistinguishedName $ObjectDn

    if((Test-Path $csObjectFile) -ne $true){
        Write-Output "## Export CS object all" | Out-File -FilePath $csObjectFile -Append
        $csObjet | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS ExportError" | Out-File -FilePath $csObjectFile -Append
        $csObjet.ExportError | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS SynchronizationError" | Out-File -FilePath $csObjectFile -Append
        $csObjet.SynchronizationError | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS object AnchorValue" | Out-File -FilePath $csObjectFile -Append
        $csObjet.AnchorValue | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS object Lineage" | Out-File -FilePath $csObjectFile -Append
        $csObjet.Lineage | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS object Attributes" | Out-File -FilePath $csObjectFile -Append
        $csObjet.Attributes | Out-File -FilePath $csObjectFile -Append
    
    
    }
    return $csObjet        
}

function Get-MVinfo{
    param(
        [parameter(Mandatory=$True)][string]$MvGuid
    ) 

    $objPath = $global:Logpath + "\" + "OBJECT"
    if(Test-path $objPath){}else{New-item -ItemType Directory -Path $objPath }

    $mvObjectFile = $objPath + "\Get-ADSyncMVObject_" + $MvGuid + ".txt"
    $mvObject = Get-ADSyncMVObject -Identifier $MvGuid

    if((Test-Path $mvObjectFile) -ne $True){
        Write-Output "## Export MV object ObjectId" | Out-File -FilePath $mvObjectFile -Append
        $mvObject.ObjectId | Out-File -FilePath $mvObjectFile -Append
        Write-Output "## Export MV object Lineage" | Out-File -FilePath $mvObjectFile -Append
        $mvObject.Lineage | Out-File -FilePath $mvObjectFile -Append
        Write-Output "## Export MV object Attributes" | Out-File -FilePath $mvObjectFile -Append
        $mvObject.Attributes | Out-File -FilePath $mvObjectFile -Append
        Write-Output "## Export MV object SerializedXml" | Out-File -FilePath $mvObjectFile -Append
        $mvObject.SerializedXml | Out-File -FilePath $mvObjectFile -Append
    }
    return $mvObject
}

function Get-ObjectInfo{
    param(
        [parameter(Mandatory=$True)][string]$ConnectorName,[string]$Dn,[string]$DomainAdminName,[string]$DomainAdminPassword
    )

    $objPath = $global:Logpath + "\" + "OBJECT"
    if(Test-path $objPath){}else{New-item -ItemType Directory -Path $objPath }

    if(($DomainAdminName -ne "") -and ($DomainAdminPassword)){
        $securePassword = ConvertTo-SecureString –String $DomainAdminPassword –AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential($DomainAdminName, $securePassword)

        $adObjectFile = $objPath + "\LdapQuery_" + $Dn + ".xml"
        $domainEntry = New-Object -TypeName System.DirectoryServices.DirectoryEntry "LDAP://$ConnectorName" ,$($credential.UserName),$($credential.GetNetworkCredential().password)
        $searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(distinguishedName=$Dn)"
        $searcher.SearchRoot = $domainEntry
        $objectAD = $searcher.FindOne()
        $objectAD.Properties | Export-Clixml -Path $adObjectFile
    }

    $csObj = Get-CSinfo -ConnectorName $ConnectorName -ObjectDn $Dn
    $mvGuid = $csObj.ConnectedMVObjectId
    $mvObj = Get-MVinfo -MvGuid $mvGuid
    $mvLineages = $mvObj.Lineage
    foreach ($mvLineage in $mvLineages) {
        if($mvLineage.ConnectorName -ne $ConnectorName){
            Get-CSinfo -ConnectorName $mvLineage.ConnectorName -ObjectDn $mvLineage.ConnectedCsObjectDN
        }
    }    

}

function Get-CSExport{
    $csExportPath = $global:Logpath + "\" + "CSEXPORT"
    if(Test-path $csExportPath){}else{New-item -ItemType Directory -Path $csExportPath }

    $currentPath = Get-Location
    $cSexportBinPath = "C:\Program Files\Microsoft Azure AD Sync\Bin"
    Set-Location $cSexportBinPath

    $connecterNames = (Get-ADSyncConnector).Name
    foreach($connecterName in $connecterNames){
        $trimName = $connecterName -replace " ", "_"
        
        .\csexport.exe $connecterName $csExportPath\error_export_$trimName.xml  /f:e | Out-Null
        .\csexport.exe $connecterName $csExportPath\error_import_$trimName.xml /f:i | Out-Null
        .\csexport.exe $connecterName $csExportPath\pending_export_$trimName.xml /f:x | Out-Null
        .\csexport.exe $connecterName $csExportPath\pending_import_$trimName.xml /f:m  | Out-Null

        .\CSExportAnalyzer.exe $csExportPath\error_export_$trimName.xml | Out-File -FilePath $csExportPath\analyzed_error_export_$trimName.csv | Out-Null
        .\CSExportAnalyzer.exe $csExportPath\error_import_$trimName.xml | Out-File -FilePath $csExportPath\analyzed_error_import_$trimName.csv | Out-Null
              

    }
    Set-Location -Path $currentPath
}

function Get-ADSyncConfig {

    Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1"

    $configPath = $global:Logpath + "\" + "CONFIG"
    if(Test-path $configPath){}else{New-item -ItemType Directory -Path $configPath }

    $aadcConfig = $configPath + "\MEC"
    $generalConfig = $configPath + "\GENERAL"
    New-item -ItemType Directory -Path $aadcConfig | Out-Null  
    New-item -ItemType Directory -Path $generalConfig| Out-Null
    
    # AADC config
    Get-ADSyncAutoUpgrade | Out-File -FilePath $aadcConfig\Get-ADSyncAutoUpgrade.txt
    
    $connectorInfo = $aadcConfig + "\Get-ADSyncConnector.txt"
    $connectors = Get-ADSyncConnector
    foreach ($connector  in $connectors) {
        Write-Output "## Connector Summary" | Out-File -FilePath $connectorInfo -Append
        $connector | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector Runprofiles" | Out-File -FilePath $connectorInfo -Append
        $connector.RunProfiles | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector ConnectivityParameters" | Out-File -FilePath $connectorInfo -Append
        $connector.ConnectivityParameters | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector GlobalParameters" | Out-File -FilePath $connectorInfo -Append
        $connector.GlobalParameters | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector ObjectInclusionList" | Out-File -FilePath $connectorInfo -Append
        $connector.ObjectInclusionList | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector AttributeInclusionList" | Out-File -FilePath $connectorInfo -Append
        $connector.AttributeInclusionList | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector PasswordHashConfiguration" | Out-File -FilePath $connectorInfo -Append
        $connector.PasswordHashConfiguration | Out-File -FilePath $connectorInfo -Append
        Write-Output "## Connector AADPasswordResetConfiguration" | Out-File -FilePath $connectorInfo -Append
        $connector.AADPasswordResetConfiguration | Out-File -FilePath $connectorInfo -Append

        
        if($connector.Name -like "*AAD"){
            $aadPassResetConfgFile = $aadcConfig + "\Get-ADSyncAADPasswordResetConfiguration.txt"
            Get-ADSyncAADPasswordResetConfiguration -Connector $connector.Name | Out-File -FilePath $aadPassResetConfgFile -Append

            $companyFeatureSwitch = (Get-Command Get-ADSyncAADCompanyFeature).Parameters.Keys | Select-Object -First 1
            if($companyFeatureSwitch -eq "ConnectorName"){
                Get-ADSyncAADCompanyFeature -ConnectorName $connector.Name | Out-File -FilePath $aadcConfig\Get-ADSyncAADCompanyFeature.txt

            }else {
                Get-ADSyncAADCompanyFeature | Out-File -FilePath $aadcConfig\Get-ADSyncAADCompanyFeature.txt
            }
    

        }else {
            $aadPassSyncConfigFile = $aadcConfig + "\Get-ADSyncAADPasswordSyncConfiguration.txt"
            Get-ADSyncAADPasswordSyncConfiguration -SourceConnector $connector.Name | Out-File -FilePath $aadPassSyncConfigFile -Append

            $inheritanDisabledFile = $aadcConfig + "\Get-ADSyncObjectsWithInheritanceDisabled.txt"
            Get-ADSyncObjectsWithInheritanceDisabled -SearchBase $connector.Name | Out-File -FilePath $inheritanDisabledFile -Append
        }
        
        $connectorStaticticsFile = $aadcConfig + "\Get-ADSyncConnectorStatistics.txt"
        Write-Output "## Connector statistics for "  $connector.Name | Out-File -FilePath $connectorStaticticsFile -Append
        Get-ADSyncConnectorStatistics -ConnectorName $connector.Name | Out-File -FilePath $connectorStaticticsFile -Append

    }
    Get-ADSyncDatabaseConfiguration | Out-File -FilePath $aadcConfig\Get-ADSyncDatabaseConfiguration.txt -Append

    
    ##$exportDeletionThresholdSwitch = (Get-Command Get-ADSyncExportDeletionThreshold).Parameters.Keys | Select-Object -First 1
    ##if($exportDeletionThresholdSwitch -ne "AADCredential"){
    ##    Get-ADSyncExportDeletionThreshold | Out-File -FilePath $aadcConfig\Get-ADSyncExportDeletionThreshold.txt -Append
    ##}


    (Get-ADSyncGlobalSettings).Parameters | Select-Object Name,Value | Out-File -FilePath $aadcConfig\Get-ADSyncGlobalSettings.txt
    
    Get-ADSyncPartitionPasswordSyncState | Out-File -FilePath $aadcConfig\Get-ADSyncPartitionPasswordSyncState.txt -Append
    Get-ADSyncRule | Format-List | Out-File -FilePath $aadcConfig\Get-ADSyncRule.txt
    
    
    Get-ADSyncScheduler | Out-File -FilePath $aadcConfig\Get-ADSyncScheduler.txt
    Get-ADSyncSchedulerConnectorOverride | Out-File -FilePath $aadcConfig\Get-ADSyncSchedulerConnectorOverride.txt
    
    Write-Output "## Connector Schema " | Out-File -FilePath $aadcConfig\Get-ADSyncSchema.txt  -Append
    Get-ADSyncSchema | Out-File -FilePath $aadcConfig\Get-ADSyncSchema.txt  -Append
    Write-Output "## Connector ObjectTypes " | Out-File -FilePath $aadcConfig\Get-ADSyncSchema.txt  -Append
    (Get-ADSyncSchema).ObjectTypes | Out-File -FilePath $aadcConfig\Get-ADSyncSchema.txt  -Append
    Write-Output "## Connector AttributeTypes " | Out-File -FilePath $aadcConfig\Get-ADSyncSchema.txt  -Append
    (Get-ADSyncSchema).AttributeTypes | Out-File -FilePath $aadcConfig\Get-ADSyncSchema.txt  -Append
    
    Get-ADSyncServerConfiguration -Path $aadcConfig
    

    # Health config
    ##$healthProxyFile = $aadcConfig +"\Get-AzureADConnectHealthProxySettings.txt"
    ##Get-AzureADConnectHealthProxySettings | Out-File -FilePath $HealthProxyFile -Append
    
    # General config
    $machineconfigFile = $env:windir + "\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
    Copy-Item -Path $machineconfigFile -Destination $generalConfig
    
    msinfo32 /report $generalConfig\msinfo32.txt

    tasklist /svc >> $generalConfig\tasklist.txt
    netsh winhttp show proxy >> $generalConfig\winhttpproxy.txt
    ipconfig /all >> $generalConfig\ipconfigall.txt
    whoami /all >> $generalConfig\whoamiall.txt
    Get-HotFix | Export-Csv -Path $generalConfig\Hotfix.csv
    $netStatFile = $generalConfig + "\netstat.txt"
    netstat -ano | Out-File -FilePath $netStatFile -Append

    certutil -v -silent -store ROOT > $generalConfig\cert-root.txt
    certutil -v -silent -store -user ROOT > $generalConfig\cert-user-root.txt
    certutil -v -silent -store CA > $generalConfig\cert-ca.txt
    certutil -v -silent -store -user CA > $generalConfig\cert-user-ca.txt
    certutil -v -silent -store AUTHROOT > $generalConfig\cert-authroot.txt
    certutil -v -silent -store -enterprise ROOT > $generalConfig\cert-ent-root.txt
    certutil -v -silent -store -enterprise CA > $generalConfig\cert-ent-ca.txt
    certutil -v -silent -store -enterprise NTAUTH > $generalConfig\cert-ent-ntauth.txt
    certutil -v -silent -store -grouppolicy ROOT > $generalConfig\cert-gp-root.txt
    certutil -v -silent -store -grouppolicy CA > $generalConfig\cert-gp-ca.txt
    certutil -v -silent -store MY > $generalConfig\cert-machine-my.txt
    certutil -v -silent -store -user MY > $generalConfig\cert-user-my.txt

    reg save HKLM\SYSTEM\ $generalConfig\REG_HKLM_SYSTEM_Hive.hiv > $null 2>&1
    reg export HKLM\SYSTEM\ $generalConfig\REG_HKLM_SYSTEM_Hive.log > $null 2>&1
    reg save HKLM\Software\ $generalConfig\REG_HKLM_Software_Hive.hiv > $null 2>&1
    reg export HKLM\Software\ $generalConfig\REG_HKLM_Software_Hive.log > $null 2>&1
    reg export HKU $generalConfig\REG_HKU.log > $null 2>&1

}

function Get-Logs{

    $aadcTracePath = $global:Logpath + "\" + "AADCTRACE"
    if(Test-path $aadcTracePath){}else{New-item -ItemType Directory -Path $aadcTracePath }

    $eventlogPath = $global:Logpath + "\" + "EVENTLOG"
    if(Test-path $eventlogPath){}else{New-item -ItemType Directory -Path $eventlogPath }
    
    $sysEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_SystemEvent.evtx"
    wevtutil epl system $sysEventPath

    $appEventPath =$eventlogPath + "\" + $env:COMPUTERNAME + "_Application.evtx"
    wevtutil epl Application $appEventPath

    $secEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_Security.evtx"
    wevtutil epl Security $secEventPath

    $capEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_CAPI2_Operational.evtx"
    wevtutil epl Microsoft-Windows-CAPI2/Operational $capEventPath
    
    ##$updEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_Microsoft_AzureADConnect_AgentUpdater_Admin.evtx"
    ##wevtutil epl Microsoft-AzureADConnect-AgentUpdater/Admin $updEventPath > $null 2>&1
    
    ##$ptaEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_Microsoft_AzureADConnect_AuthenticationAgent_Admin.evtx"
    ##wevtutil epl Microsoft-AzureADConnect-AuthenticationAgent/Admin $ptaEventPath > $null 2>&1
    
    ##$syncHealthEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_Microsoft_AzureADConnectHealth_MonitorDataManagement_Operational.evtx"
    ##wevtutil epl Microsoft-AzureADConnectHealth-MonitorDataManagement/Operational $syncHealthEventPath > $null 2>&1
    
    ##xcopy /s C:\Windows\System32\winevt\Logs\* $eventlogPath


    # Collect Tracelog
    $tracePath = $env:programdata + "\AADConnect"
    Copy-item $tracePath $aadcTracePath -Recurse
    
    ##$healthTracePath = $env:programdata + "\Microsoft\AadConnectHealth"
    ##Copy-item $healthTracePath $aadcTracePath -Recurse
    
    ##$passthrougtracePath = $env:programdata + "\Microsoft\Azure AD Connect Authentication Agent\"
    ##Copy-item $passthrougtracePath $aadcTracePath -Recurse
    
    
    ##$helthTracePath = $env:ProgramFiles + "\Microsoft Azure AD Connect Health Sync Agent"
    ##Copy-item $helthTracePath $aadcTracePath -Recurse
    
}

function Start-Initialize {
    if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]"Administrator") -eq $false){
        Write-Warning "You have to execute this script with Administration privilege."
        exit 1
    }

    Start-Sleep 1

    if($global:Logpath -eq "c:\MECLOG"){
        if(Test-Path $global:Logpath){}else{New-item -ItemType Directory -Path $global:Logpath | Out-Null}
    }else{
        if(Test-Path $global:Logpath\MECLOG){
            $global:Logpath = Resolve-Path $global:Logpath\MECLOG    
        }else{        
            New-item -ItemType Directory -Path $global:Logpath\MECLOG | Out-Null
            $global:Logpath = Resolve-Path $global:Logpath\MECLOG    
        }       
    }
    $dateTime = Get-Date -Format yyyyMMdd-HHmmss
    $global:Logpath = Join-Path $global:Logpath $dateTime
    
}

#endregion

# Start main
$errorActionPreference = "silentlycontinue"
$global:Logpath = $Logpath
Write-Progress -Activity "Start-Initialize" -Status "Executing..." -CurrentOperation "Preparing to collect logs." -PercentComplete 10
Start-Initialize

# Collect Object Infomation
if (($GetObjDomainName -ne "") -and ($GetObjADdn -ne "") -and ($DomainAdminName -ne "") -and ($DomainAdminPassword)){
    $errorActionPreference = "continue"
    Write-Progress -Activity "Get-ObjectInfo" -Status "Executing..." -CurrentOperation "Dumping object data." -PercentComplete 100
    Get-ObjectInfo -ConnectorName $GetObjDomainName -Dn $GetObjADdn -DomainAdminName $DomainAdminName -DomainAdminPassword $DomainAdminPassword | Out-Null
    exit 0
}

# Collect Network Capture
if($NetTrace -eq $true){ 
    Write-Progress -Activity "Get-NetworkTrace" -Status "Executing..." -CurrentOperation "Capturing trace." -PercentComplete 40
    Get-NetworkTrace | Out-Null
}

# Collect Configuration
Write-Progress -Activity "Get-ADSyncConfig" -Status "Executing..." -CurrentOperation "Collecting configuration." -PercentComplete 50
Get-ADSyncConfig | Out-Null

# Colloect CS Export Errors
Write-Progress -Activity "Get-CSExport" -Status "Executing..." -CurrentOperation "Collecting cs exports logs" -PercentComplete 65
Get-CSExport | Out-Null

# Collect log
Write-Progress -Activity "Get-Logs" -Status "Executing..." -CurrentOperation "Collecting event logs." -PercentComplete 85
Get-Logs | Out-Null

## Collect Run history
Write-Progress -Activity "Get-HistoryLog" -Status "Executing..." -CurrentOperation "Collecting sync history." -PercentComplete 100
Get-HistoryLog | Out-Null

