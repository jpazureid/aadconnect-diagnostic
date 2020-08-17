<#
    .Synopsis
    Version 9.2.2

    .DESCRIPTION
    Collect Azure AD Connect logs.

    .PARAMETER Logpath
    Specifies the log path. It's not mandatory. Default value is c:\AADCLOG.
    
    .EXAMPLE
    .\Get-AADCDiagData.ps1 -Logpath C:\Tmp

    .PARAMETER NetTraceFor
    Specifies which scenarios you want to collect logs. You can choose one of four scenarios, DirSyncAndPHSAndPWB, PathThroughAuth, Health, ConfiguraionOrOtherthing
    
    .EXAMPLE
    .\Get-AADCDiagData.ps1 -NetTraceFor DirSyncAndPHSAndPWB

    .PARAMETER GetObjDomainName_GetObjADdn
    Specifies distinguishName of AD object in order to collect it's CS information and MV information.

    .EXAMPLE
    .\Get-AADCDiagData.ps1 -GetObjDomainName "contoso.com" -GetObjADdn "CN=user01,OU=users,DC=contoso,DC=com"

#>

param(
    [string] $Logpath = "c:\AADCLOG",
    [ValidateSet("DirSyncAndPHSAndPWB", "PathThroughAuth", "Health", "ConfiguraionOrOtherthing")]$NetTraceFor,
    [string]$GetObjDomainName,
    [string]$GetObjADdn
)

#region Functions

function Get-HistoryLog {
    $runhitsoryPath = $global:Logpath + "\" + "RUNHISTORY"
    if(Test-path $runhitsoryPath){}else{New-item -ItemType Directory -Path $runhitsoryPath }
    
    $runProfileResult = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_Get-ADSyncRunProfileResult.csv"
    $runStepResult = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_Get-ADSyncRunStepResult.txt"

    $runHistorySwitch = Get-Command Get-ADSyncRunProfileResult -ErrorAction Ignore
    if ($null -ne $runHistorySwitch){
        $runHistory = Get-ADSyncRunProfileResult | Select-Object RunNumber,RunHistoryId,ConnectorName,RunProfileName,Result,StartDate,EndDate
        $runHistory | Export-Csv -Path $runProfileResult -NoTypeInformation
        $runprofileErrors = Get-ADSyncRunProfileResult | Where-Object{$_.Result -ne "success"} | Select-Object -First 50

        foreach($runprofileError in $runprofileErrors){
            (Get-ADSyncRunStepResult -RunHistoryId $runprofileError.RunHistoryId) | Out-File -FilePath $runStepResult -Append
            $runprofileErrorXml = (Get-ADSyncRunStepResult -RunHistoryId $runprofileError.RunHistoryId).SyncErrors.SyncErrorsXml
            $runprofileErrorXml  | Out-File -FilePath $runStepResult -Append
            Write-Output "==============================" | Out-File -FilePath $runStepResult -Append
            
            $xmlRunprofileError = [xml]$runprofileErrorXml
            $csImportErrorDns = $xmlRunprofileError."synchronization-errors"."import-error"."dn"
            $csSynchronizationErrorDns = $xmlRunprofileError."synchronization-errors"."synchronization-error"."dn"
            $csExportErrorDns = $xmlRunprofileError."synchronization-errors"."export-error"."dn"
            $csErrorConnectorName = $runprofileError.ConnectorName

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
    } else {

        $runhistoryFile = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_SyncHistorySummary.csv"    
        $runhistoryErrorLogFile = $runhitsoryPath+"\"+$env:COMPUTERNAME+"_SyncHistoryError.txt"
    
        ## Get hitory from wmi
        $runhistory = Get-WmiObject -class "MIIS_RunHistory" -namespace root\MicrosoftIdentityintegrationServer 
        $formatHistory = $runhistory | Select-Object RunNumber,MaName,RunProfile,RunStatus,RunStartTime,RunEndTime,PSComputerName 
        $formatHistory | Export-Csv -Path $runhistoryFile -NoTypeInformation
    
        ## Output only error log
        $errHistories = $runHistory | Where-Object{$_.RunStatus -ne "success"} | Select-Object -First 50
        foreach ($errHistory in $errHistories){
            $errHistory.RunDetails().ReturnValue | Out-File -FilePath $runhistoryErrorLogFile -Append

            $errXml = [xml]$errHistory.RunDetails().ReturnValue
            $csErrorConnectorName = $errXml."run-history"."run-details"."ma-name"
            $csImportErrorDns = $errXml."run-history"."run-details"."step-details"."synchronization-errors"."import-error"."dn"
            $csSynchronizationErrorDns = $errXml."run-history"."run-details"."step-details"."synchronization-errors"."synchronization-error"."dn"
            $csExportErrorDns = $errXml."run-history"."run-details"."step-details"."synchronization-errors"."export-error"."dn"
            
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
}

function Get-NetworkTrace{
    param(
        [parameter(Mandatory=$True)][string]$Scenario
    )
    $netTracePath = $global:Logpath + "\" + "NETTRACE"
    if(Test-path $netTracePath){}else{New-item -ItemType Directory -Path $netTracePath }
    
    $existCapi2 = wevtutil gl Microsoft-Windows-CAPI2/Operational | Select-String "enabled: true"
    if($null -notcontains $existCapi2){
        $capi2AlreadyON = $True 
    }

    $etlLogFile = $netTracePath + "\NetTrace.etl"
    $schannelTraceLogFile = $netTracePath + "\SchannelTrace.etl"

    $operationLog = $netTracePath + "\OperationLog.txt"
    
    if($capi2AlreadyON -eq $true){
    }else{
            wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:true    
    }
    

    ## Start Trace
    logman create trace "ds_security" -ow -o $schannelTraceLogFile -p "{44492B72-A8E2-4F20-B0AE-F1D437657C92}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
    logman update trace "ds_security" -p "Microsoft-Windows-Schannel-Events" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "{37D2C3CD-C5D4-4587-8531-4696C44244C8}" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "{37D2C3CD-C5D4-4587-8531-4696C44244C8}" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "Schannel" 0xffffffffffffffff 0xff -ets


    netsh trace start scenario=InternetClient capture=yes maxsize=1024 tracefile=$etlLogFile

    ipconfig /flushdns
    klist purge
    klist purge -li 0x3e7
    klist purge -li 0x3e4

    switch ($Scenario) {
        DirSyncAndPHSAndPWB {
            $adSyncService = Get-Service -Name ADSync
            Write-Warning "We are going to re-start $($adSyncService.DisplayName) service."
            [string]$answer =  Read-Host "Are you sure to continue?(y/n)" 
            if($answer -eq "y"){
                Get-Date -Format "yyyy/MM/dd HH:mm:ss"| Out-File -FilePath $operationLog -Append
                Write-Output "NetTrace for DirSyncAndPHSAndPWB started." | Out-File -FilePath $operationLog -Append
                $adSyncService | Restart-Service
                Start-Sleep 30
                $adSyncService = Get-Service -Name ADSync
                if($adSyncService.Status -eq "Running"){
                    Write-Host "Service re-started successfully." -ForegroundColor Green -BackgroundColor Black
                } else{
                    Write-Host "Service re-started failed. Please re-start service manually." -ForegroundColor Red -BackgroundColor Black
                }   
            } else {
                break;
            }
          }
        PathThroughAuth {        
            $ptaService = Get-Service -Name AzureADConnectAuthenticationAgent
            Write-Warning "We are going to re-start $($ptaService.DisplayName) service."
            [string]$answer =  Read-Host "Are you sure to continue?(y/n)" 
            if($answer -eq "y"){
                Get-Date -Format "yyyy/MM/dd HH:mm:ss"| Out-File -FilePath $operationLog -Append
                Write-Output "NetTrace for PathThroughAuth started." | Out-File -FilePath $operationLog -Append
                $ptaService | Restart-Service
                Start-Sleep 30
                $ptaService = Get-Service -Name AzureADConnectAuthenticationAgent
                if($ptaService.Status -eq "Running"){
                    Write-Host "Service re-started successfully." -ForegroundColor Green -BackgroundColor Black
                }else {
                    Write-Host "Service re-started failed. Please re-start service manually." -ForegroundColor Red -BackgroundColor Black
                }       
            } else {
                break;
            }
          }
        Health {
            $insightService = Get-Service -Name AzureADConnectHealthSyncInsights
            $monitorService = Get-Service -Name AzureADConnectHealthSyncMonitor
            Write-Warning "We are going to re-start $($insightService.DisplayName) and $($monitorService.DisplayName)."
            [string]$answer =  Read-Host "Are you sure to continue?(y/n)"
            if($answer -eq "y"){
                Get-Date -Format "yyyy/MM/dd HH:mm:ss"| Out-File -FilePath $operationLog -Append
                Write-Output "NetTrace for Health started." | Out-File -FilePath $operationLog -Append

                $insightService | Restart-Service
                $monitorService | Restart-Service
                Start-Sleep 30
                $insightService = Get-Service -Name AzureADConnectHealthSyncInsights
                $monitorService = Get-Service -Name AzureADConnectHealthSyncMonitor
                if(($insightService.Status -eq "Running") -and ($monitorService.Status -eq "Running")){
                    Write-Host "Service re-started successfully." -ForegroundColor Green -BackgroundColor Black
                }else {
                    Write-Host "Service re-started failed. Please re-start service manually." -ForegroundColor Red -BackgroundColor Black
                }  

                $healthLogFile = $netTracePath + "\OutPutofTestHealth.txt"
                Test-AzureADConnectHealthConnectivity -Role Sync -ShowResult | Out-File -FilePath $healthLogFile -Append        
            } else {
                break;
            }
          }
        ConfiguraionOrOtherthing {
            Write-Host "Please start configuration steps or onther scenarios." -ForegroundColor Green -BackgroundColor Black
            Get-Date -Format "yyyy/MM/dd HH:mm:ss"| Out-File -FilePath $operationLog -Append
            Write-Output "NetTrace for ConfiguraionOrOtherthing started." | Out-File -FilePath $operationLog -Append
            $psrPath = $netTracePath + "\psr.zip"
            psr /start /sc 1 /maxsc 100 /gui 0 /output $psrPath
            $answer =  Read-Host "If you have finished all steps, then close configuration wizard and press enter here..." 
            psr /stop
            break;
          }
        Default {break;}
    }


    ## Stop Trace
    logman stop "ds_security" -ets
    netsh trace stop

    if($capi2AlreadyON -ne $true){
        wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:false
    }

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
        Write-Output "## Export CS object AnchorValue" | Out-File -FilePath $csObjectFile -Append
        $csObjet.AnchorValue | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS object Lineage" | Out-File -FilePath $csObjectFile -Append
        $csObjet.Lineage | Out-File -FilePath $csObjectFile -Append
        Write-Output "## Export CS object Attributes" | Out-File -FilePath $csObjectFile -Append
        $csObjet.Attributes | Out-File -FilePath $csObjectFile -Append
    
        if($ConnectorName -notlike "*AAD"){
            Import-Module "C:\Program Files\Microsoft Azure Active Directory Connect\AdSyncConfig\AdSyncConfig.psm1"
            Write-Output "## Show-ADSyncADObjectPermissions for this object" | Out-File -FilePath $csObjectFile -Append
            Show-ADSyncADObjectPermissions -ADobjectDN $csObjet.DistinguishedName | Out-File -FilePath $csObjectFile -Append
        }
    
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
        [parameter(Mandatory=$True)][string]$ConnectorName,[string]$Dn
    )
    $objPath = $global:Logpath + "\" + "OBJECT"
    if(Test-path $objPath){}else{New-item -ItemType Directory -Path $objPath }

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

    $aadcConfig = $configPath + "\AADC"
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

        Write-Output "=============================================" | Out-File -FilePath $connectorInfo -Append
    }
    Get-ADSyncDatabaseConfiguration | Out-File -FilePath $aadcConfig\Get-ADSyncDatabaseConfiguration.txt -Append
    $exportDeletionThresholdSwitch = (Get-Command Get-ADSyncExportDeletionThreshold).Parameters.Keys | Select-Object -First 1
    if($exportDeletionThresholdSwitch -ne "AADCredential"){
        Get-ADSyncExportDeletionThreshold | Out-File -FilePath $aadcConfig\Get-ADSyncExportDeletionThreshold.txt -Append
    }


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
    $healthProxyFile = $aadcConfig +"\Get-AzureADConnectHealthProxySettings.txt"
    Get-AzureADConnectHealthProxySettings | Out-File -FilePath $HealthProxyFile -Append
    
    # General config
    $machineconfigFile = $env:windir + "\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
    Copy-Item -Path $machineconfigFile -Destination $generalConfig
    
    msinfo32 /nfo $generalConfig\system.nfo

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

    $userContexts = reg query hku | Select-String -Pattern "_Classes" -NotMatch
    foreach($userContext in $userContexts){
        if($userContext -like "*\*"){
            $ieProxySetting = $userContext.ToString() + "\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            $ieProxySettinWow64 = $userContext.ToString() + "\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Internet Settings"
            $contextID = $userContext.ToString().Split("\")[1]
    
            $ieProxySettingFile = $generalConfig + "\" + $contextID + "_IEproxySettings.hiv"
            $ieProxySettingWow64File = $generalConfig + "\" + $contextID + "_IEproxySettingsWow64.hiv"
    
            reg save $ieProxySetting $ieProxySettingFile > $null 2>&1
            reg save $ieProxySettinWow64 $ieProxySettingWow64File > $null 2>&1    
        }
    }
    $sChannelSettings = $generalConfig + "\SchannelSettings.hiv"
    reg save "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $sChannelSettings
    $sslSettings = $generalConfig + "\SslSettings.hiv"
    reg save "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL" $sslSettings
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
    
    $updEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_Microsoft_AzureADConnect_AgentUpdater_Admin.evtx"
    wevtutil epl Microsoft-AzureADConnect-AgentUpdater/Admin $updEventPath > $null 2>&1
    
    $ptaEventPath = $eventlogPath + "\" + $env:COMPUTERNAME + "_Microsoft_AzureADConnect_AuthenticationAgent_Admin.evtx"
    wevtutil epl Microsoft-AzureADConnect-AuthenticationAgent/Admin $ptaEventPath > $null 2>&1
    
    # Collect Tracelog
    $tracePath = $env:programdata + "\AADConnect"
    Copy-item $tracePath $aadcTracePath -Recurse
    $passthrougtracePath = $env:programdata + "\Microsoft\Azure AD Connect Authentication Agent\"
    Copy-item $passthrougtracePath $aadcTracePath -Recurse
    $helthTracePath = $env:ProgramFiles + "\Microsoft Azure AD Connect Health Sync Agent"
    Copy-item $helthTracePath $aadcTracePath -Recurse
    
}
function Start-Initialize {
    if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]"Administrator") -eq $false){
        Write-Warning "You have to execute this script with Administration privilege."
        exit 1
    }
    Start-Sleep 4

    if($global:Logpath -eq "c:\AADCLOG"){
        if(Test-Path $global:Logpath){}else{New-item -ItemType Directory -Path $global:Logpath | Out-Null}
    }else{
        if(Test-Path $global:Logpath\AADCLOG){
            $global:Logpath = Resolve-Path $global:Logpath\AADCLOG    
        }else{        
            New-item -ItemType Directory -Path $global:Logpath\AADCLOG | Out-Null
            $global:Logpath = Resolve-Path $global:Logpath\AADCLOG    
        }       
    }
    $dateTime = Get-Date -Format yyyyMMdd-HHmmss
    $global:Logpath = Join-Path $global:Logpath $dateTime
    
}

#endregion

# Start main
$errorActionPreference = "SilentlyContinue"
$global:Logpath = $Logpath
Write-Progress -Activity "Start-Initialize" -Status "Executing..." -CurrentOperation "Preparing to collect logs." -PercentComplete 10
Start-Initialize

# Collect Object Infomation
if (($GetObjDomainName -ne "") -and ($GetObjADdn -ne "")){
    Write-Progress -Activity "Get-ObjectInfo" -Status "Executing..." -CurrentOperation "Dumping object data." -PercentComplete 100
    Get-ObjectInfo -ConnectorName $GetObjDomainName -Dn $GetObjADdn | Out-Null
    exit 0
}

# Collect Network Capture
if($null -ne $NetTraceFor){ 
    Write-Progress -Activity "Get-NetworkTrace" -Status "Executing..." -CurrentOperation "Capturing trace." -PercentComplete 40
    Get-NetworkTrace -Scenario $NetTraceFor | Out-Null
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

