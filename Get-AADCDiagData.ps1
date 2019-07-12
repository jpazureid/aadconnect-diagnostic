<#
.Synopsis
    Version 8.0.1
.DESCRIPTION
   Collect Azure AD Connect logs.
.EXAMPLE
   .\Get-AADCDiagData.ps1
.EXAMPLE
   .\Get-AADCDiagData.ps1 -Logpath C:\Tmp
.EXAMPLE
   .\Get-AADCDiagData.ps1 -GetObj $true
.EXAMPLE
   .\Get-AADCDiagData.ps1 -GetObj $true -NetTraceON $True
.EXAMPLE
   .\Get-AADCDiagData.ps1 -GetObj $true -ForestName contoso.com -ObjectName user01

#>

param(
[string] $Logpath = "c:\AADCLOG",
[bool]$NetTraceON = $False,
[bool]$GetObj = $False,
[string]$ForestName= "",
[string]$ObjectName= ""
)

#region Functions
 

function BuildRunHistoryData( [System.Object]$xmlobject, [string]$columnname, [int]$i ) 
{ 

    if($xmlobject -eq $null) { 
        if( $Global:GetRunHistoryColumnData -eq "" )  { 
            $Global:GetRunHistoryColumnData = $getdata 
        } 
        else { 
            $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData+"`t"+$getdata 
        }
    } 
    else  {
        if( $Global:GetRunHistoryColumnName -eq "" )   { 
            $Global:GetRunHistoryColumnName = $xmlobject[$columnname].Name 
        }
        else  { 
            if( -not $Global:GetRunHistoryColumnName.Contains($columnname) )  { 
                if(( -not $xmlobject[$columnname].Name -eq "" ) -or ( -not $xmlobject.Name -eq "" ))   { 
                    $NewColumnName = if( $xmlobject[$columnname].Name -eq $null ) {$xmlobject.Name} else {$xmlobject[$columnname].Name} 
                    $Global:GetRunHistoryColumnName = $Global:GetRunHistoryColumnName.Trim()+"`t"+$NewColumnName
                }
            } 
        } 
 
        switch ($i) 
        { 
            0 { $getdata = $xmlobject[$columnname].InnerText } 
            1 { $getdata = $xmlobject[$columnname].InnerXML } 
            2 { $getdata = $xmlobject[$columnname].OuterXML } 
            3 { $getdata = $xmlobject[$columnname].type } 
            4 { $getdata = $xmlobject[$columnname].Value } 
            5 { $getdata = $xmlobject.Value } 
        } 
 
        if( $columnname.ToLower() -eq "call-stack" ) 
        { 
            #$getdata = $getdata.Replace(" ","") 
            $getdata = $getdata.Replace("`n","`r`n")
            $getdata = $getdata.Replace("`r`r`n","`r`n") 
        } 

        if($columnname -eq "call-stack"){
            $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "`r`n-----------START CALL STACK----------`r`n" + $getdata + "`r`n-----------END CALL STACK----------`r`n`r`n"           
            if($Global:GetRunHistoryColumnData.Contains("Please See RUNHISTORY_SyncErrorDetail.TXT") ){}else{
                $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData+"`t"+"Please See RUNHISTORY_SyncErrorDetail.TXT"
            }


        }else{
 
            if( $Global:GetRunHistoryColumnData -eq "" )  { 
                $Global:GetRunHistoryColumnData = $getdata 
            } 
            else  { 
                $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData+"`t"+$getdata 
            } 
        }
    } 
} 

function GetSyncHistoryLog{
    param(
        [parameter(Mandatory=$True)][string]$OutLogFilePath,[System.Management.Automation.PSCredential]$Credential
    )
    
    ## Set log file location 
    $OutLogFile = $OutLogFilePath+"\"+$env:COMPUTERNAME+"_SyncHistorySummary.csv"
    $ErrorLogFile = $OutLogFilePath+"\"+$env:COMPUTERNAME+"_SyncHistoryError.txt"
    $CSErrorLogFile = $OutLogFilePath+"\"+$env:COMPUTERNAME+"_CSErrorObject.txt"
    $MVErrorLogFile = $OutLogFilePath+"\"+$env:COMPUTERNAME+"_MVErrorObject.txt"

    ## Get hitory from wmi
    $history=Get-WmiObject -class "MIIS_RunHistory" -namespace root\MicrosoftIdentityintegrationServer 
    $formatHistory=$history | select RunNumber,MaName,RunProfile,RunStatus,RunStartTime,RunEndTime,PSComputerName 
    $formatHistory | Export-Csv -Path $OutLogFile -NoTypeInformation

    ## Output only error log
    foreach ($obj in $history){
        
        
        if($obj.RunStatus -ne "success"){
            ## Output Summary
            $obj.RunDetails().ReturnValue | Out-File -FilePath $ErrorLogFile -Append
        } 
    }
}

function GetNetworkTrace{
    param(
        [parameter(Mandatory=$True)][string]$OutLogFilePath
    )
    ## Initail
    $ExistCapi2=wevtutil gl Microsoft-Windows-CAPI2/Operational | Select-String "enabled: true"
    if($null -notcontains $ExistCapi2){
        $CAPI2AlreadyON=$True 
    }

    ## Set log file location 
    $ETLLogFile = $OutLogFilePath+"\NetTrace.etl"
    $LDAPETLLogFile = $OutLogFilePath+"\LdapTrace.etl"
    $SCHANNELETLLogFile = $OutLogFilePath+"\SchannelTrace.etl"
    $HealthLogFile = $OutLogFilePath+"\OutPutofTestHealth.txt"
    $SyncLogFile = $OutLogFilePath+"\OutPutofTestSync.txt"
    $NetStatFile = $OutLogFilePath+"\Netstat.txt"


    ## Start Trace
    if($CAPI2AlreadyON -eq $true){
    }else{
            wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:true    
    }

    logman create trace "ldap" -ow -o $LDAPETLLogFile -p "Microsoft-Windows-LDAP-Client" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
    logman update trace "ldap" -p "Microsoft-Windows-ADSI" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{F2969C49-B484-4485-B3B0-B908DA73CEBB}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{548854B9-DA55-403E-B2C7-C3FE8EA02C3C}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "Microsoft-Windows-LDAP-Client" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "Microsoft-Windows-ADSI" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{1C83B2FC-C04F-11D1-8AFC-00C04FC21914}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{F33959B4-DBEC-11D2-895B-00C04F79AB69}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{BBA3ADD2-C229-4CDB-AE2B-57EB6966B0C4}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{24DB8964-E6BC-11D1-916A-0000F8045B04}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "Active Directory Rights Management Services" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{90717974-98DB-4E28-8100-E84200E22B3F}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{90717974-98DB-4E28-8100-E84200E22B3F}" 0xffffffffffffffff 0xff -ets
    logman update trace "ldap" -p "{44415D2B-56DC-437D-AEB2-482A480183A5}" 0xffffffffffffffff 0xff -ets


    logman create trace "ds_security" -ow -o $SCHANNELETLLogFile -p "{44492B72-A8E2-4F20-B0AE-F1D437657C92}" 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
    logman update trace "ds_security" -p "Microsoft-Windows-Schannel-Events" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "{37D2C3CD-C5D4-4587-8531-4696C44244C8}" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "{37D2C3CD-C5D4-4587-8531-4696C44244C8}" 0xffffffffffffffff 0xff -ets
    logman update trace "ds_security" -p "Schannel" 0xffffffffffffffff 0xff -ets


    netsh trace start scenario=InternetClient capture=yes maxsize=1024 tracefile=$ETLLogFile

    sleep 2

    ipconfig /flushdns
    klist purge
    klist purge -li 0x3e7
    klist purge -li 0x3e4
 
    ## TestSync
    Start-ADSyncSyncCycle -PolicyType Delta | Out-File -FilePath $SyncLogFile -Append
    Get-Date | Out-File -FilePath $SyncLogFile -Append
    sleep 180

    ## Test Health Connectivity
    Test-AzureADConnectHealthConnectivity -Role Sync -ShowResult | Out-File -FilePath $HealthLogFile -Append
    Get-Date | Out-File -FilePath $HealthLogFile -Append

    ## Some config    
    netstat -ano | Out-File -FilePath $NetStatFile -Append

    ## Stop Trace
    logman stop "ldap" -ets
    logman stop "ds_security" -ets
    netsh trace stop

    if($CAPI2AlreadyON -eq $true){
    }else{
            wevtutil sl "Microsoft-Windows-CAPI2/Operational" /e:false
    }

}
function GetObjectInfo{
    param(
        [parameter(Mandatory=$True)][string]$OutLogFilePath,$ForestName,$ObjectName,[System.Management.Automation.PSCredential]$Credential
    )

    function GetCSObject{
        param(
            [parameter(Mandatory=$True)][string]$OutLogFilePath,$Connector,$objectDn
        )

        ## Export CS 
        $csObjet=Get-ADSyncCSObject -ConnectorName $Connector -DistinguishedName $objectDn
        Write-Output "## Export CS object all" | Out-File -File $OutLogFilePath -Append
        $csObjet | Out-File -File $OutLogFilePath -Append
        Write-Output "## Export CS object AnchorValue" | Out-File -File $OutLogFilePath -Append
        $csObjet.AnchorValue | Out-File -File $OutLogFilePath -Append
        Write-Output "## Export CS object Lineage" | Out-File -File $OutLogFilePath -Append
        $csObjet.Lineage | Out-File -File $OutLogFilePath -Append
        Write-Output "## Export CS object Attributes" | Out-File -File $OutLogFilePath -Append
        $csObjet.Attributes | Out-File -File $OutLogFilePath -Append        
        return $csObjet 
    }

    function GetMVObject{
        param(
            [parameter(Mandatory=$True)][string]$OutLogFilePath,$mvGuid
        )
        ## Export MV 
        $mvObject=Get-ADSyncMVObject -Identifier $mvGuid
        Write-Output "## Export MV object ObjectId" | Out-File -File $OutLogFilePath -Append
        $mvObject.ObjectId | Out-File -File $OutLogFilePath -Append
        Write-Output "## Export MV object Lineage" | Out-File -File $OutLogFilePath -Append
        $mvObject.Lineage | Out-File -File $OutLogFilePath -Append
        Write-Output "## Export MV object Attributes" | Out-File -File $OutLogFilePath -Append
        $mvObject.Attributes | Out-File -File $OutLogFilePath -Append
        Write-Output "## Export MV object SerializedXml" | Out-File -File $OutLogFilePath -Append
        $mvObject.SerializedXml | Out-File -File $OutLogFilePath -Append
        return $mvObject
    }

    function GetADObject{
        param(
            [parameter(Mandatory=$True)][string]$OutLogFilePath,$ForestName,$ObjectName,[System.Management.Automation.PSCredential]$Credential
        )

        ## Export AD info 
        $DomainEntry = New-Object -TypeName System.DirectoryServices.DirectoryEntry "LDAP://$ForestName" ,$($Credential.UserName),$($Credential.GetNetworkCredential().password)
        $Searcher = New-Object -TypeName System.DirectoryServices.DirectorySearcher
        $Searcher.Filter = "(cn=$ObjectName)"
        $Searcher.SearchRoot = $DomainEntry
        $objectAD=$Searcher.FindOne()
        $objectAD.Properties | Out-File -File $objectADFile -Append
        $objectAD.Properties | Export-Clixml $objectADFileXML
        return $objectAD
    }

    ## Initail
    if(test-path $OutLogFilePath\$ObjectName){}else{new-item -ItemType Directory -Path $OutLogFilePath\$ObjectName}
    $OutLogFilePath=Join-Path -Path $OutLogFilePath -ChildPath $ObjectName

    ## Set File Path 
    $objectADFile=$OutLogFilePath+"\Object_AD.txt"
    $objectADFileXML=$OutLogFilePath+"\Object_AD.xml"
    $csObjectOnpremisFile=$OutLogFilePath+"\CsObject_Onpremis.txt"
    $csObjectAzureFile=$OutLogFilePath+"\CsObject_Azure.txt"
    $mvObjectFile=$OutLogFilePath+"\MVObject.txt"

    ## Export Object
    $Connector = $ForestName

    if($Connector -match ".onmicrosoft.com - AAD"){

        ## Export CS Azure
        $csObjetAzure=GetCSObject -OutLogFilePath $csObjectAzureFile -Connector $Connector -objectDn $ObjectName

        ## Export MV 
        $mvGuid=$csObjetAzure.ConnectedMVObjectId.Guid
        $mvo=GetMVObject -OutLogFilePath $mvObjectFile -mvGuid $mvGuid

        ## Export CS Onpremise
        $lineages=$mvo.Lineage
        foreach($lineage in $lineages){
            if($lineage.ConnectorName -match ".onmicrosoft.com - AAD"){
            }else{
                $csObjetOnpremise=GetCSObject -OutLogFilePath $csObjectOnpremisFile -Connector $lineage.ConnectorName -objectDn $lineage.ConnectedCsObjectDN
            }
        }
        ## Export AD Object
        $onpremiseDNsplit=(($csObjetOnpremise.DistinguishedName) -split ",")
        $split0=$onpremiseDNsplit[0]
        $onpremiseCN=$split0 -replace "CN=",""
        $objectAD=GetADObject -OutLogFilePath $objectADFile -ForestName $csObjetOnpremise.ConnectorName -ObjectName $onpremiseCN -Credential $Credential    


    }else{
        if($ObjectName -match "CN="){
            ## Export CS Onpremise
            $csObjetOnpremise=GetCSObject -OutLogFilePath $csObjectOnpremisFile -Connector $Connector -objectDn $ObjectName

            ## Export MV 
            $mvGuid=$csObjetOnpremise.ConnectedMVObjectId.Guid
            $mvo=GetMVObject -OutLogFilePath $mvObjectFile -mvGuid $mvGuid

            ## Export CS Azure
            $lineages=$mvo.Lineage
            foreach($lineage in $lineages){
                if($lineage.ConnectorName -match ".onmicrosoft.com - AAD"){
                    $csObjetAzure=GetCSObject -OutLogFilePath $csObjectAzureFile -Connector $lineage.ConnectorName -objectDn $lineage.ConnectedCsObjectDN
                }
            }
            ## Export AD Object
            $onpremiseDNsplit=(($csObjetOnpremise.DistinguishedName) -split ",")
            $split0=$onpremiseDNsplit[0]
            $onpremiseCN=$split0 -replace "CN=",""
            $objectAD=GetADObject -OutLogFilePath $objectADFile -ForestName $csObjetOnpremise.ConnectorName -ObjectName $onpremiseCN -Credential $Credential    

            
        }else{
            ## Export AD Object
            $objectAD=GetADObject -OutLogFilePath $objectADFile -ForestName $ForestName -ObjectName $ObjectName -Credential $Credential    
        
            ## Export CS Onpremise
            $objectDn=($objectAD.Path).Replace("LDAP://"+$ForestName+"/","")
            $csObjetOnpremise=GetCSObject -OutLogFilePath $csObjectOnpremisFile -Connector $Connector -objectDn $objectDn

            ## Export MV 
            $mvGuid=$csObjetOnpremise.ConnectedMVObjectId.Guid
            $mvo=GetMVObject -OutLogFilePath $mvObjectFile -mvGuid $mvGuid
        
            ## Export CS Azure
            $lineages=$mvo.Lineage
            foreach($lineage in $lineages){
                if($lineage.ConnectorName -match ".onmicrosoft.com - AAD"){
                    $csObjetAzure=GetCSObject -OutLogFilePath $csObjectAzureFile -Connector $lineage.ConnectorName -objectDn $lineage.ConnectedCsObjectDN
                }
            }
        
        }
    }
        
}

function GetCSExport{
    $CurrentPath= Get-Location
    $CSexportPath=Get-Process -Name miiserver | select Path | Split-Path -Parent
    Set-Location -Path $CSexportPath

    $Connecters=(Get-ADSyncConnector).Name
    foreach($ConnecterName in $Connecters){
        $trimName = $ConnecterName -replace " ", "_"
        .\csexport.exe $ConnecterName $Logpath\CSEXPORT\error_export_$trimName.xml /f:e | Out-Null
        .\csexport.exe $ConnecterName $Logpath\CSEXPORT\error_import_$trimName.xml /f:i | Out-Null
        .\csexport.exe $ConnecterName $Logpath\CSEXPORT\Pending_export_$trimName.xml /f:x | Out-Null
        .\csexport.exe $ConnecterName $Logpath\CSEXPORT\Pending_import_$trimName.xml /f:m  | Out-Null

        .\CSExportAnalyzer.exe $Logpath\CSEXPORT\error_export_$trimName.xml | Out-File -FilePath $Logpath\CSEXPORT\Analyzed_error_export_$trimName.csv | Out-Null
        .\CSExportAnalyzer.exe $Logpath\CSEXPORT\error_import_$trimName.xml | Out-File -FilePath $Logpath\CSEXPORT\Analyzed_error_import_$trimName.csv | Out-Null
        
        if($GetObj -eq $True){
            $errorExport=Import-Csv -Path $Logpath\CSEXPORT\Analyzed_error_export_$trimName.csv
            $errorImport=Import-Csv -Path $Logpath\CSEXPORT\Analyzed_error_import_$trimName.csv
            $sumDNs=($errorExport.DN + $errorImport.DN)
            if(test-path $Logpath\GETOBJ){}else{new-item -ItemType Directory -Path $Logpath\GETOBJ}
            if(test-path $Logpath\GETOBJ\FromAzureCS){}else{new-item -ItemType Directory -Path $Logpath\GETOBJ\FromAzureCS}
            if(test-path $Logpath\GETOBJ\OnpreADCS){}else{new-item -ItemType Directory -Path $Logpath\GETOBJ\OnpreADCS}
            $uniDNs=$sumDNs | Sort-Object -Unique

            if($ConnecterName.contains("AAD")){
                foreach($dn in $uniDNs){
                    if($dn -ne $null){
                        GetObjectInfo -OutLogFilePath $Logpath\GETOBJ\FromAzureCS -forestName $ConnecterName -objectName $dn -Credential $Credential                        
                    }
                }       
            }else{
                foreach($dn in $uniDNs){
                    if($dn -ne $null){
                        GetObjectInfo -OutLogFilePath $Logpath\GETOBJ\OnpreADCS -forestName $ConnecterName -objectName $dn -Credential $Credential                        
                    }
                }               
            }        
        }
    }
    Set-Location -Path $CurrentPath
}


function GetPassHashSyncStatus{
    param(
        [parameter(Mandatory=$True)][string]$OutLogFilePath
    )
    $passHashStatusFile=$OutLogFilePath+"\PasswordHashSyncStatus.txt"

    Import-Module ADSync
    $connectors = Get-ADSyncConnector
    $aadConnectors = $connectors | Where-Object {$_.SubType -eq "Windows Azure Active Directory (Microsoft)"}
    $adConnectors = $connectors | Where-Object {$_.ConnectorTypeName -eq "AD"}
    if ($aadConnectors -ne $null -and $adConnectors -ne $null)
    {
        if ($aadConnectors.Count -eq 1)
        {
            $features = Get-ADSyncAADCompanyFeature -ConnectorName $aadConnectors[0].Name
            Write-Output ""| Out-File -FilePath $passHashStatusFile -Append
            Write-Output "Password sync feature enabled in your Azure AD directory: "  $features.PasswordHashSync | Out-File -FilePath $passHashStatusFile -Append
            foreach ($adConnector in $adConnectors)
            {
                Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
                Write-Output "Password sync channel status BEGIN ------------------------------------------------------- " | Out-File -FilePath $passHashStatusFile -Append
                Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
                Get-ADSyncAADPasswordSyncConfiguration -SourceConnector $adConnector.Name | Out-File -FilePath $passHashStatusFile -Append
                Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
                $pingEvents =
                    Get-EventLog -LogName "Application" -Source "Directory Synchronization" -InstanceId 654  -After (Get-Date).AddHours(-3) |
                        Where-Object { $_.Message.ToUpperInvariant().Contains($adConnector.Identifier.ToString("D").ToUpperInvariant()) } |
                        Sort-Object { $_.Time } -Descending
                if ($pingEvents -ne $null)
                {
                    Write-Output "Latest heart beat event (within last 3 hours). Time " $pingEvents[0].TimeWritten | Out-File -FilePath $passHashStatusFile -Append
                }
                else
                {
                    Write-Output "No ping event found within last 3 hours." | Out-File -FilePath $passHashStatusFile -Append
                }
                Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
                Write-Output "Password sync channel status END ------------------------------------------------------- " | Out-File -FilePath $passHashStatusFile -Append
                Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
            }
        }
        else
        {
            Write-Output "More than one Azure AD Connectors found. Please update the script to use the appropriate Connector." | Out-File -FilePath $passHashStatusFile -Append
        }
    }
    Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
    if ($aadConnectors -eq $null)
    {
        Write-Output "No Azure AD Connector was found." | Out-File -FilePath $passHashStatusFile -Append
    }
    if ($adConnectors -eq $null)
    {
        Write-Output "No AD DS Connector was found." | Out-File -FilePath $passHashStatusFile -Append
    }
    Write-Output "" | Out-File -FilePath $passHashStatusFile -Append
}




#endregion


###############
# Initial Config
###############
if($Logpath -eq "c:\AADCLOG"){
    if(Test-Path $Logpath){
    }else{
        new-item -ItemType Directory -Path $Logpath
    }
}else{
    if(Test-Path $Logpath\AADCLOG){
        $Logpath = Resolve-Path $Logpath\AADCLOG    
    }else{        
        new-item -ItemType Directory -Path $Logpath\AADCLOG
        $Logpath = Resolve-Path $Logpath\AADCLOG    
    }       
}
$ErrorActionPreference = "silentlycontinue"
$CurrentPath= Get-Location
$Datetime = Get-Date -Format yyyyMMdd-HHmmss
$Logpath = $Logpath+"\" +$Datetime
if($GetObj -eq $True){
    $Credential=Get-Credential -Message "Enter On-premise forest administrator's credential"
}


###############
# Collect Object Infomation
###############
if (($ForestName -ne "") -and ($ObjectName -ne "")){
    if(test-path $Logpath\GETOBJ\FromAD){}else{new-item -ItemType Directory -Path $Logpath\GETOBJ\FromAD} 
    GetObjectInfo -OutLogFilePath $Logpath\GETOBJ\FromAD -forestName $ForestName -objectName $ObjectName -Credential $Credential 
    exit 0
}
###############
# Collect Network Capture
###############
if ($NetTraceON -eq $True){
    if(test-path $Logpath\NETTRACE){}else{new-item -ItemType Directory -Path $Logpath\NETTRACE }
    GetNetworkTrace -OutLogFilePath $Logpath\NETTRACE | Out-Null
}

###############
# Collect Configuration
###############
new-item -ItemType Directory -Path $Logpath\CONFIG  
new-item -ItemType Directory -Path $Logpath\CONFIG\AADC | Out-Null  
new-item -ItemType Directory -Path $Logpath\CONFIG\GENERAL | Out-Null

Get-ADSyncAutoUpgrade > $Logpath\CONFIG\AADC\ADSyncAutoUpgrade.txt
(Get-ADSyncGlobalSettings).Parameters | select Name,Value > $Logpath\CONFIG\AADC\ADSyncGlobalSettings.txt
Get-ADSyncScheduler > $Logpath\CONFIG\AADC\ADSyncScheduler.txt

Get-ADSyncSchedulerConnectorOverride > $Logpath\CONFIG\AADC\ADSyncSchedulerConnectorOverride.txt
Get-ADSyncServerConfiguration -Path $Logpath\CONFIG\AADC\
Get-ADSyncRule | FL > $Logpath\CONFIG\AADC\ADSyncRule.txt
$HealthProxyFile = "$Logpath\CONFIG" +"\HealthProxyConfig.txt"
Get-AzureADConnectHealthProxySettings | Out-File -FilePath "$Logpath\CONFIG\AADC\" + $HealthProxyFile -Append
GetPassHashSyncStatus -OutLogFilePath $Logpath\CONFIG\AADC

$MachineconfigFile = $env:windir + "\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
Copy-Item -Path $MachineconfigFile -Destination $Logpath\CONFIG\GENERAL
msinfo32 /nfo $Logpath\CONFIG\GENERAL\system.nfo
tasklist /svc >> $Logpath\CONFIG\GENERAL\tasklist.txt
Get-HotFix | Export-Csv -Path $Logpath\CONFIG\GENERAL\Hotfix.csv


###############
# Colloect CS Export Errors
###############
if(test-path $Logpath\CSEXPORT){}else{new-item -ItemType Directory -Path $Logpath\CSEXPORT }
if($GetObj -eq $True){
    if(test-path $Logpath\GETOBJ){}else{new-item -ItemType Directory -Path $Logpath\GETOBJ}
}
GetCSExport | Out-Null

###############
# Collect Eventolog and other information
###############
if(test-path $Logpath\EVENTLOG){}else{new-item -ItemType Directory -Path $Logpath\EVENTLOG }

wevtutil epl system $Logpath\EVENTLOG\SystemEvent.evtx
wevtutil epl Application $Logpath\EVENTLOG\Application.evtx
wevtutil epl Security $Logpath\EVENTLOG\Security.evtx
wevtutil epl Microsoft-Windows-CAPI2/Operational $Logpath\EVENTLOG\CAPI2_Operational.evtx

wevtutil epl Microsoft-AzureADConnect-AgentUpdater/Admin $Logpath\EVENTLOG\Microsoft_AzureADConnect_AgentUpdater_Admin.evtx > $null 2>&1
wevtutil epl Microsoft-AzureADConnect-AuthenticationAgent/Admin $Logpath\EVENTLOG\Microsoft_AzureADConnect_AuthenticationAgent_Admin.evtx > $null 2>&1

###############
# Collect Tracelog
###############
if(test-path $Logpath\AADCTRACE){}else{new-item -ItemType Directory -Path $Logpath\AADCTRACE }
$tracePath = $env:programdata + "\AADConnect"
copy-item $tracePath $Logpath\AADCTRACE -Recurse
$passthrougtracePath = $env:programdata + "\Microsoft\Azure AD Connect Authentication Agent\Trace\"
copy-item $passthrougtracePath $Logpath\AADCTRACE -Recurse



###############
# Collect Run History
###############
if(test-path $Logpath\RUNHISTORY){}else{new-item -ItemType Directory -Path $Logpath\RUNHISTORY }
Set-Location -Path $Logpath\RUNHISTORY

GetSyncHistoryLog -OutLogFilePath $Logpath\RUNHISTORY

#region
$Global:GetRunHistoryColumnName=""  
$Global:GetRunHistoryColumnData=""
$Global:GetRunHistoryErrorStackData=""
$Global:GetRunStepNumber=0 

$OutFileHistory = ".\RUNHISTORY_CSV.csv" 
$OutFileCompleteRunHistory = ".\RUNHISTORY_ALL.txt" 
$OutXmlCompleteRunHistory = ".\RUNHISTORY_ALL.xml"
$OutErrorStackHistory = ".\RUNHISTORY_SyncErrorDetail.TXT"

$RunStartDate=(Get-Date (Get-Date).AddDays(-$days) -Format yyyy-MM-dd) 
$GetRunStartTime="RunStartTime >'"+$RunStartDate+"'" 
#$GetRunHistoryNotSuccess = Get-WmiObject -class "MIIS_RunHistory" -namespace root\MicrosoftIdentityintegrationServer -Filter $GetRunStartTime 
try  {
    $GetRunHistoryNotSuccess = Get-WmiObject -class "MIIS_RunHistory" -namespace root\MicrosoftIdentityintegrationServer -Filter $GetRunStartTime
}
catch  {
    Write-Error "There was a problem calling WMI Namespace 'root\MicrosoftIdentityintegrationServer'. Exiting."
	return
}



if( $GetRunHistoryNotSuccess -ne $null )   { 
    $sRunHistoryString="" 
    $GetRunHistoryData="" 
    $RunHistoryNames=""
	$xmlData = @()
	$totalItems = $GetRunHistoryNotSuccess.Count
    $i = 0
	
    foreach( $RHERR in $GetRunHistoryNotSuccess )   { 

		Write-Progress -Activity "Exporting Run History" -percentComplete ($i / $totalItems*100)
	
        [xml]$gRunHistory = $RHERR.RunDetails().ReturnValue 
        $gRunHistoryRunDetails = $gRunHistory.DocumentElement["run-details"] 
        BuildRunHistoryData $gRunHistoryRunDetails "ma-name" 0 
        BuildRunHistoryData $gRunHistoryRunDetails "ma-id" 0 
        BuildRunHistoryData $gRunHistoryRunDetails "run-profile-name" 0 
        BuildRunHistoryData $gRunHistoryRunDetails "security-id" 0 
        #step-details ( could have multiple steps, so we will need to loop through ) 
        $GetRunStepDetails= $gRunHistoryRunDetails["step-details"] 
        #step-details information 
        $Global:GetRunStepNumber = $GetRunStepDetails.Attributes.Item(0).Value 
 
        for( [int]$iCounter=0; $iCounter -lt $GetRunStepNumber; $iCounter++ )  { 
            
            if( $iCounter -gt 0 ) { 
                $GetRunStepDetails = $GetRunStepDetails.NextSibling 
            } 
            
            #step-details 
            BuildRunHistoryData $GetRunStepDetails.Attributes.Item(0) $GetRunStepDetails.Attributes.Item(0).Name 5 
            BuildRunHistoryData $GetRunStepDetails "step-result" 0 
            BuildRunHistoryData $GetRunStepDetails "start-date" 0 
            BuildRunHistoryData $GetRunStepDetails "end-date" 0 
 
            #MA Connection Information 
            $GetMAConnection=$GetRunStepDetails["ma-connection"] 
            BuildRunHistoryData $GetMAConnection "connection-result" 0 
            BuildRunHistoryData $GetMAConnection "server" 0 
 
            #Step-Description 
            $GetRunStepDescription= $GetRunStepDetails["step-description"] 
            BuildRunHistoryData $GetRunStepDescription "partition" 0 
            BuildRunHistoryData $GetRunStepDescription "step-type" 3 
 
            #Custom Data 
            $GetCustomData = $GetRunStepDescription["custom-data"] 
            BuildRunHistoryData $GetCustomData.FirstChild "batch-size" 0 
            BuildRunHistoryData $GetCustomData.FirstChild "page-size" 0 
            BuildRunHistoryData $GetCustomData.FirstChild "time-limit" 0 
 
            #inbound-flow-counters 
            BuildRunHistoryData $GetRunStepDetails "inbound-flow-counters" 1 
            BuildRunHistoryData $GetRunStepDetails "export-counters" 1 
 
            #Synchronization Errors 
            $GetSynchronizationErrors=$GetRunStepDetails["synchronization-errors"] 
 
            if( -not $GetSynchronizationErrors.IsEmpty )  { 
                #BuildRunHistoryData $GetSynchronizationErrors.FirstChild "error-type" 0 
                #BuildRunHistoryData $GetSynchronizationErrors.FirstChild "algorithm-step" 0 
                
                foreach($errors in $GetSynchronizationErrors.ChildNodes){
                    $GetSyncErrorInfo = $errors."extension-error-info" 
                    if( $GetSyncErrorInfo -ne $null )  { 
                        $Global:GetRunHistoryErrorStackData = "++++++++++`r`nMA-NAME :"+ $gRunHistoryRunDetails.'ma-name'+"`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "CS GUID :" + $Errors.'cs-guid' + "`r`n" 
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "DN :" + $Errors.'dn' + "`r`n" 
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Sync Start Date :" + $gRunHistoryRunDetails.'step-details'.'start-date' +"`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Sync End Date :" + $gRunHistoryRunDetails.'step-details'.'end-date' +"`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "First Error Occurred :" + $Errors.'first-occurred' + "`r`n"
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Date Error Occurred :" + $Errors.'date-occurred' + "`r`n" 
                        $Global:GetRunHistoryErrorStackData = $Global:GetRunHistoryErrorStackData + "Error Type :" + $Errors.'error-type' + "`r`n"

                        BuildRunHistoryData $GetSyncErrorInfo "call-stack" 0 
                        if($Global:GetRunHistoryErrorStackData -ne ""){
                                $Global:GetRunHistoryErrorStackData| OUT-FILE -Append $OutErrorStackHistory         
                        }

                    } 
                    if( -not $RunHistoryNames.Contains("call-stack") )  { 
                        $RunHistoryNames = $GetRunHistoryColumnName 
                    } 
                }
            } 

            if( $GetRunStepNumber -gt 1 )  { 
                $Global:GetRunHistoryColumnData = $Global:GetRunHistoryColumnData+"`n`t`t`t" 
            } 
        } 
 
        if($sRunHistoryString -eq "")  {
            $sRunHistoryString = $Global:GetRunHistoryColumnData 
        }
        else   { 
            $sRunHistoryString = $sRunHistoryString+"`r"+$GetRunHistoryColumnData 
        } 


        $Global:GetRunHistoryColumnData=""
        $Global:GetRunHistoryErrorStackData= ""
 
        if($RunHistoryNames -eq "")  { 
            $RunHistoryNames = $GetRunHistoryColumnName 
        }
        else   { 
            $RunHistoryNames = $RunHistoryNames 
        }
        if($dumpAllData -eq $true){
            if($AllDataMode -eq "TXT"){
                $RHERR.RunDetails() | Out-File -Append $OutFileCompleteRunHistory
            }
            $xmlData += $RHERR.RunDetails()
        }
		$i++
    }
 
    if($GetRunHistoryData -eq "")   {
     
        $RunHistoryNames | Out-File -Append $OutFileHistory 
    } 
    $GetRunHistoryData = $sRunHistoryString 
    $GetRunHistoryData | Out-File -Append $OutFileHistory 
    $sRunHistoryString = "" 
    $RunHistoryNames = "" 
    if(($dumpAllData -eq $true) -and ($AllDataMode -eq "XML")){
        $xmlData | Export-Clixml $OutXmlCompleteRunHistory
    }
}
Set-Location -Path $CurrentPath

#endregion
