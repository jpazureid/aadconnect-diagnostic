# Get-AADCDiagData
    
## Description

Get diagnostic data of Azure AD Connect
    
    
## Syntax

```PowerShell
Get-AADCDiagData [[-days] <Int32>] [[-logpath] <String>] [[-dumpAllData] <Object>] [[-AllDataMode] <Object>] [[-TraceON] <Boolean>] [<CommonParameters>]
``` 

## Parameters

### `-days`
Days to save run-history

| | |
|:-----------|------------:|
| Type: | Int32 |
| Position: | 1 |
| Default value: | 7 |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |


### `-logpath`
Path to save the output

| | |
|:-----------|------------:|
| Type: | String |
| Position: | 2 |
| Default value: | c:\AADCLOG |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |

        
### `-dumpAllData`
Get all dump details

| | |
|:-----------|------------:|
| Type: | Boolean |
| Position: |  3 |
| Default value: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |
        
### `-AllDataMode`
File format of run-history: "TXT" or "XML"
        
| | |
|:-----------|------------:|
| Type: | String |
| Position: | 4 |
| Default value:| TXT |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |
        
### `-TraceON`
Get network trace when this parameter is set to True

| | |
|:-----------|------------:|
| Type: | Boolean |
| Position: | 5 |
| Default value: | False |
| Accept pipeline input: | False |
| Accept wildcard characters: | False |
        

## Exmaples
    
### EXAMPLE 1
Save the diagnostic data to the specified directory

```PowerShell
C:\PS>Get-AADCDiagData.ps1 -logpath .\AADCLOG
```

### EXAMPLE 2
Save the network trace together

```PowerShell
C:\PS>Get-AADCDiagData.ps1 -TraceON $True
```

### EXAMPLE 3
Run the script when running script is restricted

```PowerShell
C:\PS>Powershell.exe -ExecutionPolicy RemoteSigned -File .\Get-AADCDiagData.ps1
```
