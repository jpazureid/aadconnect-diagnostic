# AADC サーバー情報一括採取ツール

## 概要

本スクリプトは、AADC サーバーの情報を一括で採取します。
  
<br>


## AADC サーバー情報一括採取ツールの手順


### 簡易取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先>
    ```

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### オブジェクト情報 (AD/CS/MV) 取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 以下のように、ドメイン名とオブジェクトの DN (DistinguishName) 値を指定してスクリプトを実行します。 

    ```powershell
    .\Get-AADCDiagData.ps1 -GetObjDomainName "<ドメイン名>" -GetObjADdn "<DN 値>" -DomainAdminName "ドメイン管理者名" -DomainAdminPassword "ドメイン管理者パスワード"
    ```
    例: 
    ```powershell
    .\Get-AADCDiagData.ps1 -GetObjDomainName "contoso.com" -GetObjADdn "CN=user01,OU=users,DC=contoso,DC=com" -DomainAdminName "consoto\admin01" -DomainAdminPassword "Password"
    ```
    
4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### シナリオトレース (オブジェクト同期、パスワードハッシュ同期、パスワードライトバック)

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor DirSyncAndPHSAndPWB
    ```


	**!! ご留意ください !!** 

	Azure AD Connect の下記 サービス再起動します。

	***Microsoft Azure AD Sync***

	サービスは直ぐに起動されますため、サービスの機能提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は ”y” を入力して進めてください。)


4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### シナリオトレース (パススルー認証)

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor PathThroughAuth
    ```

	**!! ご留意ください !!**
	
	Azure AD Connect Passthrough Authentication の下記 サービス再起動します。

	***Microsoft Azure AD Connect Authentication Agent***

	サービスは直ぐに起動されますため、サービスの機能提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は ”y” を入力して進めてください。)

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### シナリオトレース (Azure AD Connect Health for Sync)

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor Health
    ```

	**!! ご留意ください !!**
	
	Azure AD Connect Health for Sync の下記 2 つのサービス再起動します。

	***Azure AD Connect Health Sync Insights Service***
	
	***Azure AD Connect Health Sync Monitoring Service***

	サービスは直ぐに起動されますため、サービスの機能提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は ”y” を入力して進めてください。)

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### シナリオトレース (構成ウィザード)

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor ConfiguraionOrOtherthing
    ```

	上記を実行すると以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

		Please start configuration steps or other scenarios.
		If you have finished all steps, then close configuration wizard and press enter here...:


4. 構成ウイザードなどを進め、エラー事象を再現します。

5. エラー再現後は、手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

	※構成ウィザードを実行した場合は、構成ウィザードを閉じてから Enter を押してください。

6. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>
<br>

## エラーが出力する場合
以下のようなエラーが出力した場合は、スクリプトを後述の通り実行ください。
![image](/images/pserror.png)

```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> }
```

