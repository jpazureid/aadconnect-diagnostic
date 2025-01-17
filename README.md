# AADC (Microsoft Entra Connect Sync) サーバーの一括情報採取ツール

本スクリプトは、AADC サーバーの情報を一括で採取します。発生している問題ごとに、採取手順を用意しました。サポートエンジニアより依頼がありました際には、各項目の内容を確認し、情報を採取ください。

## 簡易取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先>
    ```

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## オブジェクト情報 (AD/CS/MV) の取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 以下のように、ドメイン名とオブジェクトの DN (DistinguishName) 値を指定してスクリプトを実行します。 

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -GetObjDomainName "<ドメイン名>" -GetObjADdn "<DN 値>" -DomainAdminName "ドメイン管理者名" -DomainAdminPassword "ドメイン管理者パスワード"
    ```
    例: 
    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath "C:\Tmp" -GetObjDomainName "contoso.com" -GetObjADdn "CN=user01,OU=users,DC=contoso,DC=com" -DomainAdminName "consoto\admin01" -DomainAdminPassword "Password"
    ```
    
4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## シナリオ トレース (オブジェクト同期、パスワード ハッシュ同期、パスワード ライトバック) の取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor DirSyncAndPHSAndPWB
    ```

> [!WARNING]
> 上記コマンドを実行すると Azure AD Connect の下記サービスが再起動します。
> 
> **Microsoft Azure AD Sync**
>
> サービスは直ぐに起動されますのでサービス提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は "y" を入力して進めてください。)

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## シナリオ トレース (パススルー認証) の取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor PathThroughAuth
    ```

> [!WARNING]
> 上記コマンドを実行すると Azure AD Connect Passthrough Authentication の下記サービスが再起動します。
>
> **Microsoft Azure AD Connect Authentication Agent**
> 
> サービスは直ぐに起動されますのでサービス提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は "y" を入力して進めてください。)

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## シナリオ トレース (Azure AD Connect Health for Sync) の取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor Health
    ```

> [!WARNING]
> 上記コマンドを実行すると Azure AD Connect Health for Sync の下記 2 つのサービスが再起動します。
>
> **Azure AD Connect Health Sync Insights Service**
> **Azure AD Connect Health Sync Monitoring Service**
>
> サービスは直ぐに起動されますのでサービス提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は ”y” を入力して進めてください。)

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## シナリオ トレース (構成ウィザードまたはその他のシナリオ) の取得

1. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-AADCDiagData.ps1 を取得します。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceFor ConfiguraionOrOtherthing
    ```

    上記を実行すると以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

    ```
    Please start configuration steps or other scenarios.
    If you have finished all steps, then close configuration wizard and press enter here...:
    ```

4. 構成ウイザードなどを進め、エラー事象を再現します。
5. エラー再現後は、手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

    ※構成ウィザードを実行した場合は、構成ウィザードを閉じてから Enter を押してください。

6. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## エラーが出力される場合

以下のようなエラーが出力した場合は、スクリプトを後述のとおり実行ください。

![image](/images/pserror.png)

```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> }
```

## Microsoft Entra Connect v2.4.18.0 以降のバージョンをご利用の方へ

Microsoft Entra Connect [v2.4.18.0 でリリースされた機能](https://learn.microsoft.com/ja-jp/entra/identity/hybrid/connect/reference-connect-version-history#updated-features) により、ADSync PowerShell モジュールのコマンドレットのうち一部のコマンドを実行すると、Entra ID の管理者 (グローバル管理者 もしくは ハイブリッド ID の管理者) の資格情報の入力が求められます。各手順で利用するスクリプト (Get-AADCDiagData.ps1) 内には、資格情報の入力が必要なコマンドが含まれております。つきましては、以下のように "AADUserName" の入力を求められた場合には、Entra ID の管理者 (グローバル管理者 もしくは ハイブリッド ID の管理者) の UPN を入力し、Enter キーを押して、ログインしたうえで後続の手順を実施ください。

![image](/images/aadusername.png)
