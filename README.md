<<<<<<< HEAD
# Microsoft Entra Connect サーバー情報一括採取ツール
=======
# AADC (Microsoft Entra Connect Sync) サーバーの一括情報採取ツール
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

本スクリプトは、AADC サーバーの情報を一括で採取します。発生している問題ごとに、採取手順を用意しました。サポートエンジニアより依頼がありました際には、各項目の内容を確認し、情報を採取ください。

<<<<<<< HEAD
本スクリプトは、Microsoft Entra Connect の情報を一括で採取します。Microsoft Entra Connect サーバー上で管理者の PowerShell プロンプトを起動したうえでスクリプトを実行ください。
  
<br>
<br>

## Microsoft Entra Connect サーバー情報一括採取ツールの手順

### 事前準備

1. Microsoft Entra Connect サーバーに管理者としてログインします。

2. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-MECDiagData.ps1 を取得します。

3. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。

<br>
<br>

### 簡易取得
=======
## 簡易取得
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

1. 下記のように実行します。

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先>
    ```

2. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

## オブジェクト情報 (AD/CS/MV) の取得

1. 以下のように、対象オブジェクトの DN (DistinguishName) 値と対象オブジェクトが所属するドメイン名を指定してスクリプトを実行します。 

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -GetObjDomainName "<ドメイン名>" -GetObjADdn "<DN 値>" -DomainAdminName "ドメイン管理者名" -DomainAdminPassword "ドメイン管理者パスワード"
    ```
    例: 
    ```powershell
    .\Get-MECDiagData.ps1 -Logpath "C:\Tmp" -GetObjDomainName "contoso.com" -GetObjADdn "CN=user01,OU=users,DC=contoso,DC=com" -DomainAdminName "consoto\admin01" -DomainAdminPassword "Password"
    ```
    
2. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<<<<<<< HEAD
<br>
<br>

### シナリオトレース
=======
## シナリオ トレース (オブジェクト同期、パスワード ハッシュ同期、パスワード ライトバック) の取得
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

各シナリオに併せてトレースログを取得します。

<br>
<br>

##### 全シナリオ共通の事前作業
1. [スタート] - [ファイル名を指定して実行] を順に選択し、eventvwr と入力後 OKボタンをクリックします。イベントビューアが開きます。
 
2. [アプリケーションとサービス ログ] - [Micorosoft] - [Windows] - [CAPI2] - [Operational] を右クリックし、プロパティを開きます。

3. プロパティ画面にて、[ログの有効化] にチェックを入れます。

4. プロパティ画面にて、[最大ログ サイズ] を、"10240” に変更し、OK ボタンをクリックします。

<br>
<br>

##### パスワードハッシュ同期でエラーが発生している場合

1. 下記のように実行します。

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -NetTrace $true
    ```

<<<<<<< HEAD
	以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

		Please start steps. You can press enter when you finish all steps.....

=======
> [!WARNING]
> 上記コマンドを実行すると Azure AD Connect の下記サービスが再起動します。
> 
> **Microsoft Azure AD Sync**
>
> サービスは直ぐに起動されますのでサービス提供に問題はございませんが、サービス監視を実施されている場合は、監視ソフトにアラートが表示される可能性がございますのでご留意ください。(問題がない場合は "y" を入力して進めてください。)
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

2. 3 分ほど待機します。

3. [Azure AD Connect] 構成ウィザードを起動します。
 
4. [構成] - [トラブルシューティング] - [次へ] - [起動] とクリックします。
 
5. ”2”(Troubleshoot Password Hash Synchronization) を入力してEnter を押下します。
 
6. "2" (Password Hash Synchronization does NOT work for a specific user account)  を入力してEnter を押下します。
 
7. ドメイン名の入力を求められた場合は、パスワード同期できていないユーザーが所属しているドメイン名を入力します。
 
8. [Please enter AD connector space object Distinguished Name:] でパスワード同期できていないユーザーの distinguishedName 属性を入力してEnter を押下します。
 
9. 手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

	※以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

        Stopped all trace logs. Please wait for a while.

10. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<<<<<<< HEAD
<br>
<br>

##### 構成ウィザードでエラーが発生している場合
=======
## シナリオ トレース (パススルー認証) の取得
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

1. 下記のように実行します。

    ```powershell
<<<<<<< HEAD
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -NetTrace $true
    ```

	上記を実行すると以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

		Please start steps. You can press enter when you finish all steps.....
=======
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
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

    ```
    Please start configuration steps or other scenarios.
    If you have finished all steps, then close configuration wizard and press enter here...:
    ```

<<<<<<< HEAD
2. 構成ウイザードを進め、エラー事象を再現します。

3. エラー再現後は、手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

	※構成ウィザードを実行した場合は、構成ウィザードを閉じてから Enter を押してください。以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。
=======
4. 構成ウイザードなどを進め、エラー事象を再現します。
5. エラー再現後は、手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

    ※構成ウィザードを実行した場合は、構成ウィザードを閉じてから Enter を押してください。
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

        Stopped all trace logs. Please wait for a while.


4. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<<<<<<< HEAD
<br>
<br>

##### 全シナリオ共通の事後作業
1. [スタート] - [ファイル名を指定して実行] を順に選択し、eventvwr と入力後 OKボタンをクリックします。イベントビューアが開きます。
 
2. [アプリケーションとサービス ログ] - [Micorosoft] - [Windows] - [CAPI2] - [Operational] を右クリックし、プロパティを開きます。

3. プロパティ画面にて、[ログの無効化] にチェックを入れます。

<br>
<br>
=======
## エラーが出力される場合

以下のようなエラーが出力した場合は、スクリプトを後述のとおり実行ください。
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c

![image](/images/pserror.png)

・簡易取得の場合
```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> }
```

<<<<<<< HEAD
・オブジェクト情報 (AD/CS/MV) 取得の場合
```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -GetObjDomainName "<ドメイン名>" -GetObjADdn "<DN 値>" -DomainAdminName "ドメイン管理者名" -DomainAdminPassword "ドメイン管理者パスワード"}
```

・シナリオトレースの場合
```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -NetTrace $true}
```
=======
## Microsoft Entra Connect v2.4.18.0 以降のバージョンをご利用の方へ

Microsoft Entra Connect [v2.4.18.0 でリリースされた機能](https://learn.microsoft.com/ja-jp/entra/identity/hybrid/connect/reference-connect-version-history#updated-features) により、ADSync PowerShell モジュールのコマンドレットのうち一部のコマンドを実行すると、Entra ID の管理者 (グローバル管理者 もしくは ハイブリッド ID の管理者) の資格情報の入力が求められます。各手順で利用するスクリプト (Get-AADCDiagData.ps1) 内には、資格情報の入力が必要なコマンドが含まれております。つきましては、以下のように "AADUserName" の入力を求められた場合には、Entra ID の管理者 (グローバル管理者 もしくは ハイブリッド ID の管理者) の UPN を入力し、Enter キーを押して、ログインしたうえで後続の手順を実施ください。

![image](/images/aadusername.png)
>>>>>>> c2ee9d080c9962fa9adb8acdd84d92657987b55c
