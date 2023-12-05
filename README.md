# Microsoft Entra Connect サーバー情報一括採取ツール

## 概要

本スクリプトは、Microsoft Entra Connect の情報を一括で採取します。Microsoft Entra Connect サーバー上で管理者の PowerShell プロンプトを起動したうえでスクリプトを実行ください。
  
<br>


## Microsoft Entra Connect サーバー情報一括採取ツールの手順

### 事前準備

1. Microsoft Entra Connect サーバーに管理者としてログインします。

2. [Releases](https://github.com/jpazureid/aadconnect-diagnostic/releases) で最新版の "Source code" をダウンロードし、Get-MECDiagData.ps1 を取得します。

3. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。

### 簡易取得

1. 下記のように実行します。

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先>
    ```

2. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### オブジェクト情報 (AD/CS/MV) 取得

1. 以下のように、対象オブジェクトの DN (DistinguishName) 値と対象オブジェクトが所属するドメイン名を指定してスクリプトを実行します。 

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -GetObjDomainName "<ドメイン名>" -GetObjADdn "<DN 値>" -DomainAdminName "ドメイン管理者名" -DomainAdminPassword "ドメイン管理者パスワード"
    ```
    例: 
    ```powershell
    .\Get-MECDiagData.ps1 -Logpath "C:\Tmp" -GetObjDomainName "contoso.com" -GetObjADdn "CN=user01,OU=users,DC=contoso,DC=com" -DomainAdminName "consoto\admin01" -DomainAdminPassword "Password"
    ```
    
2. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

<br>
<br>

### シナリオトレース

各シナリオに併せてトレースログを取得します。

#### 全シナリオ共通の事前作業
1. [スタート] - [ファイル名を指定して実行] を順に選択し、eventvwr と入力後 OKボタンをクリックします。イベントビューアが開きます。
 
2. [アプリケーションとサービス ログ] - [Micorosoft] - [Windows] - [CAPI2] - [Operational] を右クリックし、プロパティを開きます。

3. プロパティ画面にて、[ログの有効化] にチェックを入れます。

4. プロパティ画面にて、[最大ログ サイズ] を、"10240” に変更し、OK ボタンをクリックします。



#### パスワードハッシュ同期でエラーが発生している場合

1. 下記のように実行します。

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -NetTrace $true
    ```

	上記を実行すると以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

		Please start configuration steps or other scenarios.
		If you have finished all steps, then close configuration wizard and press enter here...:


2. 3 分ほど待機します。

3. [Azure AD Connect] 構成ウィザードを起動します。
 
4. [構成] - [トラブルシューティング] - [次へ] - [起動] とクリックします。
 
5. ”2”(Troubleshoot Password Hash Synchronization) を入力してEnter を押下します。
 
6. "2" (Password Hash Synchronization does NOT work for a specific user account)  を入力してEnter を押下します。
 
7. ドメイン名の入力を求められた場合は、パスワード同期できていないユーザーが所属しているドメイン名を入力します。
 
8. [Please enter AD connector space object Distinguished Name:] でパスワード同期できていないユーザーのdistinguishedName 属性を入力してEnter を押下します。
 
9. 手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

10. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。


#### 構成ウィザードでエラーが発生している場合

1. 下記のように実行します。

    ```powershell
    .\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -NetTrace $true
    ```

	上記を実行すると以下のように表示されますので、 PowerShell ウィンドウはそのまま維持します。

		Please start configuration steps or other scenarios.
		If you have finished all steps, then close configuration wizard and press enter here...:


2. 構成ウイザードを進め、エラー事象を再現します。

3. エラー再現後は、手順 1 で開いた PowerShell ウィンドウ上で Enter キーを入力します。

	※構成ウィザードを実行した場合は、構成ウィザードを閉じてから Enter を押してください。

4. MECLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。

#### 全シナリオ共通の事後作業
1. [スタート] - [ファイル名を指定して実行] を順に選択し、eventvwr と入力後 OKボタンをクリックします。イベントビューアが開きます。
 
2. [アプリケーションとサービス ログ] - [Micorosoft] - [Windows] - [CAPI2] - [Operational] を右クリックし、プロパティを開きます。

3. プロパティ画面にて、[ログの無効化] にチェックを入れます。

<br>
<br>
<br>

## エラーが出力する場合
以下のようなエラーが出力した場合は、スクリプトを後述の通り実行ください。
![image](/images/pserror.png)

・簡易取得の場合
```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> }
```

・オブジェクト情報 (AD/CS/MV) 取得の場合
```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -GetObjDomainName "<ドメイン名>" -GetObjADdn "<DN 値>" -DomainAdminName "ドメイン管理者名" -DomainAdminPassword "ドメイン管理者パスワード"}
```

・シナリオトレースの場合
```powershell
Powershell.exe -ExecutionPolicy ByPass -Command {.\Get-MECDiagData.ps1 -Logpath <ログファイル出力先> -NetTrace $true}
```
