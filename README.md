# AADC サーバー情報一括採取ツール

## 概要

本スクリプトは、AADC サーバーの情報を一括で採取します。本スクリプトにて採取する資料は、以下の弊社 Blog に公開されたものが中心となります。

[\[調査に有効な採取情報\] Azure AD Connect サーバーの全般情報](https://github.com/jpazureid/blog/blob/master/azure-active-directory-connect/general-information.md )
  
## AADC サーバー情報一括採取ツールの手順

### 簡易取得 (GetObj なし, NetTrace なし)

1. Clone or download より Get-AADCDiagData.ps1 をダウンロードします。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先>
    ```

    スクリプトの実行が許可されていない場合 (Restricted) は、下記コマンドを利用してスクリプトを実行することが可能です。

    ```powershell
    Powershell.exe -ExecutionPolicy RemoteSigned -Command {.\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先>}
    ```

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。


### フル取得 (GetObj あり, NetTrace あり)

1. Clone or download より Get-AADCDiagData.ps1 をダウンロードします。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceON $True -GetObj $true
    ```

    * 実行直後に資格情報の入力を求められるので、オンプレミスフォレストの管理者資格情報を入力してください。

    スクリプトの実行が許可されていない場合 (Restricted) は、下記コマンドを利用してスクリプトを実行することが可能です。

    ```powershell
    Powershell.exe -ExecutionPolicy RemoteSigned -Command {.\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -NetTraceON $true -GetObj $true}
    ```

4. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。


### 簡易取得+特定のオブジェクト情報取得 (GetObj あり, NetTrace なし)

1. Clone or download より Get-AADCDiagData.ps1 をダウンロードします。
2. PowerShell プロンプトを管理者として起動し、スクリプトを配置したフォルダーに移動します。
3. 下記のように実行します。

    ```powershell
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先>
    ```

4. 完了したら、続けて、任意のオブジェクトについて、下記のように実行します。

    ```powershell 
    .\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -GetObj $true -ForestName <対象オブジェクトが存在するフォレスト名 (例 : contoso.com)> -ObjectName <オブジェクト名 (例 : user01)>
    ```

    * 実行直後に資格情報の入力を求められるので、オンプレミスフォレストの管理者資格情報を入力してください。
    * ユーザー名には UPN (user01@contoso.com) を入力いただく必要はございません。ユーザー名 (user01) のみ入力ください。 

    スクリプトの実行が許可されていない場合 (Restricted) は、下記コマンドを利用してスクリプトを実行することが可能です。

    ```powershell
    Powershell.exe -ExecutionPolicy RemoteSigned -Command {.\Get-AADCDiagData.ps1 -Logpath <ログファイル出力先> -GetObj $true -ForestName <対象オブジェクトが存在するフォレスト名 (例 : contoso.com)> -ObjectName <オブジェクト名 (例 : user01)}
    ````

5. AADCLOG フォルダーを zip 形式で圧縮し、弊社までご提供ください。