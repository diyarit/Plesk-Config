# Plesk Onyx installation script on Windows Server.

## What it does

 1. Install Plesk Onyx Windows with the recommended packages.
 2. Configure recommended values for visual and basic permissions (forbidden domains, subdomain overlaps, etc).
 3. Configure Windows Firewall with basic rules.
 4. Mailserver: configure AntiSPAM, blacklists and maximum messages per hour.
 5. Configure all php.ini with the recommended values.
 6. Configure scheduled daily backup tasks.
 7. Configure scheduled daily backup tasks.

## How to use it!

 Open a Powershell console and run:

```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
$Url = "https://raw.githubusercontent.com/wnpower/PleskWindows-Config/master/install_pleskonyx.ps1"
$Output = "C:\Windows\Temp\install_pleskonyx.ps1"
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile( $url , $Output)
Invoke-Expression $Output
```
