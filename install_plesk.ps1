$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") # REFRESH PATH
$ScriptDir = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent
$ISVM = (Get-WmiObject -Class Win32_ComputerSystem).Model | Select-String -Pattern "KVM|Virtual" -Quiet

echo "Installing dependencies..."
echo "Installing Chocolatey..."
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") # REFRESH PATH

choco install googlechrome -y

echo "Downloading Plesk installer..."
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force
$Url = "https://installer-win.plesk.com/plesk-installer.exe"
$Output = "C:\Windows\Temp\plesk-installer.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile( $url , $Output)

echo "Running Plesk installer..."
&"$Output" --select-product-id=panel --select-release-latest `
--install-component panel `
--install-component awstats `
--install-component mailenable `
--install-component dns `
--install-component spamassassin `
--install-component mysql-odbc `
--install-component mylittleadmin `
--install-component webalizer `
--install-component mssql2019 `
--install-component webmail `
--install-component plesk-urlprotection `
--install-component webdeploy `
--install-component urlrewrite `
--install-component health-monitoring `
--install-component gitforwindows `
--install-component plesk-migration-manager `
--install-component msodbcsql11 `
--install-component msodbcsql13 `
--install-component msodbcsql17 `
--install-component mariadb103-client `
--install-component mysql-odbc53 `
--install-component modsecurity `
--install-component php56 `
--install-component php70 `
--install-component php71 `
--install-component php72 `
--install-component php73 `
--install-component php74 `
--install-component webdav `
--install-component dotnetcoreruntime `
--install-component aspnetcore `
--install-component appinit `
--install-component http-dynamic-compression `
--install-component cloudflare `
--install-component git `
--install-component letsencrypt

$env:plesk_dir = [System.Environment]::GetEnvironmentVariable("plesk_dir", "Machine") # REFRESH PLESK PATH
$env:plesk_bin = $env:plesk_dir + "bin"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") # REFRESH PATH

$AdminPassword = Read-Host -Prompt 'Password usuario "Administrator" '

echo "Initial Plesk configuration..."
& "$env:plesk_bin\init_conf.exe" -p -passwd "$AdminPassword" -license_agreed true -admin_info_not_required true

echo "Installing license..."
Add-Content -Path "$env:plesk_dir\admin\conf\panel.ini" -Value "[license]"
Add-Content -Path "$env:plesk_dir\admin\conf\panel.ini" -Value "fileUpload = on"

net stop plesksrv
net start plesksrv

Write-Host -NoNewLine 'At this point install the Plesk license (XML or key) using the web panel and then press enter...';
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

#& "$env:plesk_bin\license.exe" -i $License

echo "Configuring Plesk..."

echo "Setting language..."
& "$env:plesk_bin\locales.exe" --set-default en-US

echo "Configuring GUI Links..."
& "$env:plesk_bin\panel_gui.exe" -p -domain_registration true -cert_purchasing true

echo "Configuring the server..."
& "$env:plesk_bin\server_pref.exe" --update -include-remote-databases false -forbid-subscription-rename true -forbid-create-dns-subzone true -min_password_strength strong
& "$env:plesk_bin\admin.exe" --update -multiple-sessions true
& "$env:plesk_bin\domain_restriction.exe" --enable
& "$env:plesk_bin\poweruser.exe" --off

echo "Setting IIS Pools..."
& "$env:plesk_bin\server_pref.exe" --set-iis-app-pool-settings -cpu-usage-state true -cpu-usage-value 20 -cpu-usage-action Throttle
& "$env:plesk_bin\server_pref.exe" -u -idle-timeout 60

echo "Configuring Firewall..."
if([System.IO.File]::Exists("$Env:Programfiles (x86)\Mail Enable\Bin64\MESMTPC.exe")){
	netsh advfirewall firewall add rule name="MESMTPC.exe (MailEnable SMTP Connector)" dir=out program="%ProgramFiles% (x86)\Mail Enable\Bin64\MESMTPC.exe" protocol=tcp  action=allow

}
if([System.IO.File]::Exists("$Env:Programfiles (x86)\Plesk\Mail Servers\Mail Enable\Bin64\MESMTPC.exe")){
        netsh advfirewall firewall add rule name="MESMTPC.exe (MailEnable SMTP Connector)" dir=out program="%ProgramFiles% (x86)\Plesk\Mail Servers\Mail Enable\Bin64\MESMTPC.exe" protocol=tcp  action=allow
}

netsh advfirewall firewall add rule name="Allow OUT TCP" dir=out remoteport="20,21,37,43,53,80,110,113,443,873,3306,1433,6363,5224,1688" protocol=tcp  action=allow
netsh advfirewall firewall add rule name="Allow OUT UDP" dir=out remoteport="53" protocol=udp  action=allow
netsh advfirewall firewall add rule name="Allow OUT ICMP" protocol=icmpv4:any,any dir=out action=allow
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

echo "Configuring mail..."
& "$env:plesk_bin\mailserver.exe" --enable-outgoing-antispam
& "$env:plesk_bin\mailserver.exe" --set-outgoing-messages-subscription-limit 200
& "$env:plesk_bin\mailserver.exe" --set-outgoing-messages-domain-limit 200
& "$env:plesk_bin\mailserver.exe" --set-maps-zone "zen.spamhaus.org,bl.spamcop.net,b.barracudacentral.org"
& "$env:plesk_bin\mailserver.exe" --set-maps-status true
& "$env:plesk_bin\spamassassin.exe" --update-server -status true

echo "Configuring php.ini..."
Get-ChildItem "$env:plesk_dir\Additional\" -Recurse -Filter "php.ini" |
Foreach-Object {
	echo "Processing "$_.FullName
    $content = Get-Content $_.FullName
	$content | %{$_ -replace "^memory_limit.*","memory_limit = 1024M"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^enable_dl.*","enable_dl = Off"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^expose_php.*","expose_php = Off"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^disable_functions.*","disable_functions = apache_get_modules,apache_get_version,apache_getenv,apache_note,apache_setenv,disk_free_space,diskfreespace,dl,exec,highlight_file,ini_alter,ini_restore,openlog,passthru,phpinfo,popen,posix_getpwuid,proc_close,proc_get_status,proc_nice,proc_open,proc_terminate,shell_exec,show_source,symlink,system,eval,debug_zval_dump"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^upload_max_filesize.*","upload_max_filesize = 16M"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^post_max_size.*","post_max_size = 16M"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^date.timezone.*",'date.timezone = "America/Argentina/Buenos_Aires"'} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^allow_url_fopen.*","allow_url_fopen = On"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^max_execution_time.*","max_execution_time = 120"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^max_input_time.*","max_input_time = 120"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^max_input_vars.*","max_input_vars = 2000"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^display_errors.*","display_errors = On"} | Set-Content $_.FullName
	$content = Get-Content $_.FullName
	$content | %{$_ -replace "^error_reporting.*","error_reporting = E_ALL & ~E_DEPRECATED & ~E_STRICT"} | Set-Content $_.FullName
        $content = Get-Content $_.FullName
        $content | %{$_ -replace "^;extension=odbc","extension=odbc"} | Set-Content $_.FullName
        $content = Get-Content $_.FullName
        $content | %{$_ -replace "^;extension=pdo_odbc","extension=pdo_odbc"} | Set-Content $_.FullName
}

echo "Setting up timezone Horde Webmail..."
$hordephpini = "C:\Program Files (x86)\Plesk\Webmail\horde\conf\php.ini"
$content = Get-Content $hordephpini
$content | %{$_ -replace "^date.timezone.*",'date.timezone = "America/New_York"'} | Set-Content $hordephpini

echo "Configuring Backups..."
echo "Downloading scheduled task..."
$Url = "https://raw.githubusercontent.com/diyarit/Plesk-Config/master/Plesk-Backup-Scheduler-1.xml"
$Output = "C:\Windows\Temp\Plesk-Backup-Scheduler-1.xml"
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile( $url , $Output)

# BACKUP - HAND MADE SEEING THE DB NO INFO ON THE INTERNET
& "$env:plesk_bin\plesk.exe" "db" "INSERT INTO backupsscheduled VALUES (1,1,'server','local','2018-07-18 10:38:16',86400,'true','false',1,'','',0,'false','true',0,'23:00:00','backup_content_all_at_domain',2592000,1,1,1,NULL);"

& "$env:plesk_bin\plesk.exe" "db" "REPLACE INTO backupsscheduled VALUES (1,1,'server','local','2018-07-18 10:38:16',86400,'true','false',1,'','',0,'false','true',0,'23:00:00','backup_content_all_at_domain',2592000,1,1,1,NULL);" # Replace in case it exists

# Maximum number of full backup files to store (including both scheduled and manual backups)
& "$env:plesk_bin\plesk.exe" "db" "UPDATE misc SET val = '30' WHERE param = 'bu_rotation';"

# IONice
& "$env:plesk_bin\plesk.exe" "db" "UPDATE misc SET val = 'true' WHERE param = 'bu_nice';"

# Excluded files
& "$env:plesk_bin\plesk.exe" "db" "INSERT INTO backupexcludefiles VALUES (1,'/httpdocs/App_Data/cache/*\r\n/httpdocs/App_Data/tmp/*');"
& "$env:plesk_bin\plesk.exe" "db" "REPLACE INTO backupexcludefiles VALUES (1,'/httpdocs/App_Data/cache/*\r\n/httpdocs/App_Data/tmp/*');"

Register-ScheduledTask -Xml (get-content "C:\Windows\Temp\Plesk-Backup-Scheduler-1.xml" | out-string) -TaskName 'Plesk-Backup-Scheduler-1' -User "SYSTEM"

echo "Configuring SQL Server..."
echo "Opening port 1433 (SQL Express)..."
$env:PSModulePath = $env:PSModulePath + ";C:\Program Files (x86)\Microsoft SQL Server\140\Tools\PowerShell\Modules"
Import-Module "sqlps"

$MachineObject = new-object ('Microsoft.SqlServer.Management.Smo.WMI.ManagedComputer') .

$serverinstance = $MachineObject | select-object -expand ServerInstances | select-object -expand Name
$ProtocolUri = "ManagedComputer[@Name='" + (get-item env:computername).Value + "']/ServerInstance[@Name='$serverinstance']/ServerProtocol"

$tcp = $MachineObject.getsmoobject($ProtocolUri + "[@Name='Tcp']")
$np = $MachineObject.getsmoobject($ProtocolUri + "[@Name='Np']")
$sm = $MachineObject.getsmoobject($ProtocolUri + "[@Name='Sm']")

$np.IsEnabled = $true
$np.alter()
$tcp.IsEnabled = $true
$tcp.alter()

$MachineObject.getsmoobject($tcp.urn.Value + "/IPAddress[@Name='IPAll']").IPAddressProperties[1].Value = "1433"
$tcp.alter()

Restart-Service -displayname "*MSSQLSERVER*" -Exclude "*Agent*"

if ($ISVM) {
        echo "VM detected, deactivating Health Monitor / Notifier because it consumes a lot and hangs..."
	Set-Service ParallelsHealthMonitor -StartupType Disabled
	#Set-Service ParallelsHealthNotifier -StartupType Disabled

	Stop-Service ParallelsHealthMonitor
	#Stop-Service ParallelsHealthNotifier

	#stop-process -name "Parallels.MonitorSrv" -force
}

echo "Configuring packages..."
cmd /c '"%plesk_bin%/service_plan.exe" -c "Default Plan" -hosting true -disk_space 10G -quota 10G -max_traffic 200G -max_dom_aliases 10 -overuse block -disk_space_soft 80% -max_traffic_soft 80% -max_box -1 -mbox_quota 11G -total_mboxes_quota 10G -max_wu 100 -max_subftp_users 20 -max_mysql_db 10 -max_mssql_db 1 -mysql_dbase_space 1G -mssql_dbase_space 1G -mssql_dbase_filesize 500M -mssql_dbase_log_filesize 500M -max_maillists 0 -max_subdom 10 -max_site 1 -max_odbc 10 -max_site_builder 0 -mail true -maillist false -wuscripts true -sb_publish false -ssl true -php false -asp.net true -asp.net_version 4.0 -upsell_site_builder false -webstat awstats -err_docs true -iis_app_pool true -idle_timeout 60 -cpu_usage 20 -max_worker_processes 1 -bandwidth 256K -max_connections 100 -webmail horde -create_domains false -manage_phosting true -manage_php_settings true -manage_php_version true -manage_subdomains true -manage_domain_aliases true -manage_subftp true -manage_crontab true -manage_mail_settings true -manage_maillists false -manage_spamfilter true -manage_virusfilter false -manage_iis_app_pool true -remote_db_connection false -manage_protected_dirs true -manage_website_maintenance false -allow_local_backups true -allow_account_local_backups true -allow_ftp_backups false -allow_account_ftp_backups false -access_appcatalog false -manage_additional_permissions false -webdeploy true -asp true -write_modify false -iis_app_pool_addons false -cpu-usage-action Throttle -log-rotate true -log-bysize 10M -log-max-num-files 5 -log-compress true -keep_traf_stat 3'
echo "Activating Lets Encrypt in default package..."
cmd /c '"%plesk_bin%/service_plan.exe" --add-custom-plan-item "Default Plan" -custom-plan-item-name "urn:ext:letsencrypt:plan-item-sdk:keep-secured"'

echo "Deleting additional packages..."
& "$env:plesk_bin\service_plan.exe" --remove "Default Simple"
& "$env:plesk_bin\service_plan.exe" --remove "Unlimited"

echo "Configuring MailEnable..."
$hostname = [System.Net.Dns]::GetHostByName(($env:computerName)).HostName
$dnsCGSetting = Get-DnsClientGlobalSetting

Set-Itemproperty -path 'HKLM:\SOFTWARE\WOW6432Node\Mail Enable\Mail Enable\Connectors\SMTP' -Name 'Host Name' -value $hostname
Set-Itemproperty -path 'HKLM:\SOFTWARE\WOW6432Node\Mail Enable\Mail Enable\Connectors\SMTP' -Name 'Local Domain Name' -value $dnsCGSetting.SuffixSearchList

Restart-Service -Name "MailEnable SMTP Connector"

echo "Setting up Plesk session time..."
plesk db "update misc set val=600 where param='login_timeout'"

echo "Setting up SSL notifications ..."
& "$env:plesk_bin\notification.exe" --update -code ext-letsencrypt-notification-certificateAutoRenewalSucceed -send2admin false -send2reseller false -send2client false -send2email false
& "$env:plesk_bin\notification.exe" --update -code ext-letsencrypt-notification-certificateAutoRenewalFailed -send2admin false -send2reseller false -send2client false -send2email false
& "$env:plesk_bin\notification.exe" --update -code ext-sslit-notification-certificateAutoRenewalSucceed -send2admin false -send2reseller false -send2client false -send2email false
& "$env:plesk_bin\notification.exe" --update -code ext-sslit-notification-certificateAutoRenewalFailed -send2admin false -send2reseller false -send2client false -send2email false

echo "Reparando CVE MyLittleAdmin..."
# https://support.plesk.com/hc/en-us/articles/360013996240-CVE-2020-13166-myLittleAdmin-vulnerability
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") # REFRESH PATH
[xml]$xml = Get-Content "$env:PLESK_DIR\MyLittleAdmin\web.config"
$xml.save("$env:PLESK_DIR\MyLittleAdmin\web.config.bak") # BACKUP
$xml.SelectNodes("//machineKey[.]") | % { $_.ParentNode.RemoveChild($_) }
$xml.save("$env:PLESK_DIR\MyLittleAdmin\web.config")

echo "Final cleaning..."
Remove-Item (Get-PSReadlineOption).HistorySavePath
Remove-Item -Path $MyInvocation.MyCommand.Source

echo "Finalized!"
