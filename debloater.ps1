# Disable Xbox features
	Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
	Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
	Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage

# Disable Xbox GameDVR
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "AllowAutoGameMode" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "ShowStartupPanel" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\GameBar" /v "UseNexusForGameBarEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
	reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
	reg.exe add "HKCU\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
	reg.exe add "HKLM\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f

# Turn off the "Try the new Outlook" toggle that turns Outlook Desktop into the new Desktop Web version.
	if((Test-Path -LiteralPath "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\General") -ne $true) { New-Item "HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\General" -force -ea SilentlyContinue };
	New-ItemProperty -LiteralPath 'HKCU:\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\General' -Name 'HideNewOutlookToggle' -Value 1 -PropertyType DWord -Force -ea SilentlyContinue;

# Windows 10 remove Xbox bloatware
	reg.exe add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f
	Stop-Service -Name XblAuthManager
	Set-Service -Name XblAuthManager -StartupType Disabled
	Stop-Service -Name XblGameSave
	Set-Service -Name XblGameSave -StartupType Disabled
	Stop-Service -Name XboxGipSvc
	Set-Service -Name XboxGipSvc -StartupType Disabled
	Stop-Service -Name XboxNetApiSvc
	Set-Service -Name XboxNetApiSvc -StartupType Disabled
	schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable
	takeown /f "%WinDir%\System32\GameBarPresenceWriter.exe" /a
	icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant:r Administrators:F /c
	taskkill /im GameBarPresenceWriter.exe /f
	move "C:\Windows\System32\GameBarPresenceWriter.exe" "C:\Windows\System32\GameBarPresenceWriter.OLD"
	takeown /f "%WinDir%\System32\bcastdvr.exe" /a
	icacls "%WinDir%\System32\bcastdvr.exe" /grant:r Administrators:F /c
	taskkill /im bcastdvr.exe /f
	move C:\Windows\System32\bcastdvr.exe C:\Windows\System32\bcastdvr.OLD
	
# Uninstall Microsoft XPS Document Writer
	Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart -WarningAction SilentlyContinue | Out-Null

# Uninstall Work Folders Client
	Disable-WindowsOptionalFeature -Online -FeatureName "WorkFolders-Client" -NoRestart -WarningAction SilentlyContinue | Out-Null
	
# Remove Default Fax Printer
	Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
	
# Disable Windows Update automatic restart
# Note: This doesn't disable the need for the restart but rather tries to ensure that the restart doesn't happen in the least expected moment. Allow the machine to restart as soon as possible anyway.
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoRebootWithLoggedOnUsers /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUPowerManagement /t REG_DWORD /d 0 /f
	
# Disable Windows Defender
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsDefender" -ErrorAction SilentlyContinue
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealth" -ErrorAction SilentlyContinue
	
# Disable Defender Auto Sample Submission
	Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Continue | Out-Null

# Set Control Panel view to Large icons (Classic)
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v StartupPage /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /v AllItemsIconView /t REG_DWORD /d 0 /f
	
# Show all tray icons
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d 0 /f

## EXPLORER ##

# Make Explorer much faster by not scanning for folder types.
	reg.exe add "HKCU\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /v "FolderType" /t REG_SZ /d "NotSpecified" /f

# Hide 3D Objects icon from Explorer namespace - Hides the icon also from personal folders and open/save dialogs
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
	reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f

# Hide 3D Objects icon from This PC - The icon remains in personal folders and open/save dialogs
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f

# Remove Learn more about this image icon from desktop.
	reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /t REG_DWORD /d 1 /f

# Show file operations details
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v "EnthusiastMode" /t REG_DWORD /d 1 /f
		
# Disable creation of Thumbs.db thumbnail cache files
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableThumbnailCache" /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableThumbsDBOnNetworkFolders" /t REG_DWORD /d 1 /f
	
# Explorer set display the status of ongoing operations, such as file copy, move, delete, etc.
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f

# Set File Explorer to Open This PC instead of Quick Access
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
	
# Enables Explorer show File Extensions
	reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

# Disable Autorun for all drives
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f

# Show hidden files
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f

# Show shutdown options on lock screen
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d 1 /f

# Prevents Dev Home Installation
	reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f

# Windows 10 / 11 keep modern standby, but disable network in standby.
	POWERCFG -SETDCVALUEINDEX SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0
	POWERCFG -SETACVALUEINDEX SCHEME_CURRENT SUB_NONE CONNECTIVITYINSTANDBY 0

# Set Windows 10 search indexer service off and disabled.
	Stop-Service -Name WSearch
	Set-Service -Name WSearch -StartupType Disabled

# Prevents New Outlook for Windows Installation
	reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f

# Prevents Chat Auto Installation & Removes Chat Icon
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f

# Enable Long File Paths with Up to 32,767 Characters
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f

# Disables News and Interests
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f

# Disables Windows Consumer Features Like App Promotions etc.
	reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 0 /f

# Disable Cortana
	reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

# Disable Windows Ink Workspace
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 0 /f

# Disable Feedback Notifications
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

# Disable the Advertising ID for All Users
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

# Disable Windows Error Reporting
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

# Disable Delivery Optimization
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

# Disable Remote Assistance
	reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

# Search Windows Update for Drivers First
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f

# Hides the Meet Now Button on the Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

# Set Registry Keys to Disable Wifi-Sense
	reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v Value /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v Value /t REG_DWORD /d 0 /f
	
# Disable Tablet Mode
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v TabletMode /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v TabletMode /t REG_DWORD /d 0 /f
	
# Set Windows Mode to Dark and Apps mode to Light

	reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f
	reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 1 /f

# Disables the "Push To Install" feature in Windows
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d 1 /f

# DELETES SCHEDULED TASKS REGISTRY KEYS
# Deleting Application Compatibility Appraiser
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f

# Deleting Customer Experience Improvement Program
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f

# Deleting Program Data Updater
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /f
	
# Deleting QueueReporting
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /f

# Configure Maximum Password Age in Windows
	net.exe accounts /maxpwage:UNLIMITED

# Allow Execution of PowerShell Script Files
	Set-ExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy 'RemoteSigned' -Force

# Removes Microsoft Teams
	$TeamsPath = [System.IO.Path]::Combine($env:LOCALAPPDATA, 'Microsoft', 'Teams')
	$TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
	Stop-Process -Name "*teams*" -Force -ErrorAction Continue
	if ([System.IO.File]::Exists($TeamsUpdateExePath)) {
		# Uninstall app
		$proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru
		$proc.WaitForExit()
	}
	Get-AppxPackage "*Teams*" | Remove-AppxPackage -ErrorAction Continue
	Get-AppxPackage "*Teams*" -AllUsers | Remove-AppxPackage -AllUsers -ErrorAction Continue
	if ([System.IO.Directory]::Exists($TeamsPath)) {
		Remove-Item $TeamsPath -Force -Recurse -ErrorAction Continue
	}

# Uninstall Teams from Uninstall registry key UninstallString
	$us = (Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall, HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall | Get-ItemProperty | Where-Object { $_.DisplayName -like '*Teams*'}).UninstallString
	if ($us.Length -gt 0) {
		$us = ($us.Replace('/I', '/uninstall ') + ' /quiet').Replace('  ', ' ')
		$FilePath = ($us.Substring(0, $us.IndexOf('.exe') + 4).Trim())
		$ProcessArgs = ($us.Substring($us.IndexOf('.exe') + 5).Trim().replace('  ', ' '))
		$proc = Start-Process -FilePath $FilePath -Args $ProcessArgs -PassThru
		$proc.WaitForExit()
	}

# Disables Telemetry; Scheduled Tasks
	$scheduledTasks = @(
		"Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser",
		"Microsoft\Windows\Application Experience\ProgramDataUpdater",
		"Microsoft\Windows\Customer Experience Improvement Program\Consolidator",
		"Microsoft\Windows\Customer Experience Improvement Program\UsbCeip",
		"Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector",
		"Microsoft\Windows\Feedback\Siuf\DmClient",
		"Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload",
		"Microsoft\Windows\Windows Error Reporting\QueueReporting",
		"Microsoft\Windows\Application Experience\StartupAppTask",
		"Microsoft\Windows\Application Experience\PcaPatchDbTask",
		"Microsoft\Windows\Maps\MapsUpdateTask"
	)
	foreach ($task in $scheduledTasks) {
		schtasks /Change /TN $task /Disable
	}

# Disabling the Delivery of Personalized or Suggested Content Like App Suggestions, Tips, and Advertisements in Windows
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
	reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v IsMiEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v IsMiEnabled /t REG_DWORD /d 0 /f
	reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
	reg.exe delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f

# Removes Copilot
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" /v "UninstallCopilot" /t REG_SZ /d "" /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Runonce" /v "UninstallCopilot" /t REG_SZ /d "" /f
	reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f

# Align the taskbar to the left on Windows 11
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f

# Hides Search Icon on Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /t REG_DWORD /d 0 /f

# Start Menu Customizations - disables Recommendations in the Start Menu
	reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f

# Hides or Removes People from Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v PeopleBand /t REG_DWORD /d 0 /f

# Hides Task View Button on Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f

# Hides and Removes News and Interests from PC and Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f

# Disables Input Personalization Settings
	reg.exe add "HKLM\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f

# Disables Automatic Feedback Sampling
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v AutoSample /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v ServiceEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v AutoSample /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v ServiceEnabled /t REG_DWORD /d 0 /f

# Disables App Diagnostics
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f

# Disables Delivery Optimization
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f

# Disables Maps Auto Download
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Maps" /v AutoDownload /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Maps" /v AutoDownload /t REG_DWORD /d 0 /f

# Disables Telemetry and Ads
	reg.exe add "HKLM\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKLM\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

# Hides the Meet Now Button on the Taskbar
	reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

# Disables Bing Search in Start Menu
	reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
	reg.exe add "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
	
# Disable Bing Web Search in Start Menu
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f
	reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v DisableWebSearch /t REG_DWORD /d 1 /f

# Enables NumLock on Startup
	reg.exe add "HKLM\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f
	reg.exe add "HKCU\Control Panel\Keyboard" /v InitialKeyboardIndicators /t REG_SZ /d 2 /f

# Disables Sticky Keys
	reg.exe add "HKLM\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f
	reg.exe add "HKLM\Control Panel\Accessibility\StickyKeys" /v HotkeyFlags /t REG_SZ /d "58" /f
	reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v Flags /t REG_SZ /d "506" /f
	reg.exe add "HKCU\Control Panel\Accessibility\StickyKeys" /v HotkeyFlags /t REG_SZ /d "58" /f

# Set: do not Update Last Access Time Stamp - This Can Improve File System Performance
	fsutil.exe behavior set disableLastAccess 1

#Removes Bloatware Apps for all users
	Get-AppXPackage -AllUsers | Where-Object -Property 'Name' -In -Value @(
	  'Microsoft.Microsoft3DViewer';
	  'MicrosoftWindows.Client.WebExperience';
	  'Microsoft.BingSearch';
	  'Clipchamp.Clipchamp';
	  'Microsoft.549981C3F5F10';
	  'Microsoft.Windows.DevHome';
	  'MicrosoftCorporationII.MicrosoftFamily';
	  'Microsoft.WindowsFeedbackHub';
	  'Microsoft.GetHelp';
	  'microsoft.windowscommunicationsapps';
	  'Microsoft.WindowsMaps';
	  'Microsoft.ZuneVideo';
	  'Microsoft.BingNews';
	  'Microsoft.MicrosoftOfficeHub';
	  'Microsoft.Office.OneNote';
	  'Microsoft.OutlookForWindows';
	  'Microsoft.Paint';
	  'Microsoft.MSPaint';
	  'Microsoft.People';
	  'Microsoft.PowerAutomateDesktop';
	  'MicrosoftCorporationII.QuickAssist';
	  'Microsoft.SkypeApp';
	  'Microsoft.ScreenSketch';
	  'Microsoft.MicrosoftSolitaireCollection';
	  'Microsoft.MicrosoftStickyNotes';
	  'MSTeams';
	  'Microsoft.Getstarted';
	  'Microsoft.Windows.PeopleExperienceHost';
	  'Microsoft.XboxGameCallableUI';
	  'Microsoft.WidgetsPlatformRuntime';
	  'Microsoft.Todos';
	  'Microsoft.WindowsSoundRecorder';
	  'Microsoft.BingWeather';
	  'Microsoft.ZuneMusic';
	  'Microsoft.WindowsTerminal';
	  'Microsoft.Xbox.TCUI';
	  'Microsoft.XboxApp';
	  'Microsoft.XboxGameOverlay';
	  'Microsoft.XboxGamingOverlay';
	  'Microsoft.XboxIdentityProvider';
	  'Microsoft.XboxSpeechToTextOverlay';
	  'Microsoft.GamingApp';
	  'Microsoft.549981C3F5F10';
	  'Microsoft.MixedReality.Portal';
	  'Microsoft.Windows.Ai.Copilot.Provider';
	  'Microsoft.WindowsMeetNow';
	) | Remove-AppXPackage

#Removes Preinstalled Bloatware Apps
	Get-AppxProvisionedPackage -Online | Where-Object -Property 'DisplayName' -In -Value @(
	  'Microsoft.Microsoft3DViewer';
	  'MicrosoftWindows.Client.WebExperience';
	  'Microsoft.BingSearch';
	  'Clipchamp.Clipchamp';
	  'Microsoft.549981C3F5F10';
	  'Microsoft.Windows.DevHome';
	  'MicrosoftCorporationII.MicrosoftFamily';
	  'Microsoft.WindowsFeedbackHub';
	  'Microsoft.GetHelp';
	  'microsoft.windowscommunicationsapps';
	  'Microsoft.WindowsMaps';
	  'Microsoft.ZuneVideo';
	  'Microsoft.BingNews';
	  'Microsoft.MicrosoftOfficeHub';
	  'Microsoft.Office.OneNote';
	  'Microsoft.OutlookForWindows';
	  'Microsoft.Paint';
	  'Microsoft.MSPaint';
	  'Microsoft.People';
	  'Microsoft.PowerAutomateDesktop';
	  'MicrosoftCorporationII.QuickAssist';
	  'Microsoft.SkypeApp';
	  'Microsoft.ScreenSketch';
	  'Microsoft.MicrosoftSolitaireCollection';
	  'Microsoft.MicrosoftStickyNotes';
	  'MSTeams';
	  'Microsoft.Getstarted';
	  'Microsoft.Windows.PeopleExperienceHost';
	  'Microsoft.XboxGameCallableUI';
	  'Microsoft.WidgetsPlatformRuntime';
	  'Microsoft.Todos';
	  'Microsoft.WindowsSoundRecorder';
	  'Microsoft.BingWeather';
	  'Microsoft.ZuneMusic';
	  'Microsoft.WindowsTerminal';
	  'Microsoft.Xbox.TCUI';
	  'Microsoft.XboxApp';
	  'Microsoft.XboxGameOverlay';
	  'Microsoft.XboxGamingOverlay';
	  'Microsoft.XboxIdentityProvider';
	  'Microsoft.XboxSpeechToTextOverlay';
	  'Microsoft.GamingApp';
	  'Microsoft.549981C3F5F10';
	  'Microsoft.MixedReality.Portal';
	  'Microsoft.Windows.Ai.Copilot.Provider';
	  'Microsoft.WindowsMeetNow';
	) | Remove-AppxProvisionedPackage -AllUsers -Online
	
	
	
	
		
#Removes Legacy Apps (Windows capabilities)
	Get-WindowsCapability -Online | Where-Object -FilterScript {
	  ($_.Name -split '~')[0] -in @(
		'Browser.InternetExplorer';
		'MathRecognizer';
		'Microsoft.Windows.MSPaint';
		'App.Support.QuickAssist';
		'App.StepsRecorder';
		'Media.WindowsMediaPlayer';
	  );
	} | Remove-WindowsCapability -Online 

# CMD Disk Cleanup old Drivers / Packages:
	rundll32.exe pnpclean.dll,RunDLL_PnpClean /DRIVERS /MAXCLEAN
	
