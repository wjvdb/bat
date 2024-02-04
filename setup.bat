@echo off

@echo off

@echo off

REM Check if running as administrator
NET SESSION >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
    echo Running as administrator
) ELSE (
    echo Please run this script as administrator
    pause
    exit /b
)


setlocal enabledelayedexpansion

set /a count=0
set /a total=18

echo Setting registry values...

REM Add registry values and display progress
reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve >nul
echo Setting registry value: HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Search\BingSearchEnabled 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarAl 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarGlomLevel" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarGlomLevel 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ShowTaskViewButton 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Search\SearchboxTaskbarMode 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDrive" /f >nul
echo Deleting registry value: HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableXamlStartMenu" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\EnableXamlStartMenu 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableXamlStartMenuExperience" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\EnableXamlStartMenuExperience 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_PowerButtonAction" /t REG_DWORD /d 2 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Start_PowerButtonAction 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogon" /t REG_DWORD /d 1 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogon 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogonFallback" /t REG_DWORD /d 1 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogonFallback 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogonWithBiometrics" /t REG_DWORD /d 1 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogonWithBiometrics 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogonWithFingerprint" /t REG_DWORD /d 1 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogonWithFingerprint 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowDomainPINLogonWithPIN" /t REG_DWORD /d 1 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Policies\Microsoft\Windows\System\AllowDomainPINLogonWithPIN 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Control Panel\Colors" /v "Background" /t REG_SZ /d "0 0 0" /f >nul
echo Setting registry value: HKCU\Control Panel\Colors\Background 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\AppsUseLightTheme 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme 
set /a count+=1
echo Progress: !count! out of !total! [!count!%%]

reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" /v "TabPreloader" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main\TabPreloader
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge" /v "BackgroundAccessStatus" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\Microsoft.MicrosoftEdge_8wekyb3d8bbwe!MicrosoftEdge\BackgroundAccessStatus
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Search\BingSearchEnabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\Search\BingSearchEnabled
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowCortana
reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d 1 /f >nul
echo Setting registry value: HKLM\Software\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SoftLandingEnabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SystemPaneSuggestionsEnabled
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo\Enabled
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting\value
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f >nul
echo Setting registry value: HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost\EnableWebContentEvaluation


echo.
echo All registry values have been set successfully.
echo.

taskkill /f /im explorer.exe
start explorer.exe
@echo off


set /p restart=Do you want to restart the system? (y/n): 
if /i "%restart%"=="y" (
    echo System configuration complete. The system will reboot in 10 seconds.
timeout /t 10 /nobreak >nul
echo Rebooting...
    shutdown /r /t 0
) else (
    echo System configuration complete. No reboot required.
)
