###############################################################################
# System Configuration
###############################################################################
# Set up Chocolatey
Write-Host "Initializing chocolatey"
choco feature enable -n allowGlobalConfirmation
choco feature enable -n allowEmptyChecksums

$Boxstarter.RebootOk=$true # Allow reboots?
$Boxstarter.NoPassword=$false # Is this a machine with no login password?
$Boxstarter.AutoLogin=$true # Save my password securely and auto-login after a reboot
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
    REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogon /t REG_SZ /d 1 /f
}
# Basic setup
Write-Host "Setting execution policy"
Update-ExecutionPolicy Unrestricted
Set-WindowsExplorerOptions -EnableShowProtectedOSFiles -EnableShowFileExtensions -EnableShowHiddenFilesFoldersDrives
Disable-BingSearch
Disable-GameBarTips
Disable-ComputerRestore -Drive ${Env:SystemDrive}
# Disable UAC
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d "0" /f 
if (Test-Path "C:\BGinfo\build.cfg" -PathType Leaf)
{
write-host "Disabling Windows garbage from free VM!"
cmd.exe /c sc config sshd start= disabled
cmd.exe /c sc stop sshd
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "bginfo" /f 
}
# Disable Updates
write-host "Disabling Windows Update"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d "1" /f 

# Disable Firewall
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Kill Windows Defender
write-host "Disabling Windows Defender"
Stop-Service WinDefend
Set-Service WinDefend -StartupType Disabled
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Value 1
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows Defender" -Name "DisableRoutinelyTakingAction" -Value 1
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Disable Action Center
write-host "Disabling Action Center notifications"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d "0x1" /f 

# Set a nice S1 wallpaper : 
write-host "Setting a nice wallpaper"
$web_dl = new-object System.Net.WebClient
$wallpaper_url = "https://raw.githubusercontent.com/cxiao/SentinelLabs_RevCore_Tools/cxiao-tools/kare-wall.png"
$wallpaper_file = "C:\Users\Public\Pictures\101089633-48da3e80-356a-11eb-9d66-0cdf9da30220.png"
$web_dl.DownloadFile($wallpaper_url, $wallpaper_file)
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Users\Public\Pictures\101089633-48da3e80-356a-11eb-9d66-0cdf9da30220.png" /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v WallpaperStyle /t REG_DWORD /d "0" /f 
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v StretchWallpaper /t REG_DWORD /d "2" /f 
reg add "HKEY_CURRENT_USER\Control Panel\Colors" /v Background /t REG_SZ /d "0 0 0" /f

###############################################################################
# Utilities, Debugger, Disassembler, Scripting
###############################################################################
choco feature enable -n allowGlobalConfirmation
choco install checksum -y
choco install 7zip.install -y
choco install procexp -y
choco install autoruns -y
choco install tcpview -y
choco install sysmon -y
choco install hxd -y
choco install pebear -y
choco install pestudio --ignore-checksums
choco install pesieve -y
choco install cmder -y
choco install nxlog -y
choco install x64dbg.portable -y
choco install ollydbg -y
choco install ida-free -y
choco install cutter -y
choco install openjdk11 -y
setx -m JAVA_HOME "C:\Program Files\Java\jdk-11.0.2\"
cinst ghidra
choco install python -y
refreshenv
choco install pip -y
python -m pip install --upgrade pip
pip install --upgrade setuptools
pip install pefile
pip install pwntools
pip install yara
pip install frida-tools
pip install qiling
choco install vscode -y
choco install vscode-python -y
choco install microsoft-windows-terminal -y

Write-Host -NoNewline " - SentinelLabs RevCore Tools HAS COMPLETED! - "
