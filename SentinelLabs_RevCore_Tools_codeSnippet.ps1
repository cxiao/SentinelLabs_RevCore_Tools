Set-ExecutionPolicy Unrestricted;
iex ((New-Object System.Net.WebClient).DownloadString('http://boxstarter.org/bootstrapper.ps1'));
get-boxstarter -Force;
Install-BoxstarterPackage -PackageName 'https://raw.githubusercontent.com/cxiao/SentinelLabs_RevCore_Tools/cxiao-tools/SentinelLabs_RevCore_Tools.ps1';