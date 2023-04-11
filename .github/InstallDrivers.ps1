$OpenVPNMSI = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.5.7-I602-amd64.msi"
$WINTUNZIP = "https://www.wintun.net/builds/wintun-0.14.1.zip"

$global:ErrorActionPreference = "Stop"

$WorkingDir = Convert-Path .

function DownloadFile([Parameter(Mandatory=$true)]$Link, [Parameter(Mandatory=$true)]$OutFile)
{
    Write-Host "Downloading $OutFile... "
    Invoke-WebRequest $Link -UseBasicParsing -OutFile "$WorkingDir\$OutFile"
    @{$true = Write-Host "[OK]"}[$?]
}

DownloadFile "$OpenVPNMSI" "openvpn.msi"
DownloadFile "$WINTUNZIP" "wintun.zip"

Write-Host "Installing OpenVPN..."
Start-Process msiexec -ArgumentList "/i `"$WorkingDir\openvpn.msi`" ADDLOCAL=Drivers,Drivers.TAPWindows6,OpenVPN /quiet /norestart" -Wait
@{$true = Write-Host "[OK]"}[$?]

Write-Host "Extracting wintun archive..."
Expand-Archive -LiteralPath "$WorkingDir\wintun.zip" -DestinationPath "$WorkingDir\tmp" -Force
@{$true = Write-Host "[OK]"}[$?]

Write-Host "Copying wintun.dll..."
Copy-Item -Path "$WorkingDir\tmp\WINTUN\bin\amd64\wintun.dll" -Destination "$env:SystemRoot\System32\wintun.dll" -Force
@{$true = Write-Host "[OK]"}[$?]
