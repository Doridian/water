$OpenVPNMSI = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.5.7-I602-amd64.msi"
$WSTUNZIP = "https://www.wintun.net/builds/wintun-0.14.1.zip"

$global:ErrorActionPreference = "Stop"

$WorkingDir = Convert-Path .

function DownloadFile([Parameter(Mandatory=$true)]$Link, [Parameter(Mandatory=$true)]$OutFile)
{
    Write-Host "Downloading $OutFile... "
    Invoke-WebRequest $Link -UseBasicParsing -OutFile "$WorkingDir\$OutFile"
    @{$true = Write-Host "[OK]"}[$?]
}

DownloadFile "$OpenVPNMSI" "openvpn.msi"
DownloadFile "$WSTUNZIP" "wstun.zip"

Write-Host "Installing OpenVPN..."
Start-Process msiexec -ArgumentList "/i `"$WorkingDir\openvpn.msi`" ADDLOCAL=Drivers,Drivers.TAPWindows6,OpenVPN /quiet /norestart" -Wait
@{$true = Write-Host "[OK]"}[$?]

Expand-Archive -LiteralPath "$WorkingDir\wstun.zip" -DestinationPath "$WorkingDir\tmp"

Copy-Item -Path "$WorkingDir\tmp\wstun\bin\amd64\wintun.dll" -Destination "$WorkingDir\wintun.dll"
