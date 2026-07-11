param([string]$Binary = "$PSScriptRoot\kwoo-sensor-collector.exe", [string]$Config = "$PSScriptRoot\config.toml", [string]$ServiceName = "KwooSensorCollector")
$ErrorActionPreference = "Stop"
if (-not (Test-Path $Binary)) { throw "Binary not found: $Binary" }
if (-not (Test-Path $Config)) { throw "Config not found: $Config" }
sc.exe create $ServiceName binPath= "`"$Binary`" `"$Config`"" start= auto | Out-Null
sc.exe description $ServiceName "Kwoo sensor TCP collector and uploader" | Out-Null
sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
sc.exe start $ServiceName
