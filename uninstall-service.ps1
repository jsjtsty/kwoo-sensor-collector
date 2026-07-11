param([string]$ServiceName = "KwooSensorCollector")
$ErrorActionPreference = "Stop"
sc.exe stop $ServiceName | Out-Null
sc.exe delete $ServiceName | Out-Null
