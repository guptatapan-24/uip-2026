param(
  [string]$OutDir = '.'
)
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$priv = Join-Path $OutDir 'private.pem'
$pub = Join-Path $OutDir 'public.pem'
Write-Host "Generating RSA 2048 keypair to $OutDir"
& openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out $priv
& openssl rsa -in $priv -pubout -out $pub
Write-Host "Private: $priv"
Write-Host "Public:  $pub"
