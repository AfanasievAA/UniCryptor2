# Getting folder name of the script
$ScriptRunFolderPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
# Including Main Unicryptor proccedure file
.$ScriptRunFolderPath\UniCryptor2-Class.ps1

$VerbosePreference =" Continue" #Uncomment for Verbose output to On
#$VerbosePreference =" SilentlyContinue" #Uncomment for Verbose output to Off

# Declaring new Object 
$UniCryptor = New-Object UniCryptor2
# For this example to work you should have at least 1 certificate with a private key
$EncryptionCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.privatekey.KeyExchangeAlgorithm }
$CertCount = ($EncryptionCerts |Measure-Object).Count
if ($CertCount -le 0) {
    Write-Host "No certificates found. Cannot proceed"
    return
}
$UniCryptor.SetEncryptionCertificates($EncryptionCerts)

# Compressing a folder to 7Z archive with PKI encrypted random password. Advanced usage
# Example 4. Compressing a folder to 7Z archive with PKI encrypted random password

# Compressing  bin folder to 7Z AESPKI archive
$UniCryptor.Compress7ZIPPKI( "$($ScriptRunFolderPath)\bin", "$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder.7z" , $true)
# Extracting archive compressed earlier
$UniCryptor.Expand7ZIPPKI("$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder.7z", "$($ScriptRunFolderPath)\tmp\7ZExtracted\", $true)
# Get Archive PKI service info
$info = $UniCryptor.GetPKIFileServiceInfo("$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder.7z")
Write-Host "Information about file:"
($info | Format-List)

$UniCryptor.Options.ExtractPasswordOnly = $true
$UniCryptor.Expand7ZIPPKI("$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder.7z", $null, $null)
