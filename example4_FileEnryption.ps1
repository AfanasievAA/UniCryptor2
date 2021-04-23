# Getting folder name of the script
$ScriptRunFolderPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
# Including Main Unicryptor proccedure file
.$ScriptRunFolderPath\UniCryptor2-Class.ps1

$VerbosePreference =" Continue" #Uncomment for Verbose output to On
#$VerbosePreference =" SilentlyContinue" #Uncomment for Verbose output to Off

# Declaring new Object 
$UniCryptor = New-Object UniCryptor2
# For this example to work you should have at least 1 certificate with a private key
$EncryptionCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.hasPrivateKey  -and $_.PrivateKey -ne $null }
$CertCount = ($EncryptionCerts |Measure-Object).Count
if ($CertCount -le 0) {
    Write-Host "No certificates found. Cannot proceed"
    return
}
$UniCryptor.SetEncryptionCertificates($EncryptionCerts)

# Protecting File with AESPKI encryption
$UniCryptor.ProtectFilePKI("$($ScriptRunFolderPath)\UniCryptor2-Class.ps1", "$($ScriptRunFolderPath)\tmp\EncryptedFiles", $true)

# Get protected file info
$info = $UniCryptor.GetPKIFileServiceInfo("$($ScriptRunFolderPath)\tmp\EncryptedFiles\UniCryptor2-Class.ps1.AESPKI")
$info | Format-List

# Unprotecting file
$UniCryptor.UnprotectFilePKI("$($ScriptRunFolderPath)\tmp\EncryptedFiles\UniCryptor2-Class.ps1.AESPKI", "$($ScriptRunFolderPath)\tmp\DecryptedFiles", $true)
#>