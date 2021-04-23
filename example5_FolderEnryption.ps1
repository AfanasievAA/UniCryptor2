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

# Example 3. Encrypting and decrypting folder with AES PKI

# Encrypting Docs subfolder
$UniCryptor.ProtectFolderPKI("$($ScriptRunFolderPath)\Docs", "$($ScriptRunFolderPath)\tmp\EncryptedFiles", $true)
# Decrypting All Files in EncryptedFiles folder
$UniCryptor.UnProtectFolderPKI("$($ScriptRunFolderPath)\tmp\EncryptedFiles", "$($ScriptRunFolderPath)\tmp\DecryptedFiles", $true)
