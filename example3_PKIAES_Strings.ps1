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
Write-Host "Using $($certCount) certificates for encryption"
# Setting encryption certificates to that list
$UniCryptor.SetEncryptionCertificates($EncryptionCerts)

$SomeText = "This is an exmple of long string. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog/ The quick brown fox jumps over the lazy dog/"

$encryptedText = $UniCryptor.ProtectStringPKI($SomeText)
Write-Host "Length of encrypted PKI data is $($encryptedText.Length)"
# Unlike above this procedure generates random AES key and encrypts it using supplied certificates, while the rest of data are encrypted using AES encryption
# Which gives alot smaller output file size
$encryptedTextPKIAES = $UniCryptor.ProtectStringPKIAES($SomeText)
Write-Host "Length of encrypted PKI AES data is $($encryptedTextPKIAES.Length)"

# Now will try to decrypt encrypted text
$decryptedText = $UniCryptor.UnProtectStringPKIAES($encryptedTextPKIAES)
Write-Host "Decrypted text length: $($decryptedText.Length)"
