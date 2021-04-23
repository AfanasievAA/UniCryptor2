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

# Setting additional parameters
# Hyperthreading
$UniCryptor.SevenZipCompressor.CustomParameters.Add("mt", "on")
# Encrypt File Names
$UniCryptor.SevenZipCompressor.EncryptHeaders = $true
$UniCryptor.SevenZipCompressor.IncludeEmptyDirectories  = $true
$UniCryptor.SevenZipCompressor.DirectoryStructure = $true

#Including to archive only files with this attribute
$UniCryptor.Options.OnlyFilesWithArchiveBit = $true
#Clear this bit after archiving
$UniCryptor.Options.ClearArchiveBit = $true

# Compress only files with archive bit set. For backup purposes
#$UniCryptor.Compress7ZIPPKI("$($ScriptRunFolderPath)\bin", "$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder1.7z", $true)

# Not extracting archive, listing contents only
$UniCryptor.Options.ListContentsOnly = $true
$archiveContent = $UniCryptor.Expand7ZIPPKI("$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder.7z", $null, $true)
$archiveContent | Format-Table

# Not extracting archive, just extract archive password for usage in external programme
$UniCryptor.Options.ListContentsOnly = $fase
$UniCryptor.Options.ExtractPasswordOnly = $true
$password = $UniCryptor.Expand7ZIPPKI("$($ScriptRunFolderPath)\tmp\7zCompressed\binFolder.7z", $null, $true)
Write-Host "Archive password is: $($password)"


