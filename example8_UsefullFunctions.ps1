# Getting folder name of the script
$ScriptRunFolderPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
# Including Main Unicryptor proccedure file
.$ScriptRunFolderPath\UniCryptor2-Class.ps1

$VerbosePreference =" Continue" #Uncomment for Verbose output to On
#$VerbosePreference =" SilentlyContinue" #Uncomment for Verbose output to Off

# Declaring new Object 
$UniCryptor = New-Object UniCryptor2

# Example. Useful functions of UniCryptor object
$bytes = [byte]255,254,253,252,251,250
$UniCryptor.Bytes2Hex($bytes)
$HEX = "AAADABACAEAF010203"
$bytes2 = $UniCryptor.Hex2Bytes($HEX)
$bytes2 -join ","

# Computes MD5Sum of bytes and return it as byte array
$md5sum = $UniCryptor.GetMD5CheckSumBytes($bytes)
$UniCryptor.Bytes2Hex($md5sum)

# This will generate random password length from 10 to 15. 
# Soome letters and numbers are excluded. Likewise 0 and O. For easy human reading.
$UniCryptor.NewRandomPassword(10,15)
# Long password example
$UniCryptor.NewRandomPassword(100,150)