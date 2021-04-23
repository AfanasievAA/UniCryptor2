# Getting folder name of the script
$ScriptRunFolderPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
# Including Main Unicryptor proccedure file
.$ScriptRunFolderPath\UniCryptor2-Class.ps1

$VerbosePreference =" Continue" #Uncomment for Verbose output to On
#$VerbosePreference =" SilentlyContinue" #Uncomment for Verbose output to Off

# Declaring new Object 
$UniCryptor = New-Object UniCryptor2
# AES Encrypting strings using AES key generated from password
$testString = "This is a basic test string used for encryption/decryption test"
$testPassword = "SimplePassword"
$null = $UniCryptor.NewAESKeyFromPassword($testPassword)
$encryptedText = $UniCryptor.ProtectStringAES($testString)
Write-Host "Encrypted text length is $($encryptedText.length)"
Write-Host $encryptedText

#AES Decrypting a string 
$decryptedString = $UniCryptor.UnProtectStringAES($encryptedText)
Write-Host $decryptedString

#AES Decrypting a string using known password
$encryptedText = "0kkLrYvo5Ree3iBm1lGMpQ8NZ3YZjkJU/LLCytiZ7Ii9ZiAHhI3wS7BIDRwtc1gvG2gs1VwB7li/VPRWnZrbpfLDiCRJHKpZUXSTerrIxQum"
$null = $UniCryptor.NewAESKeyFromPassword("P@ssw0rd")
Write-Host ($UniCryptor.UnProtectStringAES($encryptedText))
