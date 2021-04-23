#requires -version 5.0
<#
.SYNOPSIS
  Powershell class object used for different types of encryption and decryption purposes.
.DESCRIPTION
  Can be used to encrypt and decrypt following instances:
  1) Strings using RSA, AES, or RSAAES encryption algorithms
  2) Files using RSAAES encryption algorotm. 
  3) Folders with files using RSAAES encryption algorotm. 
  4) Create 7Z archives using RSA encryption algorithm (Generates a long password and encrypts it using RSA PKI encryption)
  5) Create 7Z archives of files with Archive attribute set (for backup purposes) and (optionalluy) reset that attribute after successfull archiving
.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>
.NOTES
  Version:        0.52 beta
  Author:         Andrew Afanasiev
  Date:           26.12.2020
  Purpose/Change: Initial script development
  Contacts:       AfanasievAA@yandex.ru

  SevenZipSharp and 7z64.dll libraries are needed for a script to work properly
.FUNCTION Initialize
    Initialize an object again
.FUNCTION InitializeEncryptionObject ($Aes_Key, $AES_IV)
    Initializes AES encryption object with provided key and IV.
.FUNCTION GetAESKey
    Returns current AES key as BASE64 encoded string
.FUNCTION GetAESIV
    Returns current AES IV vector as BASE64 string
.FUNCTION NewSelfCertificate ($subject)
    Generates new self signed certificate for testing purposes. Subject is a name of certificate
.FUNCTION Hex2Bytes ($HexString)
    Converts a HEX string to a byte array
.FUNCTION Bytes2HEX ($bytesArray)
    Converts an array of bytes to a HEX string
.FUNCTION GetMD5CheckSumBytes ($ByteArray)
    Calculates a MD5 check sum from provided array of bytes
.FUNCTION ConvertString2BytesWChecksum ($Input)
    Converts a give string to a byte array with a checksum consisting of 4 bytes from MD5 SUM
.FUNCTION ConvertBytesWChecksum2String ($arrayOfBytes)
    Converts byte array with a checksum to a string, checking if a checksum is correct. If not - returns $null
.FUNCTION NewAESKey
    Generates new AES Key and IV pair
.FUNCTION ProtectStringAES ($String)
    Encryptes a $String with AES encryption using current KEY and IV pair or PASSWORD if specified and returns BASE64 string
.FUNCTION UnProtectStringAES ($Base64EncodedString)
    Decrypts an AES encrypted $BASE64EncodedString to a string if checksum is OK
.EXAMPLE
    $UniCryptor = New-Object UniCryptor2
    $EncryptionCerts = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.hasPrivateKey  -and $_.PrivateKey -ne $null }
    # Setting encryption certificates to that list
    $UniCryptor.SetEncryptionCertificates($EncryptionCerts)
    $UniCryptor.PasswordAES = "test1"
    $protectedString = $UniCryptor.ProtectStringAES("This bytes to protect")
    Write-Host $protectedString
    $UniCryptor.UnProtectStringAES($protectedString)
    $prString = "QQWO3tL9dT56KtzgIEBw0QfFgLj4aJxkLk62o1RIJTnD1TCSSIruvIdcHkzf+1g8PA=="
    $UniCryptor.PasswordAES = "test"
    $UniCryptor.UnProtectStringAES($prString)
#>

$ScriptRunFolderPath=Split-Path ((Get-Variable MyInvocation -Scope 0).Value).MyCommand.Path
Add-Type -Path "$ScriptRunFolderPath\bin\7Zip4Powershell\SevenZipSharp.dll"
[SevenZip.SevenZipCompressor]::SetLibraryPath("$($ScriptRunFolderPath)\bin\7Zip4Powershell\7z64.dll" )
# Defining a main class
Class UniCryptor2 {
    [object]$CryptoAES = $null
    $EncryptionCertificates = @{}
    [int16]$UTCTimeOffset = 0
    [int]$minCertsKeySize = 0
    [int]$maxCertsKeySize = 0
    [object]$SevenZipCompressor = $null
    [object]$md5Obj = $null
    $Options = [PSCustomObject]@{
        OnlyFilesWithArchiveBit = $false
        ClearArchiveBit = $false
        ExtractPasswordOnly = $false
        ListContentsOnly = $false
    }
    [string]$PasswordAES = $null
    $TimeLastInitialized = $this.Initialize()

    [datetime] Initialize() {
        $DateToday = Get-Date
        $this.UTCTimeOffset = (New-Timespan (($DateToday).ToUniversalTime()) $DateToday).Hours
        # PKI section
        $this.md5Obj = (New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider)
        $this.EncryptionCertificates = @{}
        $this.minCertsKeySize = 0
        $this.maxCertsKeySize = 0
        # 7Z compressor object creation and defaults
        $this.SevenZipCompressor = New-Object SevenZip.SevenZipCompressor
        $this.SevenZipCompressor.CompressionMethod = "Lzma2"
        $this.SevenZipCompressor.CompressionLevel = "Fast"
        $this.SevenZipCompressor.DirectoryStructure = $true
        $this.SevenZipCompressor.PreserveDirectoryRoot = $false
        $this.SevenZipCompressor.ArchiveFormat = "SevenZip"
        $this.SevenZipCompressor.EncryptHeaders = $false
        $this.SevenZipCompressor.ZipEncryptionMethod = "AES256" # [SevenZip.ZipEncryptionMethod].DeclaredFields.Name
        # AES Setction and defaults
        $this.CryptoAES = New-Object "System.Security.Cryptography.AesManaged"
        $this.CryptoAES.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $this.CryptoAES.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        $this.CryptoAES.BlockSize = 128
        $this.CryptoAES.KeySize = 256
        $this.InitializeEncryptionObject($null, $null)
        $this.NewAESKey()
        return $DateToday
    }
    
    [object] InitializeEncryptionObject($key, $IV) {
        if ($IV) {
            if ($IV.getType().Name -eq "String") {
                $this.CryptoAES.IV = [System.Convert]::FromBase64String($IV)
            } else {
                $this.CryptoAES.IV = $IV
            }
        }
        if ($key) {
            if ($key.getType().Name -eq "String") {
                $this.CryptoAES.Key = [System.Convert]::FromBase64String($key)
            } else {
                $this.CryptoAES.Key = $key
            }
        }
        return ($this.CryptoAES)
    }
    # Gets current AES Key
    [string] GetAESKey() {
        return [System.Convert]::ToBase64String($this.CryptoAES.key)
    }
    # Gets current AES IV
    [string] GetAESIV() {
        return [System.Convert]::ToBase64String($this.CryptoAES.IV)
    }
    [object] NewSelfCertificate([string]$subject) {
        $cert = New-SelfSignedCertificate -DnsName $subject -CertStoreLocation "Cert:\CurrentUser\My" `
        -KeyUsage KeyEncipherment,DataEncipherment -Type Custom,DocumentEncryptionCert `
        -NotAfter ((Get-Date).AddYears(2)) -Keyspec KeyExchange `
        -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"
        return $cert
    }

    # Converts array of bytes to HEX string
    [string] Bytes2Hex ([byte[]]$Bytes)  {
        return ([System.BitConverter]::ToString($Bytes))
    }
    # Converts HEX string to array of bytes. Hex string might be AA-AB-01-02 or AAAB0102
    [byte[]] Hex2Bytes ([string]$HexString) {
        $rg = "[\dA-F]{2}"
        [array]$values = ((Select-String $rg -InputObject $HexString -AllMatches).Matches).Value
        $scriptBlock = "[byte]0x"+($Values -join ",0x")
        return (&([Scriptblock]::Create($scriptBlock)))
    }
    # Converts dattime to a byte array (ticks)
    [byte[]] ConvertDateTime2Bytes($dt) {
        return ([System.BitConverter]::GetBytes([int64]$dt.Ticks))
    }

    # Converts bytes array to datetime
    [datetime] ConvertBytes2DateTime($Bytes) {
        $ticks = [Int64]([System.BitConverter]::ToInt64($Bytes,  0))
        if ($ticks -le  ([datetime]::MaxValue.ticks) -and $ticks -ge ([datetime]::MinValue.Ticks)) {
            return ([datetime]$ticks)
        } else {
            return $null
        }
    }

    [int32] ReadFSInt32 ($FileStream) {
        [Byte[]]$Bytes = New-Object Byte[] 4
        $null = $FileStream.Read($Bytes,  0, 4) 
        return ([System.BitConverter]::ToInt32($Bytes,  0))
    }
    [uint32] ReadFSUInt32 ($FileStream) {
        [Byte[]]$Bytes = New-Object Byte[] 4
        $null = $FileStream.Read($Bytes,  0, 4) 
        return ([System.BitConverter]::ToUInt32($Bytes,  0))
    }
    [int64] ReadFSInt64 ($FileStream) {
        [Byte[]]$Bytes = New-Object Byte[] 8
        $null = $FileStream.Read($Bytes,  0, 8) 
        return ([System.BitConverter]::ToInt64($Bytes,  0))
    }
    [UInt64] ReadFSUInt64 ($FileStream) {
        [Byte[]]$Bytes = New-Object Byte[] 8
        $null = $FileStream.Read($Bytes,  0, 8) 
        return ([System.BitConverter]::ToUInt64($Bytes,  0))
    }
    [string] ReadFSBase64String ($FileStream, $BytesLength) {
        [Byte[]]$Bytes = New-Object Byte[] $BytesLength
        $null = $FileStream.Read($Bytes,  0, $BytesLength) 
        return ([System.Convert]::ToBase64String($Bytes))
    }
    [datetime] ReadFSDateTime ($FileStream) {
        [Byte[]]$Bytes = New-Object Byte[] 8
        $null = $FileStream.Read($Bytes,  0, 8) 
        return ($this.ConvertBytes2DateTime($Bytes))
    }
    [byte[]] ReadFSBytes ($FileStream, $BytesLength) {
        [Byte[]]$Bytes = New-Object Byte[] $BytesLength
        $null = $FileStream.Read($Bytes,  0, $BytesLength) 
        return $Bytes
    }
    # Calculates md5 SUM of array of bytes or a tring
    [byte[]] GetMD5CheckSumBytes ($byteArr) {
        if ($byteArr.getType().Name -eq "String") {
            $byteArr = [system.Text.Encoding]::UTF8.GetBytes($byteArr)
        } else{
            $byteArr = [byte[]]$byteArr
        }
        return (($this.md5Obj).ComputeHash($byteArr))
    }
    # COnverts any string to byte array where 4 first bytes are 4 bytes of md5sum of the string
    [byte[]] ConvertString2BytesWChecksum ($InputText) {
        if ($InputText.getType().Name -ne "String") {
            return $null
        }
        $byteArr = [system.Text.Encoding]::UTF8.GetBytes($InputText)
        return (this.ConvertBytes2BytesWChecksum $byteArr)
    }
    # Convert bytes to array of bytes with checksum calculated as 4 first bytes of md5 sum
    [byte[]] ConvertBytes2BytesWChecksum ($byteArr) {
        $md5Bytes = $this.GetMD5CheckSumBytes($byteArr)
        return ($md5Bytes[0..3]+$byteArr)
    }
    # Converts a byte array to a string if first 4 bytes match 4 byte of md5 sum.
    [byte[]] ConvertBytesWChecksum2String ($byteArr) {
        $bytes = $this.ConvertBytesWChecksum2Bytes($byteArr)
        if ($null -ne $bytes) {
            return ([System.Text.Encoding]::UTF8.GetString($bytes))
        } else {
            return $null
        }
    }
    # Converts array of bytes with 4 byte of md5 sum to array of bytes without checksum if checksum matches.
    [byte[]] ConvertBytesWChecksum2Bytes($ByteArr) {
        $md5Src =  $ByteArr[0..3]
        $md5Calculated = $this.GetMD5CheckSumBytes($ByteArr[4..($ByteArr.Length)])
        if (($md5Src -join ",") -eq ($md5Calculated[0..3] -join ",")) {
            return ($ByteArr[4..($ByteArr.Length)])
        } else {
            return $null
        }
    }
    # Generates new AES key and IV pair
    [void] NewAESKey() {
        $this.PasswordAES = $null
        $this.CryptoAES.GenerateKey()
        $this.CryptoAES.GenerateIV()
    }
    # Generates new AES key from plain text password using IV as salt
    [bool] NewAESKeyFromPassword([string]$password) {
        if ($null -ne $password) {
            $this.PasswordAES = $password
        }
        if ($null -eq $this.PasswordAES) {
            Write-Warning "No paassword defined. Cannot generate key"
            return $false
        }
        $passDerive = New-Object Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @($this.PasswordAES, $this.CryptoAES.IV)
        $iterations = 1000 + [math]::Ceiling([System.BitConverter]::ToUInt16(($this.CryptoAES.IV[0..1]),0)/100)
        $passDerive = New-Object Security.Cryptography.Rfc2898DeriveBytes -ArgumentList @($this.PasswordAES, $this.CryptoAES.IV, $iterations, 'SHA256')
        $this.CryptoAES.Key = ($passDerive.GetBytes($this.CryptoAES.KeySize / 8))
        return ([System.Convert]::ToBase64String($this.CryptoAES.Key))
    }
    # Encrypts bytes with AES encryption using current KEY and IV pair
    [byte[]] ProtectBytesAES ([byte[]]$bytes) {
        $this.InitializeEncryptionObject($this.CryptoAES.Key, $this.CryptoAES.IV)
        $encryptor = $this.CryptoAES.CreateEncryptor()
        $bytesWCHeckSum = $this.ConvertBytes2BytesWChecksum($bytes)
        $encryptedData = $encryptor.TransformFinalBlock($bytesWCHeckSum, 0, $bytesWCHeckSum.Length)
        $LenDiff = $encryptedData.length - $bytesWCHeckSum.length
        return ([byte[]]$LenDiff += $encryptedData)
    }
    # Encrypts a string using AES encryption with current KEY and IV pair. IV is stored in encrypted string for decrypt
    [string] ProtectStringAES([string]$text) {
        if ($null -eq $text -or $text.getType().Name -ne "String") {
            return  $null
        }
        if ($null -ne $this.PasswordAES) {
            $this.CryptoAES.GenerateIV()
            $null = $this.NewAESKeyFromPassword($null)
        }
        $ProtectedBytes = $this.ProtectBytesAES(([System.Text.Encoding]::UTF8.GetBytes($text)))
        $bytes = ($this.CryptoAES.IV) + $ProtectedBytes
        return ([System.Convert]::ToBase64String($bytes))
    }
    # Decrypts bytes encrypted with AES encryption using current KEY and IV pair
    [byte[]] UnProtectBytesAES ($bytes) {
        if ($null -eq $bytes -or $null -eq $bytes[0]) {
            return $null
        }
        $LenDiff = [UInt16]$bytes[0]
        $this.InitializeEncryptionObject($this.CryptoAES.Key, $this.CryptoAES.IV)
        $decryptor = $this.CryptoAES.CreateDecryptor()
        $bytesWCHeckSum = ($decryptor.TransformFinalBlock($bytes, 1, $bytes.Length - 1)) | Select-Object -SkipLast $LenDiff
        return ($this.ConvertBytesWChecksum2Bytes($bytesWCHeckSum))
    }
    # Decrypts a BASE64 AES encoded string with with current AES key and returns UTF8 encoded result
    [string] UnProtectStringAES ($Base64Text) {
        if ($null -eq $Base64Text -or $Base64Text.getType().Name -ne "String") {
            return  $null
        }
        $bytes = [System.Convert]::FromBase64String($Base64Text)
        $this.CryptoAES.IV = $bytes[0..15]
        if ($null -ne $this.PasswordAES) {
            $null = $this.NewAESKeyFromPassword($null)
        }
        $Uncrypted = $this.UnProtectBytesAES($bytes[16..$bytes.Length])
        if ($null -eq $Uncrypted) {
            return $null
        } else {
            return [System.Text.Encoding]::UTF8.GetString($Uncrypted)
        }
    }
    # Add an encryption certiicate to an global array for later use in function encryption process
    [void] AddEncryptionCertificates ($certList) {
        [string]$thumbprint =""
        foreach ($Item in $certList) {
            if ($Item.GetType().Name -eq "String") {
                $thumbprint = $Item
                $cert = Get-ChildItem "Cert:\CurrentUser\My" | Where-Object { $_.Thumbprint -eq $Item }
                if ($null -eq $cert) {
                    $cert = Get-ChildItem "Cert:\CurrentUser\AddressBook" | Where-Object { $_.Thumbprint -eq $Item }
                }
                if ($null -ne $cert) {
                    $this.EncryptionCertificates[$Thumbprint] = $cert
                }
            } elseif ($Item.GetType().Name -eq "X509Certificate2") {
                $thumbprint = $Item.Thumbprint
                $this.EncryptionCertificates[$Thumbprint] = $Item
            }
            $CKeySize = ($this.EncryptionCertificates[$thumbprint]).PublicKey.Key.KeySize
            if (0 -eq $this.minCertsKeySize -or $this.minCertsKeySize -gt $CKeySize) {
                $this.minCertsKeySize = $CKeySize
            }
            if (0 -eq $this.maxCertsKeySize -or $this.maxCertsKeySize -lt $CKeySize) {
                $this.maxCertsKeySize = $CKeySize
            }
        }
    }
    # Clears current encryption certificates and sets a new one.
    [void] SetEncryptionCertificates ($certList) {
        $this.EncryptionCertificates = @{}
        $this.minCertsKeySize = 0
        $this.maxCertsKeySize = 0
        $this.AddEncryptionCertificates($certList)
    }
    
    # Allows to encrypt long byte arrays by splitting them into chunks and encryptiong each chunk individually
    [byte[]] ProtectLongBytesPKI ($BytesToEncrypt, $Certificate) {
        # Let's calculate current RSA key encrypted bytes limit
        $chunkSize = [math]::Floor(($Certificate.PublicKey.key.KeySize - 2*160)/8 - 2)
        $Encrypted_Bytes = new-object byte[] 0
        # We'll need this number of chunks of individually encrypted data
        $totalChunks = [math]::Ceiling(($BytesToEncrypt.length) / $chunkSize)
        # Allow no more than 100 chunks. Otherwise it is good idea to use AES - RSA encryption 
        if ($totalChunks -gt 100 -or $totalChunks -le 0) {
            Write-Error "Data chunks invalid. Data is too long for this certificate or corrupted data"
            return $null
        }
        # Encrypting each chunk of data individually
        for ($currChunk=0; $currChunk -lt $totalChunks; $currChunk++) {
            $sStart = $currChunk*$chunkSize
            $sEnd = $sStart + $chunkSize -1
            $Encrypted_Bytes += $Certificate.PublicKey.Key.Encrypt(
                                $BytesToEncrypt[($sStart)..($sEnd)], $true)
        }
        return $Encrypted_Bytes
    }

    [byte[]] UnProtectLongBytesPKI ($EncryptedBytes, $Certificate)  {
        # If encrypted data size greater than keySize then it is multi-chunk data
        $chunkSize = $Certificate.PublicKey.Key.KeySize/8
        $totalChunks = ($EncryptedBytes.length) / $chunkSize
        if ($totalChunks -gt 100 -or $totalChunks -le 0) {
            Write-Error "Data chunks count invalid. Might be corrupted data"
            return $null
        }
        $Decrypted_Bytes = new-object byte[] 0

        # Decrypting each chunk of data individually
        for ($currChunk=0; $currChunk -lt $totalChunks; $currChunk++) {
            $sStart = $currChunk*$chunkSize
            $sEnd = $sStart + $chunkSize -1
            $Decrypted_Bytes += $Certificate.PrivateKey.Decrypt($EncryptedBytes[($sStart)..($sEnd)], $true)
        }
        return $Decrypted_Bytes
    }
    # Encrypts Bytes with multiple certificates and returns byte array of encrypted data
    [byte[]] ProtectBytesPKI($Bytes2Protect) {
        $encCertCount = ($this.EncryptionCertificates.Keys | Measure-Object).Count

        if ($encCertCount -lt 1) {
            Write-Warning "No certificates for encryption is specified. Can't encrypt"
            return $null
        } 
        $EncryptedBytes = new-object byte[] 0
        
        foreach ($encCert in $this.EncryptionCertificates.Values) {
            $thumbprint_Bytes = [System.Convert]::FromBase64String($encCert.Thumbprint)
            $EncryptedBytes += [System.BitConverter]::GetBytes([int16]$thumbprint_Bytes.length)
            $EncryptedBytes += $thumbprint_Bytes

            $Payload_Bytes = $this.ProtectLongBytesPKI($Bytes2Protect, $encCert)
            $EncryptedBytes += [System.BitConverter]::GetBytes([int16]($Payload_Bytes.length))
            $EncryptedBytes += $Payload_Bytes
        }
        return $EncryptedBytes
    }

    # Returns encrypted string info as an custom object
    [object] GetPKIStringInfo ($EncryptedBytes) {
        if ($EncryptedBytes.getType().Name -eq "String") {
            $EncryptedBytes = [System.Convert]::FromBase64String($EncryptedBytes)
        } elseif ($EncryptedBytes.getType().Name -ne "byte[]") {
            return $null
        }
        $Enc_Len = $EncryptedBytes.length
        $curPos = 0
        # Limit header parts
        $maxCount = 100
        $PKIStrings = @{}
        $thumbprint_check = "^[0-9A-F]"
        while ($curPos -lt $Enc_Len -and $maxCount -ge 0) {
            $Thumbprint_Len = [System.BitConverter]::ToUInt16($EncryptedBytes,$curPos)
            $curPos += 2
            if ($Thumbprint_Len -gt 60) {
                Write-Warning "Error in string header. Could not read certificate thumbprints"
                return $null
            }
            $Thumbprint = [System.Convert]::ToBase64String($EncryptedBytes[$curPos..($curPos+$Thumbprint_Len-1)])
            if (-Not ($Thumbprint -match $thumbprint_check)) {
                Write-Warning "Invalid thumbprint. Key header is corrupt"
            }
            $curPos += $Thumbprint_Len
            $Enc_Pl_Len = [System.BitConverter]::ToUInt16($EncryptedBytes,$curPos)
            if (($Enc_Pl_Len % 64) -ne 0) {
                Write-Warning "Error in string encrypted payload. Data not even to 512 bits"
                return $null
            }
            $curPos += 2
            $Enc_Payload = $EncryptedBytes[$curPos..($curPos+$Enc_Pl_Len-1)]
            $curPos += $Enc_Pl_Len
            $maxCount--
            $PKIStrings[$thumbprint] = [PSCustomObject]@{
                Thumbprint =  $Thumbprint
                EncryptedBytes = $Enc_Payload
                CertificateObj = (Get-Item "Cert:\CurrentUser\My\$($thumbprint)" -ErrorAction SilentlyContinue| Where-Object PrivateKey)
            }
        } 
        return $PKIStrings
    }

    # Decrypts encrypted bytes (AES keys, passwords) using PKI certificates stored in ServiceInfo
    [byte[]] UnProtectBytesPKI ($EncryptedBytes, $PKIStrings) {
        if ($null -eq $PKIStrings) {
            $PKIStrings = $this.GetPKIStringInfo($EncryptedBytes)
        }
        if ($null -eq $PKIStrings) {
            return $null
        }

        $validKeys = $PKIStrings.Values | Where-Object CertificateObj
        $validKeys_Count = ($validKeys | Measure-Object).Count
        if (-Not $validKeys_Count -gt 0) {
            Write-Warning "No valid private keys found. Cant' decrypt"
            return $null
        }
        $decyptionSuccess = $false; $Counter = 0; 
        while (-Not $decyptionSuccess -and $Counter -lt $validKeys_Count) {
            $decryptionCertificate = $ValidKeys[$counter].CertificateObj
            Try {
                $Bytes_Decrypted = $this.UnProtectLongBytesPKI(($ValidKeys[$counter].EncryptedBytes), $decryptionCertificate)
                $decyptionSuccess = $true
                return $Bytes_Decrypted
            } Catch {
                Write-Verbose "Problem decrypting with certificate $($decryptionCertificate.Subject)/$($decryptionCertificate.Thumbprint) $($_.Exception.Message)"
            }
            $Counter++
        }
        if (-Not $decyptionSuccess) {
            Write-Warning "Cannot decrypt AES key with private key. All found certificates with private key failed"
            return $null
        }
        return $Null
    }
    [string]ProtectStringPKI($unprotectedString) {
        $EncryptedBytes = $this.ProtectBytesPKI([Text.Encoding]::UTF8.GetBytes($unprotectedString))
        return ([System.Convert]::ToBase64String($EncryptedBytes))
    }

    [string]UnProtectStringPKI($protectedString) {
        $EncryptedBytes = [System.Convert]::FromBase64String($protectedString)
        $Bytes_Decrypted = $this.UnProtectBytesPKI($EncryptedBytes, $null)
        return ([System.Text.Encoding]::UTF8.GetString($Bytes_Decrypted))
    }
    #  Encodes information about used certificates,  keys and encrypted passwords as an bytearray for storing in binary files
    [object] NewPKIServiceInfo ($data2Encrypt, [int64]$payLoadLength, $creationTime, $lastWriteTime
                                    , $payLoadChechSum, $payLoadQuickCheckSum) {
        $HeaderFooterObj = [PSCustomObject]@{
            HeaderBytess = new-object byte[] 0
            FooterBytes = new-object byte[] 0
        }
        if ($data2Encrypt.getType().Name -eq "String") {
            $data2Encrypt = [System.Text.Encoding]::UTF8.GetBytes($data2Encrypt)
        }
        if ($payLoadQuickCheckSum.getType().Name -eq "String") {
            $payLoadQuickCheckSum = $this.Hex2Bytes($payLoadQuickCheckSum)
        }
        # Start of a footer 
        $HeaderFooterObj.FooterBytes += [byte]254,254,254,254

        #Version. 4 byte
        [int32]$version = 1
        $HeaderFooterObj.FooterBytes += ([System.BitConverter]::GetBytes($version))
        $encCertCount = ($this.EncryptionCertificates.Keys | Measure-Object).Count
        if ($encCertCount -lt 1) {
            Write-Warning "No certificates for encryption is specified."
            return $null
        }
        # Encrypting data as an Multi encryption PKI string
        $KeysHeaderBytes = $this.ProtectBytesPKI($data2Encrypt)
        # Storing length of Keys header in PKIServiceInfo
        [int32]$KeysHeaderBytes_Count = $KeysHeaderBytes.Count
        $HeaderFooterObj.FooterBytes += ([System.BitConverter]::GetBytes($KeysHeaderBytes_Count))
        # And storing Keys headerStoring length of Keys header in PKIServiceInfo
        $HeaderFooterObj.FooterBytes += $KeysHeaderBytes
        # End of Encrypted AES Key Data Block
        $HeaderFooterObj.FooterBytes += [byte]255,255,255,255
        # Saving original file length to header
        $HeaderFooterObj.FooterBytes += [System.BitConverter]::GetBytes($payLoadLength)
        # Saving original file dateTimes
        $HeaderFooterObj.FooterBytes += $this.ConvertDateTime2Bytes($creationTime)
        $HeaderFooterObj.FooterBytes += $this.ConvertDateTime2Bytes($lastWriteTime)
        # Calculating and saving checksum to file header
        $bytes = [System.Convert]::FromBase64String($payLoadChechSum)
        $HeaderFooterObj.FooterBytes += [System.BitConverter]::GetBytes($bytes.length)
        $HeaderFooterObj.FooterBytes += $bytes
        # Saving checksum to a file header of first 128 bytes
        $HeaderFooterObj.FooterBytes += [System.BitConverter]::GetBytes([int32]($payLoadQuickCheckSum.length))
        $HeaderFooterObj.FooterBytes += $payLoadQuickCheckSum
        $HeaderFooterObj.FooterBytes += [byte]255,255,255,255
        # Reserve for future end of decrypted data PTR
        # Header start should be a filelength even to 16 bytes
        $headerShouldStartAt = ([math]::Ceiling($payLoadLength/16))*16
        $HeaderFooterObj.FooterBytes += [System.BitConverter]::GetBytes([int64]$headerShouldStartAt)
        return $HeaderFooterObj
    }

    [bool] ProtectFilePKI($file2Protect, $Destination, $OverWrite) {
        $inputFile = Get-Item $file2Protect -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) {
            Write-Warning "File for encryption is not found."
            return $null
        }

        $OutputFileName = $inputFile.Name + ".AESPKI"
        
        if ($null -eq $Destination) {
            $Destination = (Get-Location).Path
        } 
        $dstFolder = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($null -eq $dstFolder -or $dstFolder.PSIsContainer -ne $true) {
            Write-Warning "Destination folder doesn't exists or not a folder."
            return $null
        }
        
        $outPutFullFileName = $dstFolder.FullName + "\" +  $OutputFileName

        if ((Test-Path $outPutFullFileName) -eq $true -and -Not $OverWrite) {
            Write-Warning "Output filename $($outPutFullFileName) already exists. Not encrypting!"
            return $null
        }

        # Check the file length and store it in the header also
        if ($inputFile.Length -le 160) {
            Write-Warning " Cannot encrypt files with length less than 160 bytes"
            return $null
        }
        
        # Generating random key for a file. Must be done prior to header-footer generation
        #$null = $this.InitializeEncryptionObject()
        $this.NewAESKey()
        $payLoadLength = $inputFile.Length
        $creationTime = $inputFile.CreationTimeUTC
        $lastWriteTime = $inputFile.LastWriteTimeUTC
        $payLoadCheckSum = (Get-FileHash $inputFile.FullName).Hash

        Try {
            $FileStreamReader = New-Object System.IO.FileStream($inputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        } Catch {
            Write-Warning $_.Exception.Message
            return $null
        }
        # Encrypting 128 bytes for quick-check before during decryption process
        $QuickCheckBytes = $this.ReadFSBytes($FileStreamReader, 128)
        # Calculating MD5 checksum of those 128 bytes. Must load asseebly ($null = [Reflection.Assembly]::LoadWithPartialName("System.Web"))
        $payLoadQuickCheckSum = $this.GetMD5CheckSumBytes($QuickCheckBytes)
        $HeaderFooterObj = $this.NewPKIServiceInfo(($this.CryptoAES.IV + $this.CryptoAES.Key)
                                                        , $payLoadLength, $creationTime, $lastWriteTime, $payLoadCheckSum, $payLoadQuickCheckSum)
        if ($null -eq $HeaderFooterObj) {
            Return $null
        }
        $this.InitializeEncryptionObject($this.CryptoAES.Key, $this.CryptoAES.IV)
        $transforms = ($this.CryptoAES).CreateEncryptor()
        Try {
            $FileStreamWriter = New-Object System.IO.FileStream($OutputFullFileName, [System.IO.FileMode]::Create)
        } Catch {
            $FileStreamReader.Close()
            Write-Warning $_.Exception.Message
            return $null
        }
        #$FileStreamWriter.Write($HeaderFooterObj.HeaderBytess, 0, $HeaderFooterObj.HeaderBytess.length)
        # Now encrypting first 128 bytes and saving them to an output file
        $encryptedBytes = $transforms.TransformFinalBlock($QuickCheckBytes, 0, $QuickCheckBytes.Length)
        $FileStreamWriter.Write($encryptedBytes, 0, $encryptedBytes.length)
        # Creating cryptoStrream and encrypting the rest of the file
        $CryptoStream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $transforms, [System.Security.Cryptography.CryptoStreamMode]::Write)
        $FileStreamReader.CopyTo($CryptoStream)
        $CryptoStream.FlushFinalBlock()
        # Saving where encrypted data ends
        [int64]$FileHeaderStart = $FileStreamWriter.Position
        # Saving footer to file (PKI service info)
        $FileStreamWriter.Write($HeaderFooterObj.FooterBytes, 0, $HeaderFooterObj.FooterBytes.length)
        # Last 8 bytes of a file is a PTR of where footer start
        $FileStreamWriter.Seek(-8, [System.IO.SeekOrigin]::End) | Out-Null
        $Bytes = [System.BitConverter]::GetBytes($FileHeaderStart)
        $FileStreamWriter.Write($Bytes,0,$bytes.Length)
        $CryptoStream.Close()
        $FileStreamReader.Close()
        $FileStreamWriter.Close()
        Write-Verbose "File '$($inputFile.Name)' successfully encrypted for $(($this.EncryptionCertificates.Keys | Measure-Object).Count) certificates as $($OutputFileName)"
        return $true
    }    

    [object] GetPKIFileServiceInfo ($fileName) {
        $inputFile = Get-Item $fileName -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) {
            Write-Warning "Input file is not found."
            return $null
        }

        $AESPKI_File = [PSCustomObject]@{
            InputFile  = $inputFile
            Version = $null
            Keys = @{}
            FooterStart = 0
            StoredFileLength = 0
            StoredFileCreationTimeUTC = $null
            StoredFileLastwriteTimeUTC = $null
            StoredFileCreationTime = $null
            StoredFileLastwriteTime = $null
            StoredFileFullHash = $null
            StoredFileQuickMD5 = $null
            HeaderIsOK = $true
        }
        Try {
            $FileStreamReader = New-Object System.IO.FileStream($inputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        } Catch {
            Write-Warning "Could not open file '$($inputFile.FullName)' for reading"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        $FileStreamReader.Seek(-12, [System.IO.SeekOrigin]::End) | Out-Null
        # Check that starting bytes should be 255,255,255,255 (- in DEC)
        $HeaderStartMark = $this.ReadFSInt32($FileStreamReader)
        if ($HeaderStartMark -ne -1) {
            $FileStreamReader.Close()
            Write-Warning "Incorrect file header end start marker. Header is corrupt or incorrect file"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        $AESPKI_File.FooterStart = $this.ReadFSUInt64($FileStreamReader)
        if ($AESPKI_File.FooterStart -gt ($fileStreamReader.length)) {
            $FileStreamReader.Close()
            Write-Warning "Could not read where PKI Service Info starts."
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        $FileStreamReader.Seek($AESPKI_File.FooterStart, [System.IO.SeekOrigin]::Begin) | Out-Null
        $FooterStartMark = $this.ReadFSInt32($FileStreamReader)
        # Check that starting bytes should be 254,254,254,254 (-16843010 in DEC)
        if ($FooterStartMark -ne -16843010) {
            $FileStreamReader.Close()
            Write-Warning "Header start mark not found. Header is corrupt or different version"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        # Reading version of file header
        $AESPKI_File.Version = $this.ReadFSUInt32($FileStreamReader)
        if ($AESPKI_File.Version -ne 1) {
            $FileStreamReader.Close()
            Write-Warning " Incorrect file header version ($($AESPKI_File.Version)). Version 1 is required."
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        [int32]$KeysHeaderBytes_Count = $this.ReadFSUInt32($FileStreamReader)
        $KeysHeaderBytes = $this.ReadFSBytes($FileStreamReader,$KeysHeaderBytes_Count)
        $FooterMark = $this.ReadFSInt32($FileStreamReader)
        # Check that starting bytes should be 254,254,254,254 (-16843010 in DEC)
        if ($FooterMark -ne -1) {
            $FileStreamReader.Close()
            Write-Warning " Incorrect file header start mark. Header is corrupt?"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        $AESPKI_File.Keys = $this.GetPKIStringInfo($KeysHeaderBytes)
        if ($null -eq $AESPKI_File.Keys) {
            $FileStreamReader.Close()
            Write-Warning " Could not read key information from header. Header is corrupt?"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }

        # Reading Length of decrypted file
        $AESPKI_File.StoredFileLength = $this.ReadFSUInt64($FileStreamReader)
        $AESPKI_File.StoredFileCreationTimeUTC = ($this.ReadFSDateTime($FileStreamReader))
        $AESPKI_File.StoredFileLastwriteTimeUTC = ($this.ReadFSDateTime($FileStreamReader))
        if ($null -eq $AESPKI_File.StoredFileCreationTimeUTC -or $null -eq $AESPKI_File.StoredFileLastwriteTimeUTC) {
            $FileStreamReader.Close()
            Write-Warning " Could not read key date information from header. Header is corrupt?"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }

        $AESPKI_File.StoredFileCreationTime = $AESPKI_File.StoredFileCreationTimeUTC.AddHours($this.UTCTimeOffset)
        $AESPKI_File.StoredFileLastwriteTime = $AESPKI_File.StoredFileLastwriteTimeUTC.AddHours($this.UTCTimeOffset)
        # Reading File HASH sum
        $SourceHash_Len = $this.ReadFSUInt32($FileStreamReader)
        if ($SourceHash_Len -gt 128) {
            $FileStreamReader.Close()
            Write-Warning "File hash is too long. Corrupt header?"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        $AESPKI_File.StoredFileFullHash = $this.ReadFSBase64String($FileStreamReader, $SourceHash_Len)
        $QMD5Loaded_Len = $this.ReadFSUInt32($FileStreamReader)
        if ($QMD5Loaded_Len -gt 64) {
            $FileStreamReader.Close()
            Write-Warning "MD5 Sum is too long ($($QMD5Loaded_Len)). Corrupt header?"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File

        }
        $AESPKI_File.StoredFileQuickMD5 = $this.ReadFSBytes($FileStreamReader, $QMD5Loaded_Len)
        # Reading End of service info block mark. Should be 255,255,255,255 (-1 in DEC)
        $EndOfHeader = $this.ReadFSInt32($FileStreamReader)
        if ($EndOfHeader -ne -1) {
            $FileStreamReader.Close()
            Write-Warning "Corrupt header. Can't find end of header bytes"
            $AESPKI_File.HeaderIsOK = $false
            return $AESPKI_File
        }
        $fileStreamReader.Close()
        if ($AESPKI_File.DecryptedFileLength -gt $AESPKI_File.InputFile.Length) {
            Write-Warning " File length mismatch. Header is corrupt?"
            $AESPKI_File.headerisOK = $false
            return $AESPKI_File
        }
        $AESPKI_File.headerisOK = $true
        return $AESPKI_File
    }
    
    [bool] UnProtectFilePKI ($file2Unprotect, $Destination, $OverWrite) {
        $inputFile = Get-Item $file2Unprotect -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) {
            Write-Warning "Input file is not found."
            return $null
        }
        if ($inputFile.Extension -eq ".AESPKI") {
            $outPutFileName =  $inputFile.BaseName
        } else {
            Write-Warning "Could not determinte output file name.  $($inputFile.Extension) is Not supported"
            return $null
        }

        if ($null -eq $Destination) {
            $Destination = (Get-Location).Path
        } 
        $dstFolder = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($null -eq $dstFolder -or $dstFolder.PSIsContainer -ne $true) {
            Write-Warning "Destination folder doesn't exists or not a folder."
            return $null
        }
        $outPutFullFileName = $dstFolder.FullName + "\" + $OutputFileName

        if ((Test-Path $outPutFullFileName) -eq $true -and -Not $OverWrite) {
            Write-Warning "Output filename $($outPutFullFileName) already exists. Not decrypting!"
            return $null
        }

        $AESPKI = $this.GetPKIFileServiceInfo($inputFile.FullName)
        if (-Not ($AESPKI.HeaderIsOk -eq $true)) {
            Write-Warning "File header is corrupt. Decryption aborted. Run FileInfo for details"
            return $null
        }
        
        $AES_Key_Decrypted = $this.UnProtectBytesPKI($null, $AESPKI.Keys)
        $this.InitializeEncryptionObject(($AES_Key_Decrypted | Select-Object -Skip 16),($AES_Key_Decrypted[0..15]))
        $transforms = $this.CryptoAES.CreateDecryptor()
        $AES_Key_Decrypted = $null

        $FileStreamReader = New-Object System.IO.FileStream($inputFile.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
        # Reading and decrypting first 128 bytes
        $QuickCheckBytes = $this.ReadFSBytes($FileStreamReader, 128)
        $decryptedBytes = $transforms.TransformFinalBlock($QuickCheckBytes, 0, $QuickCheckBytes.Length)
        # calculating their checksum
        $QuickMD5Calculated = $this.GetMD5CheckSumBytes($decryptedBytes)
        #"QuickMD5 Calculated: $QuickMD5Calculated"
        if ($this.Bytes2Hex($QuickMD5Calculated) -eq $this.Bytes2Hex($AESPKI.StoredFileQuickMD5)) {
            Write-Verbose "Quick-check completed. Decryption continues"
        } else {
            $FileStreamReader.Close()
            Write-Warning "Decryption error. Wrong key or file format."
            return $null
        }
        # Creating output file
        $FileStreamWriter = New-Object System.IO.FileStream($outPutFullFileName, [System.IO.FileMode]::Create)
        # Writing first 128 bytes
        $FileStreamWriter.Write($decryptedBytes, 0, $decryptedBytes.length)
        
        $Stream = New-Object System.Security.Cryptography.CryptoStream($FileStreamWriter, $transforms, [System.Security.Cryptography.CryptoStreamMode]::Write)
        # Setting stream length to exclude footer
        $FileStreamReader.CopyTo($Stream)
        # Adding some padding for FulushFinalBlock to finish correctly
        $bytesPadding = [byte[]]::new(16 - ($FileStreamReader.length)%16)
        $Stream.Write($bytesPadding,0, $bytesPadding.Length)
        $Stream.FlushFinalBlock()
        $FileStreamWriter.SetLength($AESPKI.StoredFileLength)
        $Stream.Close()
        $FileStreamReader.Close()
        $FileStreamWriter.Close()
        
        $outPutFile = Get-Item $outPutFullFileName
        $outPutFile.CreationTimeUTC = $AESPKI.StoredFileCreationTimeUTC
        $outPutFile.LastWriteTimeUTC = $AESPKI.StoredFileLastwriteTimeUTC
        # Calculating hash
        $decryptedHash = (Get-FileHash $outPutFullFileName).Hash
        if ($decryptedHash -eq $AESPKI.StoredFileFullHash) {
            Write-Verbose "Output file Hash Match! File decrypted correctly to $($outPutFullFileName)."
        } else {
            Write-Warning "Error during decryption of '$($inputFile.Name)'. Hash calculated don't match hash stored in encrypted header"
        }
        return $true
    }

    [bool] ProtectFolderPKI ($folderName, $Destination, $Overwrite) {
        $srcFolder = Get-Item $folderName -ErrorAction SilentlyContinue
        if ($null -eq $srcFolder -or $srcFolder.PSIsContainer -ne $true) {
            Write-Warning "Source folder doesn't exists or not a folder."
            return $null
        }
        # If destination is not specified assuming current folder
        if ($null -eq $Destination) {
            $Destination = (Get-Location).Path
        } 
        $dstFolder = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($null -eq $dstFolder -or $dstFolder.PSIsContainer -ne $true) {
            Write-Warning "Destination folder doesn't exists or not a folder."
            return $null
        }
        Write-Host "Encrypting files in folder '$($srcFolder.FullName)' to folder '$($dstFolder.FullName)'"
        $okcounter=0; $errcounter=0
        foreach ($file in (Get-ChildItem $srcFolder | Where-Object { -NOT $_.PsIsContainer -and $_.Extension -ne ".AESPKI" })) {
            # This variable is used inside ProtectFilePKI function
            if ($this.ProtectFilePKI($file.FullName, $Destination, $Overwrite) -eq $true) {
                $okcounter++
                Write-Host "." -NoNewline
            } else {
                Write-Host "X" -NoNewline
                $errcounter++
            }
        }
        Write-Host " $($okcounter) files encrypted. $($errcounter) errors"
        return $true
    }

    [bool] UnProtectFolderPKI ($folderName, $Destination, $Overwrite) {
        $srcFolder = Get-Item $folderName -ErrorAction SilentlyContinue
        if ($null -eq $srcFolder -or $srcFolder.PSIsContainer -ne $true) {
            Write-Warning "Source folder doesn't exists or not a folder."
            return $null
        }
        $dstFolder = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($null -eq $dstFolder -or $dstFolder.PSIsContainer -ne $true) {
            Write-Warning "Destination folder doesn't exists or not a folder."
            return $null
        }
        Write-Host "Decrypting files from folder '$($folderName)' to folder '$($Destination)'s"
        $okcounter=0; $errcounter=0
        foreach ($file in (Get-ChildItem $srcFolder | Where-Object { $_.Extension -eq ".AESPKI" -and -NOT $_.PsIsContainer })) {
            # This variable is used inside UnProtectFilePKI function
            if ($this.UnProtectFilePKI($file.FullName, $Destination, $Overwrite) -eq $true) {
                $okcounter++
                Write-Host "." -NoNewline
            } else {
                Write-Host "X"
                $errcounter++
            }
        }
        Write-Host ". $($okcounter) files degecrypted. $($errcounter) errors"
        return $true
    }

    # Random password generator where $len is aproximate length
    # Excluded capital letter S, O, 0 enc
    [string] NewRandomPassword([uint16]$Min_Len, [uint16]$Max_Len) {
        if ($Max_Len -gt $Min_Len -and $Max_Len -gt 1) {
            $Len = Get-Random -Minimum $Min_Len -Maximum $Max_Len
        } else {
            $Len = $Min_Len
        }
        $Randpwd=""
        $pwd_parts = [math]::Floor($len/32)
        for ($curpart=0; $curpart -lt $pwd_parts; $curpart++) {
            $Randpwd += ([char[]](Get-Random -Input $(49..57 + 65..72 + 74..78 + 80..82 + 84..90 + 97..104 + 106 + 107 + 109 + 110 + 112..122 +33+35+36+38+43+45) -Count 32)) -join ""
        }
        [uint16]$tail_Len = $len%32
        if ($tail_Len -gt 0) {
            $Randpwd += ([char[]](Get-Random -Input $(49..57 + 65..72 + 74..78 + 80..82 + 84..90 + 97..104 + 106 + 107 + 109 + 110 + 112..122 +33+35+36+38+43+45) -Count ($tail_Len))) -join ""
        }
        return $Randpwd
    }

    [bool] Compress7ZIPPKI ($folderName, $Destination, $OverWrite) {
        if ($null -eq $Destination) {
            Write-Warning "Destination archive ($Destination) not specified."
            return $null
        }
        $destinationFile = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($destinationFile -and -Not $OverWrite) {
            Write-Warning "Destination 7z file already exists. Overwrite oprtion is not set. Aborting compression"
            return $null
        }

        $encCertCount = ($this.EncryptionCertificates.Keys | Measure-Object).Count
        if ($encCertCount -lt 1) {
            Write-Warning "No certificates for encryption is specified. Can't encrypt"
            return $null
        } 
        
        $maxRSAMessageSize = [math]::Floor(($this.minCertsKeySize - 2*160)/8 - 2)
        Write-Verbose "Maximum password length $($maxRSAMessageSize) calculated from smallest public key Size"
        if ($maxRSAMessageSize -lt 64) {
            $maxRSAMessageSize = 65
        }
        $randPWD =$this.NewRandomPassword(64, $maxRSAMessageSize)

        #$secPWD = ConvertTo-SecureString -String ($randPWD) -AsPlainText -Force
        Try {
            if ($this.Options.OnlyFilesWithArchiveBit) {
                $files2Compress = Get-ChildItem -Force -Attribute A $folderName -Recurse | Where-Object PsIsContainer -eq $false
            } else {
                $files2Compress = Get-ChildItem $folderName -Force -Recurse | Where-Object PsIsContainer -eq $false
            }
            if (($files2Compress | Measure-Object).Count -lt 1) {
                Write-Host "No files found for compression. Nothing to do."
                return $null
            }

            Write-Host "Compressing $($files2Compress.Length) files." -NoNewline
            $global:ProgressDone = 0
            # Registering Event handler to display progress 
            $null = Register-ObjectEvent -InputObject ($this.SevenZipCompressor) -EventName Compressing -Action {
                if ($null -ne ($Event.SourceArgs) -and $null -ne $Event.SourceArgs[1]) {
                    $global:ProgressDone = $Event.SourceArgs[1].PercentDone
                }
            }
            $asyncObj = $this.SevenZipCompressor.CompressFilesEncryptedAsync($Destination,$randPWD, [string[]]($files2Compress.FullName))
            $prevProgressDone = 0
            while ($asyncObj.IsCompleted -eq $false -and $asyncObj.IsCanceled -eq $false -and $asyncObj.IsFaulted -eq $false) {
                # If completion percentage changed from last number displayed to user
                if ($prevProgressDone -ne $global:ProgressDone) {
                    Write-Host ".$($global:ProgressDone)%" -NoNewline
                    $prevProgressDone = $global:ProgressDone
                } else {
                    Write-Host "." -NoNewline
                }
                Start-Sleep -Milliseconds 1000
            }
            if ($asyncObj.IsCompleted) {
                Write-Host " done."
            } elseif ($asyncObj.IsCanceled) {
                Write-Host " canceled."
                Write-Warning "Process canceled"
                return null
            } elseif ($asyncObj.IsFaulted) {
                Write-Host " error."
                Write-Warning "There were errors during compression"
                return null
            }
            # If -ClearArchiveBit is set to $TRUE - clear Archive bit on files that was compressed
            if ($this.Options.ClearArchiveBit -eq $true) {
                $Arch_attribute = [io.fileattributes]::archive
                $ClearCounter = 0
                foreach ($file in $files2Compress) {
                    if ($file.Attributes -band $Arch_attribute) {
                        Set-ItemProperty -Path $file.fullname -Name attributes -value ((Get-ItemProperty $file.fullname).attributes -BXOR $Arch_attribute) -Force
                        $ClearCounter++
                    }
                }
                Write-Host "Archive attributes cleared for $($ClearCounter) files."
            }
        } Catch {
            Write-Warning $_.Exception.Message
            return $null
        }
        $7zFile = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($null -eq $7zFile){
            Write-Warning " Something went wrong during archiving process. Can't find file '$($Destination)'"
            return $null
        }
        # Making file footer
        $payLoadCheckSum = (Get-FileHash $7zFile).Hash
        $payLoadQuickCheckSum = $this.GetMD5CheckSumBytes($randPWD)
        $HeaderFooterObj = $this.NewPKIServiceInfo( $randPWD, ($7zFile.Length), ($7zFile.CreationTimeUtc)
                                        , ($7zFile.LastWriteTimeUtc), $payLoadCheckSum, $payLoadQuickCheckSum)
        Try {
            $FileStreamWriter = New-Object System.IO.FileStream($7zFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite)
        } Catch {
            Write-Warning $_.Exception.Message
            return $null
        }
        # Writing to the end of file
        $FileStreamWriter.Seek(0, [System.IO.SeekOrigin]::End) | Out-Null
        [int64]$FileHeaderStart = $FileStreamWriter.Position
        $FileStreamWriter.Write($HeaderFooterObj.FooterBytes, 0, $HeaderFooterObj.FooterBytes.length)
        # Last 8 bytes of file is a pointer to the header start
        $FileStreamWriter.Seek(-8, [System.IO.SeekOrigin]::End) | Out-Null
        $Bytes = [System.BitConverter]::GetBytes($FileHeaderStart)
        $FileStreamWriter.Write($Bytes,0,$bytes.Length)
        $FileStreamWriter.Close()
        return $true
    }
    [object] Expand7ZIPPKI ($fileName, $Destination, $OverWrite) {
        $inputFile = Get-Item $fileName -ErrorAction SilentlyContinue
        if ($null -eq $inputFile) {
            Write-Warning "Input file is not found."
            return $null
        }
        if ($null -eq $Destination) {
            $Destination = (Get-Location).Path
        } 
        
        $dstFolder = Get-Item $Destination -ErrorAction SilentlyContinue
        if ($null -eq $dstFolder -or $dstFolder.PSIsContainer -ne $true) {
            Write-Warning "Destination folder doesn't exists or not a folder."
            return $null
        }
        # Reading file headers
        $7ZPKI = $this.GetPKIFileServiceInfo($inputFile.FullName)
        if (-Not ($7ZPKI.HeaderIsOk -eq $true)) {
            Write-Warning "File header is corrupt or regular 7Z file. Run FileInfo for details"
            return $null
        }
        # Now exctracting a correct password
        $pwd_ClearText = [System.Text.Encoding]::ASCII.GetString(($this.UnProtectBytesPKI( $null, $7ZPKI.Keys)))
        # Checking password checksum
        if (($this.Bytes2Hex($this.GetMD5CheckSumBytes($pwd_ClearText))) -ne ($this.Bytes2Hex($7ZPKI.StoredFileQuickMD5))) {
            Write-Warning "Quick checksum mismatch. Decryption failed. Wrong key or file format?"
            return $null
        }
        # If option  -ExtractPasswordOnly specified output archive password
        if ($this.options.ExtractPasswordOnly -eq $true) {
            return $pwd_ClearText
        # If -ListContentsOnly specified return archive contents
        } elseif ($this.Options.ListContentsOnly) {
            $SevenZipExtractor = New-Object sevenzip.SevenZipExtractor($inputFile.FullName, $pwd_ClearText)
            $outObj = $SevenZipExtractor.ArchiveFileData
            $SevenZipExtractor.Dispose()
            return $outObj
        # This is an extract procedure
        } else {
            Try {
                $SevenZipExtractor = New-Object sevenzip.SevenZipExtractor($inputFile.FullName, $pwd_ClearText)
                $global:ProgressDone = 0
                $null = Register-ObjectEvent -InputObject $SevenZipExtractor -EventName Extracting -Action {
                    if ($null -ne ($Event.SourceArgs) -and $null -ne $Event.SourceArgs[1]) {
                        $global:ProgressDone = $Event.SourceArgs[1].PercentDone
                    }
                }
            } Catch {
                Write-Warning $_.Exception.Message
                return $null
            }
            Write-Host "Expanding $($inputFile.FullName) ($($SevenZipExtractor.FilesCount) files) to '$($dstFolder.FullName)'." -NoNewline
            $asyncObj = $SevenZipExtractor.ExtractArchiveAsync($dstFolder.FullName)
            $prevProgressDone = 0
            do {
                if ($prevProgressDone -ne $global:ProgressDone) {
                    Write-Host ".$($global:ProgressDone)%" -NoNewline
                } else {
                    Write-Host "." -NoNewline
                }
                $prevProgressDone = $global:ProgressDone
                Start-Sleep -Milliseconds 1000
            }   while ($asyncObj.IsCompleted -eq $false -and $asyncObj.IsCanceled -eq $false -and $asyncObj.IsFaulted -eq $false)
            if ($asyncObj.IsCompleted) {
                Write-Host "done."
            } elseif ($asyncObj.IsCanceled) {
                Write-Host "canceled."
                Write-Warning "Process canceled"
                return null
            } elseif ($asyncObj.IsFaulted) {
                Write-Host "Error."
                Write-Warning "There were errors during compression"
                return null
            }
            $SevenZipExtractor.dispose()
        }
        return $true
    }
    [byte[]] ProtectBytesPKIAES ($ByteArr) {
        $this.NewAESKey()
        $bytes = $this.ConvertBytes2BytesWChecksum($ByteArr)
        $ProtectedKeyBytes = $this.ProtectBytesPKI(($this.CryptoAES.IV + $this.CryptoAES.Key))
        [int16]$ProtectedBytes_Len = $ProtectedKeyBytes.length
        $ProtectedBytes = new-object byte[] 0
        $ProtectedBytes += ([System.BitConverter]::GetBytes($ProtectedBytes_Len))
        $ProtectedBytes += $ProtectedKeyBytes
        $ProtectedBytes += ($this.ProtectBytesAES($Bytes))
        return  ($ProtectedBytes)
    }

    [byte[]] UnProtectBytesPKIAES($Bytes) {
        $ProtectedBytes_Len =  [System.BitConverter]::ToInt16(($Bytes[0,1]),  0)
        [byte[]]$ProtectedKey = ($bytes[2..($ProtectedBytes_Len+1)])
        $KeyBytes = $this.UnProtectBytesPKI($ProtectedKey, $null)
        $this.CryptoAES.IV = $KeyBytes[0..15]
        $this.CryptoAES.Key = $KeyBytes[16..($KeyBytes.length)]
        $UnprotectedBytes = $this.UnProtectBytesAES([byte[]]($bytes[($ProtectedBytes_Len+2)..($Bytes.Length)]))
        return ($this.ConvertBytesWChecksum2Bytes($UnprotectedBytes))
    }
    [string] ProtectStringPKIAES ($unprotectedString) {
        $ProtectedBytes = $this.ProtectBytesPKIAES([System.Text.Encoding]::UTF8.GetBytes($unprotectedString))
        return  ([System.Convert]::ToBase64String($ProtectedBytes))
    }
    [string] UnProtectStringPKIAES ($protectedString) {
        $bytes = [System.Convert]::FromBase64String($protectedString)
        $String = $this.UnProtectBytesPKIAES($bytes)
        return ([System.Text.Encoding]::UTF8.GetString($String))
    }
}
