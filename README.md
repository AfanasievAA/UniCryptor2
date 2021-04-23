# UniCryptor2
Powershell class object used for different types of encryption and decryption purposes.
This class is used in my work projects. Just wanted to share for anyone searching for this kind of POWERSHELL code.

Can be used to encrypt and decrypt following instances:
  1) Strings using RSA, AES, or RSA+AES encryption algorithms (in case of very long strings)
  2) Files using RSA+AES encryption algorotm. So you can encrypt a file using someone's open certificate and private key will be needed to decrypt one.
  3) Folders with files using RSA+AES encryption algorotm. Same as files but encrypts or decryptes all files in folder.
  4) Create 7Z archives using RSA encryption algorithm (Generates a long password and encrypts it using RSA encryption). So, you can create archives using someone's open certificate and send them to a person. Private key is needed to extract files.
  5) Create 7Z archives of files with Archive attribute set (for backup purposes) and (optionalluy) reset that attribute after successfull archiving. So you can create secure backup files jobs. All specified files will be backed up to 7Z archive using open certificate. After that, they can be stored anywhere (cloud storage). Private key is neeeded to decrypt those archives.
  
   SevenZipSharp and 7z64.dll libraries are needed for a script to work properly. Included in BIN.ZIP archive. Or you can download yours.
   
   Also, I've included number of examples in PS1 files. 
  
