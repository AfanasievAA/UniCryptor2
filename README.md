# UniCryptor2
Powershell class object used for different types of encryption and decryption purposes.

Can be used to encrypt and decrypt following instances:
  1) Strings using RSA, AES, or RSAAES encryption algorithms
  2) Files using RSAAES encryption algorotm. 
  3) Folders with files using RSAAES encryption algorotm. 
  4) Create 7Z archives using RSA encryption algorithm (Generates a long password and encrypts it using RSA PKI encryption)
  5) Create 7Z archives of files with Archive attribute set (for backup purposes) and (optionalluy) reset that attribute after successfull archiving
  
   SevenZipSharp and 7z64.dll libraries are needed for a script to work properly
   
