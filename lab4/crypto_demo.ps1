# PowerShell Script for Cryptography Demonstration
# Uses .NET cryptography classes

# Function to generate RSA key pair
function Generate-RSAKeyPair {
    Write-Host "Generating RSA key pair..." -ForegroundColor Green
    
    $rsa = New-Object System.Security.Cryptography.RSACryptoServiceProvider(2048)
    
    # Export private key in XML format (PEM-like)
    $privateKeyXml = $rsa.ToXmlString($true)
    [System.IO.File]::WriteAllText("$PWD\private.pem", $privateKeyXml)
    
    # Export public key in XML format
    $publicKeyXml = $rsa.ToXmlString($false)
    [System.IO.File]::WriteAllText("$PWD\public.pem", $publicKeyXml)
    
    Write-Host "RSA key pair generated: private.pem, public.pem" -ForegroundColor Green
    return $rsa
}

# Function to encrypt with RSA
function Encrypt-RSA {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [System.Security.Cryptography.RSACryptoServiceProvider]$PublicKey
    )
    
    Write-Host "Encrypting $InputFile with RSA..." -ForegroundColor Green
    
    $plaintext = [System.IO.File]::ReadAllBytes($InputFile)
    
    # RSA with OAEP can encrypt max 214 bytes for 2048-bit key
    # For larger files, we need to split into chunks
    $maxChunkSize = 214
    $output = New-Object System.Collections.ArrayList
    
    for ($i = 0; $i -lt $plaintext.Length; $i += $maxChunkSize) {
        $chunkSize = [Math]::Min($maxChunkSize, $plaintext.Length - $i)
        $chunk = New-Object byte[] $chunkSize
        [Array]::Copy($plaintext, $i, $chunk, 0, $chunkSize)
        
        $encryptedChunk = $PublicKey.Encrypt($chunk, $true)  # OAEP padding
        $output.AddRange($encryptedChunk)
    }
    
    [System.IO.File]::WriteAllBytes($OutputFile, $output.ToArray())
    Write-Host "Encrypted file saved: $OutputFile" -ForegroundColor Green
}

# Function to decrypt with RSA
function Decrypt-RSA {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [System.Security.Cryptography.RSACryptoServiceProvider]$PrivateKey
    )
    
    Write-Host "Decrypting $InputFile with RSA..." -ForegroundColor Green
    
    $ciphertext = [System.IO.File]::ReadAllBytes($InputFile)
    
    # RSA encrypted chunks are 256 bytes each (2048 bits = 256 bytes)
    $chunkSize = 256
    $output = New-Object System.Collections.ArrayList
    
    for ($i = 0; $i -lt $ciphertext.Length; $i += $chunkSize) {
        $chunk = New-Object byte[] $chunkSize
        [Array]::Copy($ciphertext, $i, $chunk, 0, $chunkSize)
        
        $decryptedChunk = $PrivateKey.Decrypt($chunk, $true)  # OAEP padding
        $output.AddRange($decryptedChunk)
    }
    
    [System.IO.File]::WriteAllBytes($OutputFile, $output.ToArray())
    Write-Host "Decrypted file saved: $OutputFile" -ForegroundColor Green
}

# Function to generate AES key and IV
function Generate-AESKeyIV {
    Write-Host "Generating AES-256 key and IV..." -ForegroundColor Green
    
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.KeySize = 256
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateKey()
    $aes.GenerateIV()
    
    [System.IO.File]::WriteAllBytes("$PWD\aes_key.bin", $aes.Key)
    [System.IO.File]::WriteAllBytes("$PWD\aes_iv.bin", $aes.IV)
    
    Write-Host "AES key and IV generated: aes_key.bin, aes_iv.bin" -ForegroundColor Green
    return $aes
}

# Function to encrypt with AES
function Encrypt-AES {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [byte[]]$Key,
        [byte[]]$IV
    )
    
    Write-Host "Encrypting $InputFile with AES-256..." -ForegroundColor Green
    
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $Key
    $aes.IV = $IV
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $plaintext = [System.IO.File]::ReadAllBytes($InputFile)
    $encryptor = $aes.CreateEncryptor()
    $ciphertext = $encryptor.TransformFinalBlock($plaintext, 0, $plaintext.Length)
    
    [System.IO.File]::WriteAllBytes($OutputFile, $ciphertext)
    Write-Host "Encrypted file saved: $OutputFile" -ForegroundColor Green
}

# Function to decrypt with AES
function Decrypt-AES {
    param(
        [string]$InputFile,
        [string]$OutputFile,
        [byte[]]$Key,
        [byte[]]$IV
    )
    
    Write-Host "Decrypting $InputFile with AES-256..." -ForegroundColor Green
    
    $aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $aes.Key = $Key
    $aes.IV = $IV
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $ciphertext = [System.IO.File]::ReadAllBytes($InputFile)
    $decryptor = $aes.CreateDecryptor()
    $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    
    [System.IO.File]::WriteAllBytes($OutputFile, $plaintext)
    Write-Host "Decrypted file saved: $OutputFile" -ForegroundColor Green
}

# Main execution
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "Cryptography Demonstration: RSA and AES-256" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host ""

# Step 1: Generate RSA key pair
$rsa = Generate-RSAKeyPair
Write-Host ""

# Step 2: RSA Encryption
Encrypt-RSA -InputFile "message.txt" -OutputFile "message_rsa_encrypted.bin" -PublicKey $rsa
Write-Host ""

# Step 3: RSA Decryption
Decrypt-RSA -InputFile "message_rsa_encrypted.bin" -OutputFile "message_rsa_decrypted.txt" -PrivateKey $rsa
Write-Host ""

# Step 4: Generate AES key and IV
$aes = Generate-AESKeyIV
Write-Host ""

# Step 5: AES Encryption
Encrypt-AES -InputFile "message.txt" -OutputFile "message_aes_encrypted.bin" -Key $aes.Key -IV $aes.IV
Write-Host ""

# Step 6: AES Decryption
Decrypt-AES -InputFile "message_aes_encrypted.bin" -OutputFile "message_aes_decrypted.txt" -Key $aes.Key -IV $aes.IV
Write-Host ""

Write-Host ("=" * 60) -ForegroundColor Cyan
Write-Host "All operations completed successfully!" -ForegroundColor Cyan
Write-Host ("=" * 60) -ForegroundColor Cyan

