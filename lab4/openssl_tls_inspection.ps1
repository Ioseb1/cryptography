# PowerShell Script for TLS/HTTPS Certificate Inspection
# Alternative to OpenSSL s_client for Windows

param(
    [string]$Website = "www.google.com",
    [int]$Port = 443
)

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "TLS/HTTPS Certificate Inspection" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Connecting to: $Website`:$Port" -ForegroundColor Yellow
Write-Host ""

# Function to get certificate details
function Get-CertificateInfo {
    param([string]$HostName, [int]$Port)
    
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient($HostName, $Port)
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {$true})
        $sslStream.AuthenticateAsClient($HostName)
        
        $certificate = $sslStream.RemoteCertificate
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certificate)
        
        return @{
            Certificate = $cert
            SslStream = $sslStream
            TcpClient = $tcpClient
        }
    }
    catch {
        Write-Host "Error connecting: $_" -ForegroundColor Red
        return $null
    }
}

# Connect and get certificate
Write-Host "=== Connecting to $Website ===" -ForegroundColor Green
$result = Get-CertificateInfo -HostName $Website -Port $Port

if ($result -eq $null) {
    Write-Host "Failed to connect. Please check if OpenSSL is available or use the bash script." -ForegroundColor Red
    exit 1
}

$cert = $result.Certificate

# Display certificate information
Write-Host ""
Write-Host "=== Certificate Details ===" -ForegroundColor Green
Write-Host "Subject: $($cert.Subject)" -ForegroundColor White
Write-Host "Issuer: $($cert.Issuer)" -ForegroundColor White
Write-Host "Serial Number: $($cert.SerialNumber)" -ForegroundColor White
Write-Host "Thumbprint: $($cert.Thumbprint)" -ForegroundColor White
Write-Host ""

Write-Host "=== Validity Period ===" -ForegroundColor Green
Write-Host "Valid From: $($cert.NotBefore)" -ForegroundColor White
Write-Host "Valid To: $($cert.NotAfter)" -ForegroundColor White
Write-Host "Days Remaining: $((New-TimeSpan -Start (Get-Date) -End $cert.NotAfter).Days)" -ForegroundColor White
Write-Host ""

Write-Host "=== Certificate Extensions ===" -ForegroundColor Green
foreach ($extension in $cert.Extensions) {
    Write-Host "$($extension.Oid.FriendlyName): $($extension.Format($true))" -ForegroundColor White
}
Write-Host ""

Write-Host "=== Cipher Information ===" -ForegroundColor Green
Write-Host "Protocol: $($result.SslStream.SslProtocol)" -ForegroundColor White
Write-Host "Cipher Algorithm: $($result.SslStream.CipherAlgorithm)" -ForegroundColor White
Write-Host "Cipher Strength: $($result.SslStream.CipherStrength) bits" -ForegroundColor White
Write-Host "Hash Algorithm: $($result.SslStream.HashAlgorithm)" -ForegroundColor White
Write-Host "Hash Strength: $($result.SslStream.HashStrength) bits" -ForegroundColor White
Write-Host ""

# Save certificate to file
$certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
[System.IO.File]::WriteAllBytes("server_certificate.cer", $certBytes)
Write-Host "Certificate saved to: server_certificate.cer" -ForegroundColor Green

# Save details to text file
$output = @"
Certificate Inspection Report
=============================
Website: $Website
Port: $Port
Date: $(Get-Date)

Subject: $($cert.Subject)
Issuer: $($cert.Issuer)
Serial Number: $($cert.SerialNumber)
Thumbprint: $($cert.Thumbprint)

Validity Period:
  Valid From: $($cert.NotBefore)
  Valid To: $($cert.NotAfter)
  Days Remaining: $((New-TimeSpan -Start (Get-Date) -End $cert.NotAfter).Days)

Cipher Information:
  Protocol: $($result.SslStream.SslProtocol)
  Cipher Algorithm: $($result.SslStream.CipherAlgorithm)
  Cipher Strength: $($result.SslStream.CipherStrength) bits
  Hash Algorithm: $($result.SslStream.HashAlgorithm)
  Hash Strength: $($result.SslStream.HashStrength) bits

Extensions:
$($cert.Extensions | ForEach-Object { "  $($_.Oid.FriendlyName): $($_.Format($true))" } | Out-String)
"@

[System.IO.File]::WriteAllText("certificate_details.txt", $output)
Write-Host "Certificate details saved to: certificate_details.txt" -ForegroundColor Green

# Cleanup
$result.SslStream.Close()
$result.TcpClient.Close()

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "Inspection complete!" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

