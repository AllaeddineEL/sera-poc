    

$PfxPasswordPlain = "IISPassword"

Start-Process -FilePath "certutil.exe" `
    -ArgumentList "-p $PfxPasswordPlain,$PfxPasswordPlain -MergePFX C:\ProgramData\Vault\ip-172-31-67-198-ec2.cer C:\ProgramData\Vault\ip-172-31-67-198-ec2.pfx" `
    -Wait -NoNewWindow

Import-Module WebAdministration


if (-not (Test-Path "C:\ProgramData\Vault\ip-172-31-67-198-ec2.pfx")) {
    throw "PFX not found: C:\ProgramData\Vault\ip-172-31-67-198-ec2.pfx"
}

if (-not (Get-Website -Name "Default Web Site" -ErrorAction SilentlyContinue)) {
    throw "IIS site not found: Default Web Site"
}

$securePwd = ConvertTo-SecureString $PfxPasswordPlain -AsPlainText -Force

$params = @{
    FilePath = 'C:\ProgramData\Vault\ip-172-31-67-198-ec2.pfx'
    CertStoreLocation = 'Cert:\LocalMachine\My'
    Password = $securePwd
}

# Import cert to LocalMachine\My
$cert = Import-PfxCertificate @params

if (-not $cert) {
    throw "Certificate import failed."
}

Remove-Item -Path "C:\ProgramData\Vault\ip-172-31-67-198-ec2.pfx"

# Ensure HTTPS binding exists
$binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -IPAddress "*" -HostHeader "ip-172-31-67-198.ec2.internal" -ErrorAction SilentlyContinue
if (-not $binding) {
    New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -IPAddress "*" -HostHeader "ip-172-31-67-198.ec2.internal" -SslFlags 0 | Out-Null
    $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443 -IPAddress "*" -HostHeader "ip-172-31-67-198.ec2.internal"
}

# Attach certificate to the binding
$binding.AddSslCertificate($cert.Thumbprint, "My")

Write-Host "Certificate thumbprint: $($cert.Thumbprint)"
Write-Host "Bound to site 'Default Web Site' on https://ip-172-31-67-198.ec2.internal"

