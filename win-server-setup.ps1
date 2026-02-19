<#
.SYNOPSIS
Installs IIS + HashiCorp Vault (agent mode) on Windows Server.

.NOTES
- Run as Administrator.
- Update the generated agent config before starting in production.
#>

param(
    [string]$VaultVersion    = "1.21.3",
    [string]$VaultInstallDir = "C:\Program Files\Vault",
    [string]$VaultDataDir    = "C:\ProgramData\Vault",
    [string]$VaultConfigPath = "C:\ProgramData\Vault\agent.hcl",
    [string]$VaultPKITemplate = "C:\ProgramData\Vault\pki-cert.tpl",
    [string]$VaultPKIOutput = "C:\ProgramData\Vault\pki-cert.pem",
    [string]$VaultPKIPrivateCertOutput = "C:\ProgramData\Vault\iis.cert",
    [string]$VaultPKIPrivateKeyOutput = "C:\ProgramData\Vault\iis.key",
    [string]$VaultAuthPathRoleId = "C:\ProgramData\Vault\role_id",
    [string]$VaultAuthPathSecretId = "C:\ProgramData\Vault\secret_id",
    [string]$VaultAddr = "http://172.31.83.4:8200", #change to your vault address
    [string]$Domain = "ec2.internal",
    [string]$SubDomain = "ip-172-31-67-198",  #change to your server's hostname or desired subdomain
    [string]$IpAddress = "*", #change to specific IP if needed
    [string]$ServiceName     = "VaultAgent",
    [string]$SiteName     = "Default Web Site",
    [string]$HostHeader   = "ip-172-31-67-198.ec2.internal" #change to your server's FQDN
)

$ErrorActionPreference = "Stop"

function Write-CertInstallScript {
    @"
    `$bytes = New-Object byte[] 24
 [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes(`$bytes)

    `$PfxPasswordPlain = [System.Text.Encoding]::UTF8.GetString(`$bytes)

Start-Process -FilePath "certutil.exe" `
    -ArgumentList "-p `$PfxPasswordPlain,`$PfxPasswordPlain -MergePFX $VaultDataDir\$SubDomain-$Domain.cer $VaultDataDir\$SubDomain-$Domain.pfx" `
    -Wait -NoNewWindow

Import-Module WebAdministration

if (-not (Test-Path `"$VaultDataDir\$SubDomain-$Domain.pfx`")) {
    throw "PFX not found: $VaultDataDir\$SubDomain-$Domain.pfx"
}

if (-not (Get-Website -Name `"$SiteName`" -ErrorAction SilentlyContinue)) {
    throw "IIS site not found: $SiteName"
}

`$securePwd = ConvertTo-SecureString `$PfxPasswordPlain -AsPlainText -Force

# Import cert to LocalMachine\My
`$cert = Import-PfxCertificate `
    -FilePath `"$VaultDataDir\$SubDomain-$Domain.pfx`" `
    -Password `$securePwd `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -Exportable

if (-not `$cert) {
    throw "Certificate import failed."
}


# Ensure HTTPS binding exists
`$binding = Get-WebBinding -Name `"$SiteName`" -Protocol "https" -Port 443 -IPAddress `"$IpAddress`" -HostHeader `"$HostHeader`" -ErrorAction SilentlyContinue
if (-not `$binding) {
    New-WebBinding -Name `"$SiteName`" -Protocol "https" -Port 443 -IPAddress `"$IpAddress`" -HostHeader `"$HostHeader`" -SslFlags 0 | Out-Null
    `$binding = Get-WebBinding -Name `"$SiteName`" -Protocol "https" -Port 443 -IPAddress `"$IpAddress`" -HostHeader `"$HostHeader`"
}

# Attach certificate to the binding
`$binding.AddSslCertificate(`$cert.Thumbprint, "My")

Write-Host "Certificate thumbprint: `$(`$cert.Thumbprint)"
Write-Host "Bound to site '$SiteName' on https://$($HostHeader)"

"@ | Set-Content -Path "$VaultDataDir\install-cert.ps1" -Encoding ASCII
    Write-Host "Created cert install script: install-cert.ps1"
}
function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this script in an elevated PowerShell session (Administrator)."
    }
}

function Install-IIS {
    Write-Host "Installing IIS..."
    Install-WindowsFeature -Name Web-Server -IncludeManagementTools | Out-Null
    Write-Host "IIS installation complete."
}

function Install-Vault {
    Write-Host "Installing Vault $VaultVersion..."
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    New-Item -ItemType Directory -Path $VaultInstallDir -Force | Out-Null
    New-Item -ItemType Directory -Path $VaultDataDir -Force | Out-Null

    $zipUrl  = "https://releases.hashicorp.com/vault/${VaultVersion}+ent/vault_${VaultVersion}+ent_windows_amd64.zip"
    
    $zipPath = Join-Path $env:TEMP "vault_${VaultVersion}+ent_windows_amd64.zip"

    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
    Expand-Archive -Path $zipPath -DestinationPath $VaultInstallDir -Force
    Remove-Item $zipPath -Force

    $vaultExe = Join-Path $VaultInstallDir "vault.exe"
    if (-not (Test-Path $vaultExe)) { throw "vault.exe not found after extraction." }

    # Optional: add to PATH
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    if ($machinePath -notlike "*$VaultInstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$machinePath;$VaultInstallDir", "Machine")
    }

    & $vaultExe version
    Write-Host "Vault installed at $vaultExe"
}

function Write-DefaultAgentConfig {
    if (Test-Path $VaultConfigPath) {
        Write-Host "Vault agent config already exists: $VaultConfigPath"
        return
    }
    @"
{{ with pkiCert "pki_int/issue/win-iis" "common_name=$SubDomain.$Domain" "ttl=2m"}}
{{ .Data.Key | writeToFile "C:/ProgramData/Vault/$SubDomain-$Domain.key" "" "" "0400"}}
{{ .Data.CA | writeToFile "C:/ProgramData/Vault/$SubDomain-$Domain.cer" "" "" "0400"}}
{{ .Data.Cert | writeToFile "C:/ProgramData/Vault/$SubDomain-$Domain.cer" "" "" "0400" "append" }}
{{ end }}    
"@ | Set-Content -Path $VaultPKITemplate -Encoding ASCII

    @"
dcba7c4e-54c2-c4d2-af80-88bbefb18f12
"@ | Set-Content -Path $VaultAuthPathRoleId -Encoding ASCII

    @"
6c286ced-b90f-5c9b-f5ff-cffebe52ced2
"@ | Set-Content -Path $VaultAuthPathSecretId -Encoding ASCII

    @"
# Update this file for your environment before production use.
pid_file = "$VaultDataDir\agent.pid"

vault {
  address = "$VaultAddr"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "$VaultDataDir\role_id"
      secret_id_file_path = "$VaultDataDir\secret_id"
    }
  }

  sink "file" {
    config = {
      path = "$VaultDataDir\token"
    }
  }
}

template_config {
  static_secret_render_interval = "5m"
}

template {
source      = "$VaultPKITemplate"
destination = "$VaultPKIOutput"
    exec {
        command = ["C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe", "$VaultDataDir/copy-key.ps1"]
        timeout = "30s"
    }
}
"@ | Set-Content -Path $VaultConfigPath -Encoding ASCII

    Write-Host "Created default Vault agent config: $VaultConfigPath"
}

function Install-VaultAgentService {
    $vaultExe = Join-Path $VaultInstallDir "vault.exe"
    $binaryPath = "`"$vaultExe`" agent -config=`"$VaultConfigPath`""

    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
        Write-Host "Service '$ServiceName' already exists. Updating startup type..."
        Set-Service -Name $ServiceName -StartupType Automatic
    } else {
        New-Service -Name $ServiceName `
                    -BinaryPathName $binaryPath `
                    -DisplayName "HashiCorp Vault Agent" `
                    -Description "Runs Vault Agent in service mode." `
                    -StartupType Automatic
        Write-Host "Created service: $ServiceName"
    }

    Write-Host "Service installed. Start it with: Start-Service $ServiceName"
}

Assert-Admin
Install-IIS
Install-Vault
Write-CertInstallScript
Write-DefaultAgentConfig

Install-VaultAgentService

Write-Host "`nDone."
Write-Host "Next:"
Write-Host "1) Edit $VaultConfigPath"
Write-Host "2) Validate config: `"$VaultInstallDir\vault.exe`" agent -config=`"$VaultConfigPath`" -log-level=info"
Write-Host "3) Start service: Start-Service $ServiceName"
