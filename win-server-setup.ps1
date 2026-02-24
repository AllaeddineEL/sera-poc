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
    `$PfxPasswordPlain = "IISPassword"

Start-Process -FilePath "certutil.exe" ``
    -ArgumentList "-p `$PfxPasswordPlain,`$PfxPasswordPlain -MergePFX $VaultDataDir\$SubDomain.cer $VaultDataDir\$SubDomain.pfx" ``
    -Wait -NoNewWindow

Import-Module WebAdministration

if (-not (Test-Path `"$VaultDataDir\$SubDomain.pfx`")) {
    throw "PFX not found: $VaultDataDir\$SubDomain.pfx"
}

if (-not (Get-Website -Name `"$SiteName`" -ErrorAction SilentlyContinue)) {
    throw "IIS site not found: $SiteName"
}

`$securePwd = ConvertTo-SecureString `$PfxPasswordPlain -AsPlainText -Force

# Import cert to LocalMachine\My

`$params = @{
    FilePath = '$VaultDataDir\$SubDomain.pfx'
    CertStoreLocation = 'Cert:\LocalMachine\My'
    Password = `$securePwd
}

`$cert = Import-PfxCertificate @params


if (-not `$cert) {
    throw "Certificate import failed."
}

Remove-Item -Path `"$VaultDataDir\$SubDomain.pfx`" -Force

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

$VaultDataDir = $VaultDataDir -replace '\\','/'
$VaultPKITemplate = $VaultPKITemplate -replace '\\','/'
$VaultPKIOutput = $VaultPKIOutput -replace '\\','/'



    if (Test-Path $VaultConfigPath) {
        Write-Host "Vault agent config already exists: $VaultConfigPath"
        return
    }
    @"
{{ with pkiCert "pki_int/issue/win-iis" "common_name=$SubDomain.$Domain" "ttl=2m"}}
{{ .Data.Cert }}{{ .Data.CA }}{{ .Data.Key }}
{{ .Data.Key | writeToFile "$VaultDataDir/$SubDomain.key" "" "" "0644" }}
{{ .Data.Cert | writeToFile "$VaultDataDir/$SubDomain.cer" "" "" "0644" }}
{{ end }}    
"@ | Set-Content -Path $VaultPKITemplate -Encoding ASCII

    @"
c831f520-8fa8-d8ac-2435-a22a0a8eea2c
"@ | Set-Content -Path $VaultAuthPathRoleId -Encoding ASCII

    @"
b3203e5c-f2e6-47ba-2c3a-5157ed816072
"@ | Set-Content -Path $VaultAuthPathSecretId -Encoding ASCII

    @"
# Update this file for your environment before production use.

pid_file = "$VaultDataDir/agent.pid"

log_level = "debug"
log_file  = "$VaultDataDir/agent.log"
log_rotate_duration = "10m"

vault {
  address = "$VaultAddr"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path   = "$VaultDataDir/role_id"
      secret_id_file_path = "$VaultDataDir/secret_id"
    }
  }

  sink "file" {
    config = {
      path = "$VaultDataDir/token"
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
        command = ["powershell.exe", "$VaultDataDir/install-cert.ps1"]
        timeout = "120s"
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
#Install-IIS
#Install-Vault
Write-CertInstallScript
Write-DefaultAgentConfig

Install-VaultAgentService

Write-Host "`nDone."
Write-Host "Next:"
Write-Host "1) Edit $VaultConfigPath"
Write-Host "2) Validate config: `"$VaultInstallDir\vault.exe`" agent -config=`"$VaultConfigPath`" -log-level=info"
Write-Host "3) Start service: Start-Service $ServiceName"