#requires -Version 5.1
<#
  SYSCOHADA CM Hostinger AutoRun.
  The launcher transfers this reviewed kit over OpenSSH. It never reads or stores
  your SSH password, disables host-key verification, or changes execution policy.
#>
[CmdletBinding()]
param(
    [ValidateSet('plan','install','resume','status')]
    [string]$Mode = 'install',
    [string]$VpsIp = '',
    [string]$SshUser = 'root',
    [ValidateRange(1,65535)]
    [int]$SshPort = 22,
    [string]$Domain = '',
    [string]$Email = '',
    [string]$Company = '',
    [string]$IdentityFile = '',
    [switch]$AcceptAcmeTerms
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Mode = $Mode.ToLowerInvariant()

function Assert-IPv4([string]$Value) {
    if ($Value -notmatch '^[0-9]{1,3}(\.[0-9]{1,3}){3}$') { throw 'Indiquez une adresse IPv4 publique du VPS.' }
    foreach ($part in $Value.Split('.')) {
        if (($part.Length -gt 1 -and $part.StartsWith('0')) -or [int]$part -gt 255) {
            throw 'Adresse IPv4 invalide.'
        }
    }
}

function Assert-Domain([string]$Value) {
    if ($Value.Length -gt 253 -or $Value -notmatch '^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$') {
        throw 'Domaine invalide : exemple attendu dsf.votredomaine.com, sans https:// ni chemin.'
    }
    foreach ($label in $Value.Split('.')) { if ($label.Length -gt 63) { throw 'Une partie du domaine depasse 63 caracteres.' } }
}

function Invoke-Native([string]$Program, [string[]]$ArgumentList) {
    & $Program @ArgumentList
    if ($LASTEXITCODE -ne 0) { throw "La commande $Program a echoue (code $LASTEXITCODE). Deploiement arrete." }
}

foreach ($tool in @('ssh.exe','scp.exe','tar.exe')) {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "$tool est requis. Installez le client OpenSSH et les outils Windows standards, ou utilisez la console Web Hostinger avec install.sh."
    }
}

$kit = $PSScriptRoot
foreach ($item in @('install.sh','bin','lib','templates','payload')) {
    if (-not (Test-Path -LiteralPath (Join-Path $kit $item))) { throw "Kit incomplet : $item est absent." }
}

if ([string]::IsNullOrWhiteSpace($VpsIp)) { $VpsIp = (Read-Host 'Adresse IPv4 publique du VPS Hostinger').Trim() }
Assert-IPv4 $VpsIp
if ($SshUser -notmatch '^[A-Za-z_][A-Za-z0-9_-]{0,31}$') { throw 'Nom utilisateur SSH invalide.' }
if ($IdentityFile) {
    if (-not (Test-Path -LiteralPath $IdentityFile -PathType Leaf)) { throw 'Fichier de cle SSH introuvable.' }
    $IdentityFile = (Resolve-Path -LiteralPath $IdentityFile).Path
}

$needsConfig = $Mode -eq 'install' -or $Mode -eq 'plan'
$config = $null
if ($needsConfig) {
    if ([string]::IsNullOrWhiteSpace($Domain)) { $Domain = (Read-Host 'Domaine de votre application, exemple dsf.votredomaine.com').Trim() }
    $Domain = $Domain.ToLowerInvariant()
    Assert-Domain $Domain
    if ([string]::IsNullOrWhiteSpace($Email)) { $Email = (Read-Host 'Email administrateur et contact du certificat HTTPS').Trim() }
    if ($Email.Length -gt 254 -or $Email -notmatch '^[A-Za-z0-9.!#$%&''*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$') {
        throw 'Adresse email invalide.'
    }
    if ([string]::IsNullOrWhiteSpace($Company)) { $Company = (Read-Host 'Raison sociale').Trim() }
    if ($Company.Length -lt 1 -or $Company.Length -gt 200 -or $Company -match '[\x00-\x1f\x7f]') { throw 'Raison sociale invalide.' }

    $agree = [bool]$AcceptAcmeTerms
    if ($Mode -eq 'install' -and -not $agree) {
        Write-Host ''
        Write-Host "Le certificat public Lets Encrypt transmettra le domaine $Domain et le contact $Email a une autorite de certification."
        Write-Host 'Conditions et accord : https://letsencrypt.org/repository/'
        $answer = Read-Host 'Acceptez-vous ces conditions pour ce deploiement ? Tapez OUI'
        if ($answer -cne 'OUI') { throw 'Emission du certificat non acceptee. Aucun transfert ni deploiement lance.' }
        $agree = $true
    }
    $config = [ordered]@{domain=$Domain;email=$Email;company=$Company;expected_ipv4=$VpsIp;accept_acme_terms=$agree}
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ('syscohada-client-' + [Guid]::NewGuid().ToString('N'))
$stage = Join-Path $tmp 'kit'
$archive = Join-Path $tmp 'kit.tar.gz'
$remoteName = 'syscohada-autorun-1.0.0-' + [Guid]::NewGuid().ToString('N').Substring(0,12)
$target = $SshUser + '@' + $VpsIp
$sshOptions = @('-p',[string]$SshPort,'-o','StrictHostKeyChecking=ask')
$scpOptions = @('-P',[string]$SshPort,'-o','StrictHostKeyChecking=ask')
if ($IdentityFile) { $sshOptions += @('-i',$IdentityFile); $scpOptions += @('-i',$IdentityFile) }

try {
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    foreach ($item in @('install.sh','bin','lib','templates','payload','README-FR.md','config.example.json')) {
        $source = Join-Path $kit $item
        if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $stage -Recurse }
    }
    if ($null -ne $config) {
        $json = $config | ConvertTo-Json -Depth 4
        [IO.File]::WriteAllText((Join-Path $stage 'config.remote.json'),$json,(New-Object Text.UTF8Encoding($false)))
    }
    Invoke-Native 'tar.exe' @('-czf',$archive,'-C',$stage,'.')
    Write-Host ''
    Write-Host "Cible : $target, port $SshPort ; mode : $Mode."
    Write-Host 'OpenSSH vous demandera sa verification de cle et son authentification habituelles.'
    Write-Host 'Le lanceur ne recueille aucun mot de passe SSH.'
    $prepare = 'umask 077; mkdir -- "$HOME/' + $remoteName + '" && chmod 700 -- "$HOME/' + $remoteName + '"'
    Invoke-Native 'ssh.exe' ($sshOptions + @($target,$prepare))
    Invoke-Native 'scp.exe' ($scpOptions + @($archive,($target + ':~/' + $remoteName + '/kit.tar.gz')))
    $command = 'cd "$HOME/' + $remoteName + '" && tar -xzf kit.tar.gz && '
    if ($SshUser -cne 'root') { $command += 'sudo -- ' }
    $command += 'bash ./install.sh --' + $Mode
    if ($needsConfig) { $command += ' --config ./config.remote.json' }
    Invoke-Native 'ssh.exe' ($sshOptions + @('-t',$target,$command))
    Write-Host ''
    Write-Host "Kit transfere dans ~/$remoteName sur le VPS."
    Write-Host 'Si le processus est interrompu, utilisez le mode --resume du kit sur ce serveur.'
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Recurse -Force }
}
