function validacionIP {
    param([string]$ip)
    $regex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if ($ip -match $regex) { return $true } else { return $false }
}

function sacarMascara {
    param([string]$ip)
    $octComp = [int]($ip.Split('.')[0])
    if ($octComp -le 126 -and $octComp -ge 1) { $script:mask = "255.0.0.0"; return $true }
    elseif ($octComp -ge 128 -and $octComp -le 191) { $script:mask = "255.255.0.0"; return $true }
    elseif ($octComp -ge 192 -and $octComp -le 223) { $script:mask = "255.255.255.0"; return $true }
    else { return $false }
}

function validarMascara {
    if ($script:mask -eq "255.0.0.0" -and $script:claseIP -ne "a") { return $false }
    elseif ($script:mask -eq "255.255.0.0" -and $script:claseIP -ne "b") { return $false }
    elseif ($script:mask -eq "255.255.255.0" -and $script:claseIP -ne "c") { return $false }
    else { return $true }
}

function validarNoAptos {
    param([string]$ip)
    $octetos = $ip.Split('.')
    if ($octetos[0] -eq "127") { return $false }
    elseif ($script:claseIP -eq "a") {
        if (($octetos[1..3] -join '.') -eq "0.0.0" -or ($octetos[1..3] -join '.') -eq "255.255.255") { return $false }
        else { return $true }
    }
    elseif ($script:claseIP -eq "b") {
        if (($octetos[2..3] -join '.') -eq "0.0" -or ($octetos[2..3] -join '.') -eq "255.255") { return $false }
        else { return $true }
    }
    elseif ($script:claseIP -eq "c") {
        if ($octetos[3] -eq "0" -or $octetos[3] -eq "255") { return $false }
        else { return $true }
    }
}

function verificar_paquete {
    $dhcpService = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
    if ($dhcpService -and $dhcpService.Installed) {
        Write-Host "El paquete fue instalado previamente."
    }
    else {
        Write-Host "El paquete no ha sido instalado."
    }
}

function calcular_valor_ip {
    param([string]$ip, [string]$clase)
    $oct = $ip.Split('.')
    switch ($clase) {
        "a" { return [int]$oct[1] * 65536 + [int]$oct[2] * 256 + [int]$oct[3] }
        "b" { return [int]$oct[2] * 256 + [int]$oct[3] }
        "c" { return [int]$oct[3] }
    }
}

function aplicar_ip_servidor {
    param([string]$ip, [int]$prefixLength)
    Remove-NetIPAddress -InterfaceAlias "Ethernet" -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $ip -PrefixLength $prefixLength
    Write-Host "Direccion IP actualizada exitosamente."
    netsh advfirewall firewall add rule name="DHCP Server" dir=in action=allow protocol=UDP localport=67
}

function configurar_dns {
    param([string]$subnet, [string]$dns, [string]$dns2)
    try {
        if (-not [string]::IsNullOrWhiteSpace($dns2)) {
            Set-DhcpServerv4OptionValue -ScopeId $subnet -DnsServer $dns, $dns2 -ErrorAction Stop
        }
        else {
            Set-DhcpServerv4OptionValue -ScopeId $subnet -DnsServer $dns -ErrorAction Stop
        }
        Write-Host "DNS configurado correctamente."
    }
    catch {
        Write-Host "Windows no pudo validar el DNS. Intentando metodo alternativo..." -ForegroundColor Yellow
        try {
            $dnsArray = if (-not [string]::IsNullOrWhiteSpace($dns2)) { @($dns, $dns2) } else { @($dns) }
            Set-DhcpServerv4OptionValue -ScopeId $subnet -OptionId 6 -Value $dnsArray -Force -ErrorAction Stop
            Write-Host "DNS configurado exitosamente (metodo alternativo)." -ForegroundColor Green
        }
        catch {
            Write-Host "ADVERTENCIA: No se pudo configurar el DNS automaticamente." -ForegroundColor Red
            if (-not [string]::IsNullOrWhiteSpace($dns2)) {
                Write-Host "Set-DhcpServerv4OptionValue -ScopeId $subnet -OptionId 6 -Value $dns,$dns2 -Force" -ForegroundColor Cyan
            }
            else {
                Write-Host "Set-DhcpServerv4OptionValue -ScopeId $subnet -OptionId 6 -Value $dns -Force" -ForegroundColor Cyan
            }
            Write-Host "El scope fue creado correctamente pero SIN DNS." -ForegroundColor Yellow
        }
    }
}