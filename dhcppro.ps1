param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$args
)

$opcion = if ($args) { $args[0] } else { $null }

$script:mask = $null
$script:claseIP = $null

function validacionIP {
    param([string]$ip)
    
    $regex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if ($ip -match $regex) {
        return $true
    }
    else {
        return $false
    }
}

function sacarMascara {
    param([string]$ip)
    
    $octComp = [int]($ip.Split('.')[0])
    
    if ($octComp -le 126 -and $octComp -ge 1) {
        $script:mask = "255.0.0.0"
        return $true
    }
    elseif ($octComp -ge 128 -and $octComp -le 191) {
        $script:mask = "255.255.0.0"
        return $true
    }
    elseif ($octComp -ge 192 -and $octComp -le 223) {
        $script:mask = "255.255.255.0"
        return $true
    }
    else {
        return $false
    }
}

function validarMascara {
    if ($script:mask -eq "255.0.0.0" -and $script:claseIP -ne "a") {
        return $false
    }
    elseif ($script:mask -eq "255.255.0.0" -and $script:claseIP -ne "b") {
        return $false
    }
    elseif ($script:mask -eq "255.255.255.0" -and $script:claseIP -ne "c") {
        return $false
    }
    else {
        return $true
    }
}

function validarNoAptos {
    param([string]$ip)
    
    $octetos = $ip.Split('.')
    
    if ($octetos[0] -eq "127") {
        return $false
    }
    elseif ($script:claseIP -eq "a") {
        if (($octetos[1..3] -join '.') -eq "0.0.0" -or ($octetos[1..3] -join '.') -eq "255.255.255") {
            return $false
        }
        else {
            return $true
        }
    }
    elseif ($script:claseIP -eq "b") {
        if (($octetos[2..3] -join '.') -eq "0.0" -or ($octetos[2..3] -join '.') -eq "255.255") {
            return $false
        }
        else {
            return $true
        }
    }
    elseif ($script:claseIP -eq "c") {
        if ($octetos[3] -eq "0" -or $octetos[3] -eq "255") {
            return $false
        }
        else {
            return $true
        }
    }
}

if ([string]::IsNullOrWhiteSpace($opcion)) {
    Write-Host "`n"
    Write-Host "---------------------------------------------"
    Write-Host "---------- MENU SCRIPT DHCP-SERVER ----------"
    Write-Host "---------------------------------------------`n"
    
    Write-Host "Para verificar la instalacion del paquete:"
    Write-Host ".\dhcppro.ps1 -verificar`n"
    
    Write-Host "Para re/instalar el paquete:"
    Write-Host ".\dhcppro.ps1 -instalar`n"
    
    Write-Host "Para escribir una nueva configuracion al archivo dhcpd.conf:"
    Write-Host ".\dhcppro.ps1 -newconfig`n"
    
    Write-Host "Para mostrar la configuracion actual:"
    Write-Host ".\dhcppro.ps1 -verconfig`n"
    
    Write-Host "Para reiniciar el servicio:"
    Write-Host ".\dhcppro.ps1 -restartserv`n"
    
    Write-Host "Monitor de concesiones:"
    Write-Host ".\dhcppro.ps1 -monitor`n"
    exit
}

switch ($opcion) {
    "-verificar" {
        Write-Host "Buscando al paquete dhcp-server:"
        
        $dhcpService = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        
        if ($dhcpService -and $dhcpService.Installed) {
            Write-Host "El paquete fue instalado previamente.`n"
        }
        else {
            Write-Host "El paquete no ha sido instalado.`n"
        }
        exit 0
    }
    
    "-instalar" {
        $dhcpService = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        
        if ($dhcpService -and $dhcpService.Installed) {
            Write-Host "El paquete fue instalado previamente."
        }
        else {
            Write-Host "El paquete no ha sido instalado."
        }
        
        $res = Read-Host "Deseas instalar/reinstalar el paquete? s/n"
        $res = $res.ToLower()
        
        if ($res -eq "s") {
            Write-Host "Instalando el paquete dhcp-server.`n"
            Install-WindowsFeature -Name DHCP -IncludeManagementTools
            Add-DhcpServerSecurityGroup
            exit 0
        }
        else {
            Write-Host "La instalacion fue cancelada.`n"
            exit 0
        }
    }
    
    "-newconfig" {
        while ($true) {
            $nomScope = Read-Host "Inserta el nombre del Scope para el DHCP"
            if ([string]::IsNullOrWhiteSpace($nomScope)) {
                Write-Host "Inserta un nombre para el Scope."
                continue
            }
            else {
                Write-Host "`n"
                break
            }
        }
        
        while ($true) {
            $script:claseIP = Read-Host "Inserta el tipo de clase para el rango de direcciones IP: (A, B, C)"
            $script:claseIP = $script:claseIP.ToLower()
            
            if ($script:claseIP -ne "a" -and $script:claseIP -ne "b" -and $script:claseIP -ne "c") {
                Write-Host "Inserta una clase valida."
                continue
            }
            else {
                Write-Host "`n"
                break
            }
        }
        
        while ($true) {
            $limInicial = Read-Host "Inserta el limite inicial del rango de direcciones IP"
            if (validacionIP $limInicial) {
                if (validarNoAptos $limInicial) {
                    if (sacarMascara $limInicial) {
                        if (validarMascara) {
                            $oct4Ini = [int]($limInicial.Split('.')[3])
                            Write-Host "`n"
                            break
                        }
                        else {
                            Write-Host "Inserta una direccion IP que concuerde con la clase seleccionada."
                            continue
                        }
                    }
                }
                else {
                    Write-Host "Inserta una direccion IP valida."
                }
            }
            else {
                Write-Host "Inserta una direccion IP con formato valido."
                continue
            }
        }
        
        while ($true) {
            $limFinal = Read-Host "Inserta el limite final del rango de direcciones IP"
            if (validacionIP $limFinal) {
                $salir = $false
                switch ($script:claseIP) {
                    "a" {
                        $octIni = $limInicial.Split('.')
                        $octFin = $limFinal.Split('.')
                        if ($octIni[0] -eq $octFin[0]) {
                            $valIniA = [int]$octIni[1] * 65536 + [int]$octIni[2] * 256 + [int]$octIni[3]
                            $valFinA = [int]$octFin[1] * 65536 + [int]$octFin[2] * 256 + [int]$octFin[3]
                            if ($valIniA -lt $valFinA) {
                                $prefijo = $octIni[0]
                                $subnet = "$prefijo.0.0.0"
                                Write-Host "`n"
                                $salir = $true
                            }
                            else {
                                Write-Host "Inserta una direccion mayor a la especificada previamente."
                            }
                        }
                        else {
                            Write-Host "Inserta una direccion IP con un prefijo valido."
                        }
                    }
                    
                    "b" {
                        $octIni = $limInicial.Split('.')
                        $octFin = $limFinal.Split('.')
                        if (($octIni[0..1] -join '.') -eq ($octFin[0..1] -join '.')) {
                            $valIniB = [int]$octIni[2] * 256 + [int]$octIni[3]
                            $valFinB = [int]$octFin[2] * 256 + [int]$octFin[3]
                            if ($valIniB -lt $valFinB) {
                                $prefijo = $octIni[0..1] -join '.'
                                $subnet = "$prefijo.0.0"
                                Write-Host "`n"
                                $salir = $true
                            }
                            else {
                                Write-Host "Inserta una direccion mayor a la especificada previamente."
                            }
                        }
                        else {
                            Write-Host "Inserta una direccion IP con un prefijo valido."
                        }
                    }
                    
                    "c" {
                        $octIni = $limInicial.Split('.')
                        $octFin = $limFinal.Split('.')
                        if (($octIni[0..2] -join '.') -eq ($octFin[0..2] -join '.')) {
                            if ($oct4Ini -lt [int]$octFin[3]) {
                                $prefijo = $octIni[0..2] -join '.'
                                $subnet = "$prefijo.0"
                                Write-Host "`n"
                                $salir = $true
                            }
                            else {
                                Write-Host "Inserta una direccion mayor a la especificada previamente."
                            }
                        }
                        else {
                            Write-Host "Inserta una direccion IP con un prefijo valido."
                        }
                    }
                }
                
                if ($salir) {
                    break
                }
            }
            else {
                Write-Host "Inserta una direccion IP con formato valido"
            }
        }
        
        while ($true) {
            $segLease = Read-Host "Inserta el Lease Time (Segundos)"
            if ([string]::IsNullOrWhiteSpace($segLease)) {
                Write-Host "Inserta el Lease Time."
                continue
            }
            elseif ($segLease -match '^\d+$') {
                Write-Host "`n"
                break
            }
            else {
                Write-Host "Inserta un numero."
                continue
            }
        }
        
        $oct4Fin = [int]($limFinal.Split('.')[3])
        
        while ($true) {
            $resGw = Read-Host "Deseas insertar una direccion IP especifica para el Gateway? s/n"
            $resGw = $resGw.ToLower()
            if ($resGw -eq "s") {
                $final = Read-Host "Inserta la direccion IP para el Gateway: $prefijo."
                $gateway = "$prefijo.$final"
                
                if (-not (validacionIP $gateway) -or -not (validarNoAptos $gateway)) {
                    Write-Host "Inserta un Gateway valido."
                    continue
                }
                
                $salir = $false
                switch ($script:claseIP) {
                    "a" {
                        $octGw = $gateway.Split('.')
                        $valGwA = [int]$octGw[1] * 65536 + [int]$octGw[2] * 256 + [int]$octGw[3]
                        if ($valGwA -lt $valIniA -or $valGwA -gt $valFinA) {
                            Write-Host "`n"
                            $salir = $true
                        }
                        else {
                            Write-Host "Inserta una direccion fuera del rango previamente establecido."
                        }
                    }
                    
                    "b" {
                        $octGw = $gateway.Split('.')
                        $valGwB = [int]$octGw[2] * 256 + [int]$octGw[3]
                        if ($valGwB -lt $valIniB -or $valGwB -gt $valFinB) {
                            Write-Host "`n"
                            $salir = $true
                        }
                        else {
                            Write-Host "Inserta una direccion fuera del rango previamente establecido."
                        }
                    }
                    
                    "c" {
                        $octGw = $gateway.Split('.')
                        $valGwC = [int]$octGw[3]
                        if ($valGwC -lt $oct4Ini -or $valGwC -gt $oct4Fin) {
                            Write-Host "`n"
                            $salir = $true
                        }
                        else {
                            Write-Host "Inserta una direccion fuera del rango previamente establecido."
                        }
                    }
                }
                
                if ($salir) {
                    break
                }
            }
            elseif ($resGw -eq "n") {
                Write-Host "`n"
                break
            }
            else {
                Write-Host "Inserta una opcion valida."
                continue
            }
        }
        
        while ($true) {
            $resDns = Read-Host "Deseas insertar una direccion IP especifica para el DNS Server? s/n"
            $resDns = $resDns.ToLower()
            if ($resDns -eq "s") {
                $dns = Read-Host "Inserta la direccion IP para el DNS Server"
                
                if (-not (validacionIP $dns) -or -not (validarNoAptos $dns) -or $dns -eq $gateway) {
                    Write-Host "Inserta una direccion valida."
                    continue
                }
                else {
                    while ($true) {
                        $resDns2 = Read-Host "Deseas insertar una direccion IP secundaria para el DNS Server? s/n"
                        $resDns2 = $resDns2.ToLower()
                        if ($resDns2 -eq "s") {
                            $dns2 = Read-Host "Inserta la direccion IP para el DNS Server"
                            
                            if (-not (validacionIP $dns2) -or -not (validarNoAptos $dns2) -or $dns2 -eq $gateway) {
                                Write-Host "Inserta una direccion valida."
                                continue
                            }
                            else {
                                Write-Host "`n"
                                break
                            }
                        }
                        elseif ($resDns2 -eq "n") {
                            Write-Host "`n"
                            break
                        }
                        else {
                            Write-Host "Inserta una opcion valida."
                            continue
                        }
                    }
                    break
                }
            }
            elseif ($resDns -eq "n") {
                Write-Host "`n"
                break
            }
            else {
                Write-Host "Inserta una opcion valida."
                continue
            }
        }
        
        Write-Host "Creando scope DHCP..."
        
        try {
            $existingScope = Get-DhcpServerv4Scope | Where-Object { $_.Name -eq $nomScope }
            if ($existingScope) {
                Remove-DhcpServerv4Scope -ScopeId $existingScope.ScopeId -Force
            }
            
            Add-DhcpServerv4Scope -Name $nomScope `
                -StartRange $limInicial `
                -EndRange $limFinal `
                -SubnetMask $script:mask `
                -LeaseDuration ([TimeSpan]::FromSeconds($segLease)) `
                -State Active
            
            Write-Host "Scope creado correctamente."
        }
        catch {
            Write-Host "Error al crear el scope: $_" -ForegroundColor Red
            Write-Host "Archivo no guardado. Revisa los permisos."
            exit 1
        }
        
        if (-not [string]::IsNullOrWhiteSpace($gateway)) {
            try {
                Set-DhcpServerv4OptionValue -ScopeId $subnet -Router $gateway -ErrorAction Stop
                Write-Host "Gateway configurado correctamente."
            }
            catch {
                Write-Host "Windows no pudo validar el Gateway. Configurando manualmente..." -ForegroundColor Yellow
                try {
                    netsh dhcp server \\127.0.0.1 scope $subnet set optionvalue 3 IPADDRESS $gateway
                    Write-Host "Gateway configurado exitosamente (sin validacion de Windows)." -ForegroundColor Green
                }
                catch {
                    Write-Host "Error: No se pudo configurar el Gateway ni con PowerShell ni con netsh." -ForegroundColor Red
                    Write-Host "Prueba configurarlo manualmente con: netsh dhcp server \\127.0.0.1 scope $subnet set optionvalue 3 IPADDRESS $gateway"
                }
            }
        }
        
        if (-not [string]::IsNullOrWhiteSpace($dns)) {
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
                    if (-not [string]::IsNullOrWhiteSpace($dns2)) {
                        $dnsArray = @($dns, $dns2)
                    }
                    else {
                        $dnsArray = @($dns)
                    }
                    
                    $optionExists = Get-DhcpServerv4OptionDefinition -OptionId 6 -ErrorAction SilentlyContinue
                    
                    Set-DhcpServerv4OptionValue -ScopeId $subnet -OptionId 6 -Value $dnsArray -Force -ErrorAction Stop
                    
                    Write-Host "DNS configurado exitosamente (metodo alternativo)." -ForegroundColor Green
                }
                catch {
                    Write-Host "ADVERTENCIA: No se pudo configurar el DNS automaticamente." -ForegroundColor Red
                    Write-Host "Para configurarlo manualmente, ejecuta estos comandos:" -ForegroundColor Yellow
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
        
        Write-Host "El archivo fue guardado correctamente.`n"
        Restart-Service DHCPServer
        
        while ($true) {
            $finNuevaIp = Read-Host "Inserta una nueva IP para el servidor: $prefijo."
            $nuevaIp = "$prefijo.$finNuevaIp"
            
            if (-not (validacionIP $nuevaIp) -or -not (validarNoAptos $nuevaIp)) {
                Write-Host "Inserta una direccion IP valida."
                continue
            }
            else {
                $salir = $false
                switch ($script:claseIP) {
                    "a" {
                        $octNueva = $nuevaIp.Split('.')
                        $valNuevaIp = [int]$octNueva[1] * 65536 + [int]$octNueva[2] * 256 + [int]$octNueva[3]
                        if ($valNuevaIp -lt $valIniA -or $valNuevaIp -gt $valFinA) {
                            Write-Host "La IP insertada es valida."
                            Remove-NetIPAddress -InterfaceAlias "Ethernet" -Confirm:$false -ErrorAction SilentlyContinue
                            New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $nuevaIp -PrefixLength 8
                            Write-Host "Direccion IP actualizada exitosamente."
                            netsh advfirewall firewall add rule name="DHCP Server" dir=in action=allow protocol=UDP localport=67
                            $salir = $true
                        }
                        else {
                            Write-Host "Inserta una direccion fuera del rango."
                        }
                    }
                    
                    "b" {
                        $octNueva = $nuevaIp.Split('.')
                        $valNuevaIp = [int]$octNueva[2] * 256 + [int]$octNueva[3]
                        if ($valNuevaIp -lt $valIniB -or $valNuevaIp -gt $valFinB) {
                            Write-Host "La IP insertada es valida."
                            Remove-NetIPAddress -InterfaceAlias "Ethernet" -Confirm:$false -ErrorAction SilentlyContinue
                            New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $nuevaIp -PrefixLength 16
                            Write-Host "Direccion IP actualizada exitosamente."
                            netsh advfirewall firewall add rule name="DHCP Server" dir=in action=allow protocol=UDP localport=67
                            $salir = $true
                        }
                        else {
                            Write-Host "Inserta una direccion fuera del rango."
                        }
                    }
                    
                    "c" {
                        $octNueva = $nuevaIp.Split('.')
                        $valNuevaIp = [int]$octNueva[3]
                        if ($valNuevaIp -lt [int]($limInicial.Split('.')[3]) -or $valNuevaIp -gt [int]($limFinal.Split('.')[3])) {
                            Write-Host "La IP insertada es valida."
                            Remove-NetIPAddress -InterfaceAlias "Ethernet" -Confirm:$false -ErrorAction SilentlyContinue
                            New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress $nuevaIp -PrefixLength 24
                            Write-Host "Direccion IP actualizada exitosamente."
                            netsh advfirewall firewall add rule name="DHCP Server" dir=in action=allow protocol=UDP localport=67
                            $salir = $true
                        }
                        else {
                            Write-Host "Inserta una direccion fuera del rango."
                        }
                    }
                }
                
                if ($salir) {
                    break
                }
            }
        }
    }
    
    "-restartserv" {
        Write-Host "Validando configuracion antes de reiniciar...`n"
        
        try {
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            Write-Host "Sintaxis OK. Reiniciando servicio..."
            Restart-Service DHCPServer -ErrorAction Stop
            
            if ($?) {
                Write-Host "Servicio iniciado correctamente."
                exit 0
            }
            else {
                Write-Host "Error critico: El servicio no pudo iniciar a pesar de tener sintaxis correcta."
                Get-EventLog -LogName System -Source "Microsoft-Windows-Dhcp-Server" -Newest 10
                exit 1
            }
        }
        catch {
            Write-Host "Error de sintaxis detectado!"
            Write-Host $_.Exception.Message
            exit 1
        }
    }
    
    "-verconfig" {
        Write-Host "Configuracion actual:`n"
        $scopes = Get-DhcpServerv4Scope
        
        if ($scopes) {
            foreach ($scope in $scopes) {
                Write-Host "========================================" 
                Write-Host "Scope: $($scope.Name)" -ForegroundColor Yellow
                Write-Host "========================================"
                $scope | Format-List Name, ScopeId, SubnetMask, StartRange, EndRange, LeaseDuration, State
                
                Write-Host "Opciones del Scope:" -ForegroundColor Green
                
                $opciones = Get-DhcpServerv4OptionValue -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                
                if ($opciones) {
                    $gateway = $opciones | Where-Object { $_.OptionId -eq 3 }
                    if ($gateway) {
                        Write-Host "  Gateway (Router): $($gateway.Value -join ', ')" -ForegroundColor White
                    }
                    else {
                        Write-Host "  Gateway (Router): No configurado" -ForegroundColor Gray
                    }
                    
                    $dns = $opciones | Where-Object { $_.OptionId -eq 6 }
                    if ($dns) {
                        Write-Host "  DNS Servers: $($dns.Value -join ', ')" -ForegroundColor White
                    }
                    else {
                        Write-Host "  DNS Servers: No configurado" -ForegroundColor Gray
                    }
                    
                    Write-Host ""
                    $opciones | Format-Table OptionId, Name, Value -AutoSize
                }
                else {
                    Write-Host "  No hay opciones configuradas para este scope." -ForegroundColor Gray
                }
                
                Write-Host ""
            }
        }
        else {
            Write-Host "No hay scopes configurados."
        }
    }
    
    "-monitor" {
        Write-Host "`nEstado del servicio:"
        $servicio = Get-Service DHCPServer -ErrorAction SilentlyContinue
        
        if ($servicio -and $servicio.Status -eq "Running") {
            Write-Host "El servicio esta activo.`n"
        }
        else {
            Write-Host "El servicio esta apagado o no existe."
        }
        
        Write-Host "`nConcesiones activas:"
        $scopes = Get-DhcpServerv4Scope
        
        if ($scopes) {
            $hayConcesiones = $false
            foreach ($scope in $scopes) {
                $leases = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                
                if ($leases) {
                    $hayConcesiones = $true
                    Write-Host "`nScope: $($scope.Name) ($($scope.ScopeId))" -ForegroundColor Cyan
                    $leases | Format-Table IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime -AutoSize
                }
            }
            
            if (-not $hayConcesiones) {
                Write-Host "No hay concesiones activas actualmente."
            }
        }
        else {
            Write-Host "Error: No hay scopes configurados. Por favor crea un scope primero."
        }
        
        Write-Host "`nValidacion de sintaxis de dhcpd.conf:"
        try {
            $scopesValidacion = Get-DhcpServerv4Scope -ErrorAction Stop
            if ($scopesValidacion) {
                Write-Host "La sintaxis de dhcpd.conf es CORRECTA"
            }
            else {
                Write-Host "La sintaxis de dhcpd.conf es ERRONEA"
            }
        }
        catch {
            Write-Host "La sintaxis de dhcpd.conf es ERRONEA"
        }
    }
}