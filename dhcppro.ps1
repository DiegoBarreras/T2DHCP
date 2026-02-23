param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$args
)

. "$PSScriptRoot\funciones.ps1"

$opcion = if ($args) { $args[0] } else { $null }

$script:mask = $null
$script:claseIP = $null

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
        verificar_paquete
        exit 0
    }

    "-instalar" {
        verificar_paquete
        $res = (Read-Host "Deseas instalar/reinstalar el paquete? s/n").ToLower()
        if ($res -eq "s") {
            Write-Host "Instalando el paquete dhcp-server.`n"
            Install-WindowsFeature -Name DHCP -IncludeManagementTools
            Add-DhcpServerSecurityGroup
            netsh dhcp add server $env:COMPUTERNAME 127.0.0.1
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
            if ([string]::IsNullOrWhiteSpace($nomScope)) { Write-Host "Inserta un nombre para el Scope."; continue }
            else { Write-Host "`n"; break }
        }

        while ($true) {
            $script:claseIP = (Read-Host "Inserta el tipo de clase para el rango de direcciones IP: (A, B, C)").ToLower()
            if ($script:claseIP -ne "a" -and $script:claseIP -ne "b" -and $script:claseIP -ne "c") { Write-Host "Inserta una clase valida."; continue }
            else { Write-Host "`n"; break }
        }

        while ($true) {
            $limInicial = Read-Host "Inserta el limite inicial del rango de direcciones IP"
            if (validacionIP $limInicial) {
                if (validarNoAptos $limInicial) {
                    if (sacarMascara $limInicial) {
                        if (validarMascara) {
                            $oct4Ini = [int]($limInicial.Split('.')[3])
                            Write-Host "`n"; break
                        }
                        else { Write-Host "Inserta una direccion IP que concuerde con la clase seleccionada."; continue }
                    }
                }
                else { Write-Host "Inserta una direccion IP valida." }
            }
            else { Write-Host "Inserta una direccion IP con formato valido."; continue }
        }

        while ($true) {
            $limFinal = Read-Host "Inserta el limite final del rango de direcciones IP"
            if (validacionIP $limFinal) {
                $salir = $false
                $octIni = $limInicial.Split('.')
                $octFin = $limFinal.Split('.')
                switch ($script:claseIP) {
                    "a" {
                        if ($octIni[0] -eq $octFin[0]) {
                            $valIniA = calcular_valor_ip $limInicial "a"
                            $valFinA = calcular_valor_ip $limFinal "a"
                            if ($valIniA -lt $valFinA) { $prefijo = $octIni[0]; $subnet = "$prefijo.0.0.0"; Write-Host "`n"; $salir = $true }
                            else { Write-Host "Inserta una direccion mayor a la especificada previamente." }
                        }
                        else { Write-Host "Inserta una direccion IP con un prefijo valido." }
                    }
                    "b" {
                        if (($octIni[0..1] -join '.') -eq ($octFin[0..1] -join '.')) {
                            $valIniB = calcular_valor_ip $limInicial "b"
                            $valFinB = calcular_valor_ip $limFinal "b"
                            if ($valIniB -lt $valFinB) { $prefijo = $octIni[0..1] -join '.'; $subnet = "$prefijo.0.0"; Write-Host "`n"; $salir = $true }
                            else { Write-Host "Inserta una direccion mayor a la especificada previamente." }
                        }
                        else { Write-Host "Inserta una direccion IP con un prefijo valido." }
                    }
                    "c" {
                        if (($octIni[0..2] -join '.') -eq ($octFin[0..2] -join '.')) {
                            if ($oct4Ini -lt [int]$octFin[3]) { $prefijo = $octIni[0..2] -join '.'; $subnet = "$prefijo.0"; Write-Host "`n"; $salir = $true }
                            else { Write-Host "Inserta una direccion mayor a la especificada previamente." }
                        }
                        else { Write-Host "Inserta una direccion IP con un prefijo valido." }
                    }
                }
                if ($salir) { break }
            }
            else { Write-Host "Inserta una direccion IP con formato valido" }
        }

        while ($true) {
            $segLease = Read-Host "Inserta el Lease Time (Segundos)"
            if ([string]::IsNullOrWhiteSpace($segLease)) { Write-Host "Inserta el Lease Time."; continue }
            elseif ($segLease -match '^\d+$') { Write-Host "`n"; break }
            else { Write-Host "Inserta un numero."; continue }
        }

        #$oct4Fin = [int]($limFinal.Split('.')[3])

        while ($true) {
            $resGw = (Read-Host "Deseas insertar una direccion IP especifica para el Gateway? s/n").ToLower()
            if ($resGw -eq "s") {
                $final = Read-Host "Inserta la direccion IP para el Gateway: $prefijo."
                $gateway = "$prefijo.$final"
                if (-not (validacionIP $gateway) -or -not (validarNoAptos $gateway)) { Write-Host "Inserta un Gateway valido."; continue }

                $valGw = calcular_valor_ip $gateway $script:claseIP
                $valIni = calcular_valor_ip $limInicial $script:claseIP
                $valFin = calcular_valor_ip $limFinal $script:claseIP

                if ($valGw -lt $valIni -or $valGw -gt $valFin) { Write-Host "`n"; break }
                else { Write-Host "Inserta una direccion fuera del rango previamente establecido." }
            }
            elseif ($resGw -eq "n") { Write-Host "`n"; break }
            else { Write-Host "Inserta una opcion valida."; continue }
        }

        while ($true) {
            $resDns = (Read-Host "Deseas insertar una direccion IP especifica para el DNS Server? s/n").ToLower()
            if ($resDns -eq "s") {
                $dns = Read-Host "Inserta la direccion IP para el DNS Server"
                if (-not (validacionIP $dns) -or -not (validarNoAptos $dns) -or $dns -eq $gateway) { Write-Host "Inserta una direccion valida."; continue }
                else {
                    while ($true) {
                        $resDns2 = (Read-Host "Deseas insertar una direccion IP secundaria para el DNS Server? s/n").ToLower()
                        if ($resDns2 -eq "s") {
                            $dns2 = Read-Host "Inserta la direccion IP para el DNS Server"
                            if (-not (validacionIP $dns2) -or -not (validarNoAptos $dns2) -or $dns2 -eq $gateway) { Write-Host "Inserta una direccion valida."; continue }
                            else { Write-Host "`n"; break }
                        }
                        elseif ($resDns2 -eq "n") { Write-Host "`n"; break }
                        else { Write-Host "Inserta una opcion valida."; continue }
                    }
                    break
                }
            }
            elseif ($resDns -eq "n") { Write-Host "`n"; break }
            else { Write-Host "Inserta una opcion valida."; continue }
        }

        Write-Host "Creando scope DHCP..."
        try {
            $existingScope = Get-DhcpServerv4Scope | Where-Object { $_.Name -eq $nomScope }
            if ($existingScope) { Remove-DhcpServerv4Scope -ScopeId $existingScope.ScopeId -Force }
            Add-DhcpServerv4Scope -Name $nomScope -StartRange $limInicial -EndRange $limFinal -SubnetMask $script:mask -LeaseDuration ([TimeSpan]::FromSeconds($segLease)) -State Active
            Write-Host "Scope creado correctamente."
        }
        catch {
            Write-Host "Error al crear el scope: $_" -ForegroundColor Red
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
                    Write-Host "Error: No se pudo configurar el Gateway." -ForegroundColor Red
                }
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($dns)) {
            configurar_dns $subnet $dns $dns2
        }

        Write-Host "El archivo fue guardado correctamente.`n"
        Restart-Service DHCPServer

        while ($true) {
            $finNuevaIp = Read-Host "Inserta una nueva IP para el servidor: $prefijo."
            $nuevaIp = "$prefijo.$finNuevaIp"
            if (-not (validacionIP $nuevaIp) -or -not (validarNoAptos $nuevaIp)) { Write-Host "Inserta una direccion IP valida."; continue }
            else {
                $valNuevaIp = calcular_valor_ip $nuevaIp $script:claseIP
                $valIni = calcular_valor_ip $limInicial $script:claseIP
                $valFin = calcular_valor_ip $limFinal $script:claseIP
                $cidr = switch ($script:claseIP) { "a" { 8 } "b" { 16 } "c" { 24 } }

                if ($valNuevaIp -le $valIni -or $valNuevaIp -ge $valFin) {
                    Write-Host "La IP insertada es valida."
                    aplicar_ip_servidor $nuevaIp $cidr
                    break
                }
                else { Write-Host "Inserta una direccion fuera del rango." }
            }
        }
    }

    "-restartserv" {
        Write-Host "Validando configuracion antes de reiniciar...`n"
        try {
            $scopes = Get-DhcpServerv4Scope -ErrorAction Stop
            Write-Host "Sintaxis OK. Reiniciando servicio..."
            Restart-Service DHCPServer -ErrorAction Stop
            if ($?) { Write-Host "Servicio iniciado correctamente."; exit 0 }
            else {
                Write-Host "Error critico: El servicio no pudo iniciar."
                Get-EventLog -LogName System -Source "Microsoft-Windows-Dhcp-Server" -Newest 10
                exit 1
            }
        }
        catch { Write-Host "Error de sintaxis detectado!"; Write-Host $_.Exception.Message; exit 1 }
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
                    $gw = $opciones | Where-Object { $_.OptionId -eq 3 }
                    if ($gw) { Write-Host "  Gateway (Router): $($gw.Value -join ', ')" -ForegroundColor White }
                    else { Write-Host "  Gateway (Router): No configurado" -ForegroundColor Gray }
                    $dnsOpt = $opciones | Where-Object { $_.OptionId -eq 6 }
                    if ($dnsOpt) { Write-Host "  DNS Servers: $($dnsOpt.Value -join ', ')" -ForegroundColor White }
                    else { Write-Host "  DNS Servers: No configurado" -ForegroundColor Gray }
                    Write-Host ""
                    $opciones | Format-Table OptionId, Name, Value -AutoSize
                }
                else { Write-Host "  No hay opciones configuradas para este scope." -ForegroundColor Gray }
                Write-Host ""
            }
        }
        else { Write-Host "No hay scopes configurados." }
    }

    "-monitor" {
        Write-Host "`nEstado del servicio:"
        $servicio = Get-Service DHCPServer -ErrorAction SilentlyContinue
        if ($servicio -and $servicio.Status -eq "Running") { Write-Host "El servicio esta activo.`n" }
        else { Write-Host "El servicio esta apagado o no existe." }

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
            if (-not $hayConcesiones) { Write-Host "No hay concesiones activas actualmente." }
        }
        else { Write-Host "Error: No hay scopes configurados. Por favor crea un scope primero." }

        Write-Host "`nValidacion de sintaxis de dhcpd.conf:"
        try {
            $scopesValidacion = Get-DhcpServerv4Scope -ErrorAction Stop
            if ($scopesValidacion) { Write-Host "La sintaxis de dhcpd.conf es CORRECTA" }
            else { Write-Host "La sintaxis de dhcpd.conf es ERRONEA" }
        }
        catch { Write-Host "La sintaxis de dhcpd.conf es ERRONEA" }
    }
}