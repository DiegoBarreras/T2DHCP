param(
    [Parameter(Position=0, ValueFromRemainingArguments=$true)]
    [string]$opcion
)

function validacionIP {
    param([string]$ip)
    
    $regex = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return $ip -match $regex
}

function sacarMascara {
    param([string]$ip)
    
    $octComp = [int]($ip.Split('.')[0])
    
    if ($octComp -ge 1 -and $octComp -le 126) {
        return "255.0.0.0"
    }
    elseif ($octComp -ge 128 -and $octComp -le 191) {
        return "255.255.0.0"
    }
    elseif ($octComp -ge 192 -and $octComp -le 223) {
        return "255.255.255.0"
    }
    else {
        return $null
    }
}

function validarMascara {
    param(
        [string]$mask,
        [string]$claseIP
    )
    
    if ($mask -eq "255.0.0.0" -and $claseIP -ne "a") {
        return $false
    }
    elseif ($mask -eq "255.255.0.0" -and $claseIP -ne "b") {
        return $false
    }
    elseif ($mask -eq "255.255.255.0" -and $claseIP -ne "c") {
        return $false
    }
    else {
        return $true
    }
}

function validarNoAptos {
    param(
        [string]$ip,
        [string]$claseIP
    )
    
    $octetos = $ip.Split('.')
    
    if ($octetos[0] -eq "127") {
        return $false
    }
    
    switch ($claseIP) {
        "a" {
            if (($octetos[1..3] -join '.') -eq "0.0.0" -or ($octetos[1..3] -join '.') -eq "255.255.255") {
                return $false
            }
        }
        "b" {
            if (($octetos[2..3] -join '.') -eq "0.0" -or ($octetos[2..3] -join '.') -eq "255.255") {
                return $false
            }
        }
        "c" {
            if ($octetos[3] -eq "0" -or $octetos[3] -eq "255") {
                return $false
            }
        }
    }
    
    return $true
}

function Mostrar-Menu {
    Write-Host "`n"
    Write-Host "---------------------------------------------"
    Write-Host "---------- MENU SCRIPT DHCP-SERVER ----------"
    Write-Host "---------------------------------------------`n"
    
    Write-Host "Para verificar la instalacion del servicio DHCP:"
    Write-Host ".\dhcppro.ps1 -verificar`n"
    
    Write-Host "Para instalar el servicio DHCP:"
    Write-Host ".\dhcppro.ps1 -instalar`n"
    
    Write-Host "Para crear una nueva configuracion de scope:"
    Write-Host ".\dhcppro.ps1 -newconfig`n"
    
    Write-Host "Para mostrar la configuracion actual:"
    Write-Host ".\dhcppro.ps1 -verconfig`n"
    
    Write-Host "Para reiniciar el servicio:"
    Write-Host ".\dhcppro.ps1 -restartserv`n"
    
    Write-Host "Monitor de concesiones:"
    Write-Host ".\dhcppro.ps1 -monitor`n"
}

function verificacionAdmin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ([string]::IsNullOrWhiteSpace($opcion)) {
    Mostrar-Menu
    exit
}

switch ($opcion) {
    "-verificar" {
        Write-Host "Buscando el servicio DHCP Server:"
        
        $dhcpService = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        
        if ($dhcpService -and $dhcpService.Installed) {
            Write-Host "El servicio DHCP esta instalado.`n"
        }
        else {
            Write-Host "El servicio DHCP no esta instalado.`n"
        }
    }
    
    "-instalar" {
        if (-not (verificacionAdmin)) {
            Write-Host "ERROR: Este script requiere permisos de administrador." -ForegroundColor Red
            exit 1
        }
        
        $dhcpService = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        
        if ($dhcpService -and $dhcpService.Installed) {
            Write-Host "El servicio DHCP ya esta instalado."
        }
        else {
            Write-Host "El servicio DHCP no esta instalado."
        }
        
        $res = Read-Host "Deseas instalar/reinstalar el servicio DHCP? (s/n)"
        $res = $res.ToLower()
        
        if ($res -eq "s") {
            Write-Host "Instalando el servicio DHCP Server...`n"
            
            try {
                Install-WindowsFeature -Name DHCP -IncludeManagementTools

                Add-DhcpServerSecurityGroup
                Restart-Service DHCPServer -Force
                
                Write-Host "`nServicio DHCP instalado correctamente."
            }
            catch {
                Write-Host "Error al instalar el servicio: $_" -ForegroundColor Red
            }
        }
        else {
            Write-Host "La instalacion fue cancelada.`n"
        }
    }
    
    "-newconfig" {
        if (-not (verificacionAdmin)) {
            Write-Host "ERROR: Este script requiere permisos de administrador." -ForegroundColor Red
            exit 1
        }
        
        $dhcpService = Get-WindowsFeature -Name DHCP -ErrorAction SilentlyContinue
        if (-not ($dhcpService -and $dhcpService.Installed)) {
            Write-Host "ERROR: El servicio DHCP no esta instalado. Ejecuta primero -instalar" -ForegroundColor Red
            exit 1
        }
        
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
            $claseIP = Read-Host "Inserta el tipo de clase para el rango de direcciones IP (A, B, C)"
            $claseIP = $claseIP.ToLower()
            
            if ($claseIP -ne "a" -and $claseIP -ne "b" -and $claseIP -ne "c") {
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
            
            if (-not (validacionIP $limInicial)) {
                Write-Host "Inserta una direccion IP con formato valido."
                continue
            }
            
            if (-not (validarNoAptos $limInicial $claseIP)) {
                Write-Host "Inserta una direccion IP valida."
                continue
            }
            
            $mask = sacarMascara $limInicial
            if (-not $mask) {
                Write-Host "Error al obtener la mascara."
                continue
            }
            
            if (-not (validarMascara $mask $claseIP)) {
                Write-Host "Inserta una direccion IP que concuerde con la clase seleccionada."
                continue
            }
            
            $oct4Ini = [int]($limInicial.Split('.')[3])
            Write-Host "`n"
            break
        }
        
        while ($true) {
            $limFinal = Read-Host "Inserta el limite final del rango de direcciones IP"
            
            if (-not (validacionIP $limFinal)) {
                Write-Host "Inserta una direccion IP con formato valido."
                continue
            }
            
            $octIni = $limInicial.Split('.')
            $octFin = $limFinal.Split('.')
            $valido = $false
            
            switch ($claseIP) {
                "a" {
                    if ($octIni[0] -eq $octFin[0]) {
                        $valIniA = [int]$octIni[1] * 65536 + [int]$octIni[2] * 256 + [int]$octIni[3]
                        $valFinA = [int]$octFin[1] * 65536 + [int]$octFin[2] * 256 + [int]$octFin[3]
                        
                        if ($valIniA -lt $valFinA) {
                            $prefijo = $octIni[0]
                            $subnet = "$prefijo.0.0.0"
                            $valido = $true
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
                    if ($octIni[0..1] -join '.' -eq $octFin[0..1] -join '.') {
                        $valIniB = [int]$octIni[2] * 256 + [int]$octIni[3]
                        $valFinB = [int]$octFin[2] * 256 + [int]$octFin[3]
                        
                        if ($valIniB -lt $valFinB) {
                            $prefijo = $octIni[0..1] -join '.'
                            $subnet = "$prefijo.0.0"
                            $valido = $true
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
                    if ($octIni[0..2] -join '.' -eq $octFin[0..2] -join '.') {
                        if ($oct4Ini -lt [int]$octFin[3]) {
                            $prefijo = $octIni[0..2] -join '.'
                            $subnet = "$prefijo.0"
                            $valido = $true
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
            
            if ($valido) { 
                Write-Host "`n"
                break 
            }
        }
        
        while ($true) {
            $segLease = Read-Host "Inserta el Lease Time (Segundos)"
            
            if ([string]::IsNullOrWhiteSpace($segLease)) {
                Write-Host "Inserta el Lease Time."
                continue
            }
            
            if ($segLease -match '^\d+$') {
                Write-Host "`n"
                break
            }
            else {
                Write-Host "Inserta un numero."
            }
        }
        
        $oct4Fin = [int]($limFinal.Split('.')[3])

        $gateway = $null
        while ($true) {
            $resGw = Read-Host "Deseas insertar una direccion IP especifica para el Gateway? s/n"
            $resGw = $resGw.ToLower()
            
            if ($resGw -eq "s") {
                $final = Read-Host "Inserta la direccion IP para el Gateway: $prefijo."
                $gateway = "$prefijo.$final"
                Write-Host "$gateway"

                if (-not (validacionIP $gateway) -or -not (validarNoAptos $gateway $claseIP)) {
                    Write-Host "Inserta un Gateway valido."
                    continue
                }
                
                $octGw = $gateway.Split('.')
                $fueraDeRango = $false
                
                switch ($claseIP) {
                    "a" {
                        $valGwA = [int]$octGw[1] * 65536 + [int]$octGw[2] * 256 + [int]$octGw[3]
                        if ($valGwA -lt $valIniA -or $valGwA -gt $valFinA) {
                            $fueraDeRango = $true
                        }
                    }
                    "b" {
                        $valGwB = [int]$octGw[2] * 256 + [int]$octGw[3]
                        if ($valGwB -lt $valIniB -or $valGwB -gt $valFinB) {
                            $fueraDeRango = $true
                        }
                    }
                    "c" {
                        $valGwC = [int]$octGw[3]
                        if ($valGwC -lt $oct4Ini -or $valGwC -gt $oct4Fin) {
                            $fueraDeRango = $true
                        }
                    }
                }
                
                if ($fueraDeRango) {
                    Write-Host "`n"
                    break
                }
                else {
                    Write-Host "Inserta una direccion fuera del rango previamente establecido."
                }
            }
            elseif ($resGw -eq "n") {
                Write-Host "`n"
                break
            }
            else {
                Write-Host "Inserta una opcion valida."
            }
        }
        
        $dns = $null
        $dns2 = $null
        while ($true) {
            $resDns = Read-Host "Deseas insertar una direccion IP especifica para el DNS Server? s/n"
            $resDns = $resDns.ToLower()
            
            if ($resDns -eq "s") {
                $dns = Read-Host "Inserta la direccion IP para el DNS Server"
                
                if (-not (validacionIP $dns) -or -not (validarNoAptos $dns $claseIP) -or $dns -eq $gateway) {
                    Write-Host "Inserta una direccion valida."
                    $dns = $null
                    continue
                }
                
                while ($true) {
                    $resDns2 = Read-Host "Deseas insertar una direccion IP secundaria para el DNS Server? s/n"
                    $resDns2 = $resDns2.ToLower()
                    
                    if ($resDns2 -eq "s") {
                        $dns2 = Read-Host "Inserta la direccion IP para el DNS Server"
                        
                        if (-not (validacionIP $dns2) -or -not (validarNoAptos $dns2 $claseIP) -or $dns2 -eq $gateway) {
                            Write-Host "Inserta una direccion valida."
                            $dns2 = $null
                            continue
                        }
                        Write-Host "`n"
                        break
                    }
                    elseif ($resDns2 -eq "n") {
                        Write-Host "`n"
                        break
                    }
                    else {
                        Write-Host "Inserta una opcion valida."
                    }
                }
                break
            }
            elseif ($resDns -eq "n") {
                Write-Host "`n"
                break
            }
            else {
                Write-Host "Inserta una opcion valida."
            }
        }
        
        if ([string]::IsNullOrWhiteSpace($gateway)) {
            $gwLinea = "# No se configuro el Gateway."
        }
        else {
            $gwLinea = "option routers $gateway;"
        }
        
        if ([string]::IsNullOrWhiteSpace($dns)) {
            $dnsLinea = "# No se configuro el DNS."
        }
        else {
            if ([string]::IsNullOrWhiteSpace($dns2)) {
                $dnsLinea = "option domain-name-servers $dns;"
            }
            else {
                $dnsLinea = "option domain-name-servers $dns, $dns2;"
            }
        }
        
        # Crear el scope en DHCP
        try {
            Write-Host "Creando scope DHCP..."
            
            # Eliminar scope existente si existe
            $existingScope = Get-DhcpServerv4Scope | Where-Object { $_.Name -eq $nomScope }
            if ($existingScope) {
                Remove-DhcpServerv4Scope -ScopeId $existingScope.ScopeId -Force
            }
            
            # Crear nuevo scope
            Add-DhcpServerv4Scope -Name $nomScope `
                                   -StartRange $limInicial `
                                   -EndRange $limFinal `
                                   -SubnetMask $mask `
                                   -LeaseDuration ([TimeSpan]::FromSeconds($segLease)) `
                                   -State Active
            
            # Configurar opciones del scope
            if ($gateway) {
                Set-DhcpServerv4OptionValue -ScopeId $subnet -Router $gateway
            }
            
            if ($dns) {
                if ($dns2) {
                    Set-DhcpServerv4OptionValue -ScopeId $subnet -DnsServer $dns, $dns2
                }
                else {
                    Set-DhcpServerv4OptionValue -ScopeId $subnet -DnsServer $dns
                }
            }
            
            Write-Host "El scope fue guardado correctamente." -ForegroundColor Green
            Restart-Service DHCPServer -Force
            exit 0
        }
        catch {
            Write-Host "Error al crear el scope: $_" -ForegroundColor Red
            exit 1
        }
    }
    
    "-verconfig" {
        Write-Host "Configuracion actual:`n"
        
        try {
            $scopes = Get-DhcpServerv4Scope
            
            if ($scopes) {
                foreach ($scope in $scopes) {
                    Write-Host "========================================" 
                    Write-Host "Scope: $($scope.Name)" 
                    Write-Host "========================================" 
                    $scope | Format-List Name, ScopeId, SubnetMask, StartRange, EndRange, LeaseDuration, State
                    
                    Write-Host "Opciones del Scope:" 
                    Get-DhcpServerv4OptionValue -ScopeId $scope.ScopeId | Format-Table OptionId, Name, Value -AutoSize
                    Write-Host ""
                }
            }
            else {
                Write-Host "No hay scopes configurados.`n"
            }
        }
        catch {
            Write-Host "Error al obtener la configuracion: $_" -ForegroundColor Red
        }
    }
    
    "-restartserv" {
        if (-not (verificacionAdmin)) {
            Write-Host "ERROR: Este script requiere permisos de administrador." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "Reiniciando servicio...`n"
        
        try {
            Restart-Service DHCPServer -Force
            Write-Host "Servicio iniciado correctamente." -ForegroundColor Green
            exit 0
        }
        catch {
            Write-Host "Error al iniciar el servicio. Revisa la configuracion del servicio DHCP." -ForegroundColor Red
            exit 1
        }
    }
    
    "-monitor" {
        Write-Host "`nEstado del servicio:"
        
        $servicio = Get-Service DHCPServer -ErrorAction SilentlyContinue
        
        if ($servicio) {
            if ($servicio.Status -eq "Running") {
                Write-Host "El servicio esta activo.`n" -ForegroundColor Green
            }
            else {
                Write-Host "El servicio esta apagado o no existe.`n"
            }
        }
        else {
            Write-Host "El servicio esta apagado o no existe.`n" -ForegroundColor Red
        }
        
        Write-Host "`nConcesiones activas:"
        
        try {
            $scopes = Get-DhcpServerv4Scope
            
            if ($scopes) {
                $hayConcesiones = $false
                foreach ($scope in $scopes) {
                    $leases = Get-DhcpServerv4Lease -ScopeId $scope.ScopeId -ErrorAction SilentlyContinue
                    
                    if ($leases) {
                        $hayConcesiones = $true
                        Write-Host "`nScope: $($scope.Name) ($($scope.ScopeId))" 
                        $leases | Format-Table IPAddress, ClientId, HostName, AddressState, LeaseExpiryTime -AutoSize
                    }
                }
                
                if (-not $hayConcesiones) {
                    Write-Host "No hay concesiones activas actualmente."
                }
            }
            else {
                Write-Host "No hay scopes configurados.`n"
            }
        }
        catch {
            Write-Host "Error: No se pudieron obtener las concesiones. Por favor verifica que el servicio DHCP este instalado." -ForegroundColor Red
        }
        
        Write-Host "`nValidacion de sintaxis/configuracion del servidor DHCP:"
        try {
            $scopesValidacion = Get-DhcpServerv4Scope -ErrorAction Stop
            if ($scopesValidacion) {
                Write-Host "La configuracion del servidor DHCP es CORRECTA" -ForegroundColor Green
            }
            else {
                Write-Host "La configuracion del servidor DHCP es ERRONEA" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "La configuracion del servidor DHCP es ERRONEA" -ForegroundColor Red
        }
    }
}