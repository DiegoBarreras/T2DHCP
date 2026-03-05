validacionIP() {
        local ip=$1
        local regex="^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        if [[ $ip =~ $regex ]]; then
                return 0
        else
                return 1
        fi
}

sacarMascara() {
        local ip=$1
        local octComp=$(echo $ip | cut -d. -f1)

        if (($octComp <= "126" && $octComp >= "1")); then
                mask="255.0.0.0"
                return 0
        elif (($octComp >= "128" && $octComp <= "191")); then
                mask="255.255.0.0"
                return 0
        elif (($octComp >= "192" && $octComp <= "223")); then
                mask="255.255.255.0"
		return 0
        else
                return 1
        fi
}

validarMascara() {
	if [[ $mask == "255.0.0.0" && $claseIP != "a" ]]; then
                return 1
	elif [[ $mask == "255.255.0.0" && $claseIP != "b" ]]; then
                return 1
	elif [[ $mask == "255.255.255.0" && $claseIP != "c" ]]; then
                return 1
	else
		return 0
	fi
}

validarNoAptos() {
	local ip=$1

	if [[ $(echo $ip | cut -d. -f1) == "127" ]]; then
		return 1
	elif [[ $claseIP == "a" ]]; then
		if [[ $(echo $ip | cut -d. -f2-4) == "0.0.0" || $(echo $ip | cut -d. -f2-4) == "255.255.255" ]]; then
			return 1
		else
			return 0
		fi
	elif [[ $claseIP == "b" ]]; then
                if [[ $(echo $ip | cut -d. -f3-4) == "0.0" || $(echo $ip | cut -d. -f3-4) == "255.255" ]]; then
                        return 1
		else
			return 0
                fi
        elif [[ $claseIP == "c" ]]; then
                if [[ $(echo $ip | cut -d. -f4) == "0" || $(echo $ip | cut -d. -f4) == "255" ]]; then
                        return 1
		else
			return 0
                fi
	fi
}

verificar_paquete() {
	local paq=$1
	if rpm -q $paq &> /dev/null; then
		echo -e "El paquete fue instalado previamente."
	else
		echo -e "El paquete no ha sido instalado."
	fi
}

calcular_valor_ip() {
	local ip=$1
	local clase=$2
	case $clase in
		"a") echo $(( $(echo $ip | cut -d. -f2) * 65536 + $(echo $ip | cut -d. -f3) * 256 + $(echo $ip | cut -d. -f4) )) ;;
		"b") echo $(( $(echo $ip | cut -d. -f3) * 256 + $(echo $ip | cut -d. -f4) )) ;;
		"c") echo $(( $(echo $ip | cut -d. -f4) )) ;;
	esac
}

aplicar_ip_servidor() {
	local ip=$1
	local cidr=$2
	sudo nmcli con mod "red_interna" ipv4.addresses $ip/$cidr
	sudo nmcli con mod "red_interna" ipv4.method manual
	sudo nmcli con up "red_interna"
	echo "Direccion IP actualizada exitosamente."
	sudo firewall-cmd --add-service=dhcp --permanent
	sudo firewall-cmd --reload
}

escribir_config_dhcp() {
cat <<EOF | sudo tee /etc/dhcp/dhcpd.conf > /dev/null
ddns-update-style none;
authoritative;
$dnsLinea

subnet $subnet netmask $mask {
    range $limInicial $limFinal;
    $gwLinea
    default-lease-time $segLease;
}
EOF
}