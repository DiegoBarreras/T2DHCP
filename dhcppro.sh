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

if [[ $# -eq 0 ]]; then
	echo -e "\n"
	echo -e "---------------------------------------------"
	echo -e "---------- MENU SCRIPT DHCP-SERVER ----------"
	echo -e "---------------------------------------------\n"

	echo -e "Para verificar la instalacion del paquete:"
	echo -e "./dhcppro.sh -verificar\n"

	echo -e "Para re/instalar el paquete:"
	echo -e "./dhcppro.sh -instalar\n"

	echo -e "Para escribir una nueva configuracion al archivo dhcpd.conf:"
	echo -e "./dhcppro.sh -newconfig\n"

	echo -e "Para mostrar la configuracion actual:"
	echo -e "./dhcppro.sh -verconfig\n"

	echo -e "Para reiniciar el servicio:"
        echo -e "./dhcppro.sh -restartserv\n"

        echo -e "Monitor de concesiones:"
        echo -e "./dhcppro.sh -monitor\n"
fi


case $1 in
	-verificar)
		echo "Buscando al paquete dhcp-server:"

		if rpm -q dhcp-server &> /dev/null; then
			echo -e "El paquete fue instalado previamente.\n";
		else
			echo -e "El paquete no ha sido instalado.\n"
		fi
		exit 0
	;;

	-instalar)
		if rpm -q dhcp-server &> /dev/null; then
                        echo -e "El paquete fue instalado previamente.";
                else
                        echo -e "El paquete no ha sido instalado."
                fi

		read -p "Deseas instalar/reinstalar el paquete? s/n " res
                res=${res,,}
                if [[ $res == "s" ]]; then
                	echo -e "Instalando el paquete dhcp-server.\n"
                        sudo dnf install -y dhcp-server
			exit 0
                else
                        echo -e "La instalacion fue cancelada.\n"
			exit 0
                 fi
	;;
	-newconfig)
                while true; do
                        read -p "Inserta el nombre del Scope para el DHCP: " nomScope
                        if [[ -z "$nomScope" ]]; then
                        echo "Inserta un nombre para el Scope."; continue
                        else
                                echo -e "\n"
                                break
                        fi
                done

		while true; do
			read -p "Inserta el tipo de clase para el rango de direcciones IP: (A, B, C) " claseIP
			claseIP=${claseIP,,}

			if [[ $claseIP != "a"  && $claseIP != "b" && $claseIP != "c" ]]; then
				echo "Inserta una clase valida."
				continue
			else
				echo -e "\n"
				break
			fi
		done

		while true; do
			read -p "Inserta el limite inicial del rango de direcciones IP: " limInicial
			if validacionIP "$limInicial"; then
				if validarNoAptos "$limInicial"; then
					sacarMascara "$limInicial"
					if validarMascara; then
						oct4Ini=$(echo $limInicial | cut -d. -f4)
						echo -e "\n"
						break
					else
						echo "Inserta una direccion IP que concuerde con la clase seleccionada."
						continue
					fi
				else
					echo "Inserta una direccion IP valida."
				fi
			else
				echo "Inserta una direccion IP con formato valido."
				continue
			fi
		done

		while true; do
		        read -p "Inserta el limite final del rango de direcciones IP: " limFinal
		        if validacionIP "$limFinal"; then
				case $claseIP in
					"a")
						if [[ $(echo $limInicial | cut -d. -f1) == $(echo $limFinal | cut -d. -f1) ]]; then
                                                	valIniA=$(( $(echo $limInicial | cut -d. -f2) * 65536 + $(echo $limInicial | cut -d. -f3) * 256 + $(echo $limInicial | cut -d. -f4) ))
                                                        valFinA=$(( $(echo $limFinal | cut -d. -f2) * 65536 + $(echo $limFinal | cut -d. -f3) * 256 + $(echo $limFinal | cut -d. -f4) ))
                                                        if [[ $valIniA -lt $valFinA ]]; then
								prefijo=$(echo $limInicial | cut -d. -f1)
								subnet=$(echo "$prefijo.0.0.0")
                                                                echo -e "\n"
                                                                break
                                                        else
                                                                echo "Inserta una direccion mayor a la especificada previamente."
                                                                continue
                                                        fi
                                        	else
                                                	echo "Inserta una direccion IP con un prefijo valido."
                                                	continue
                                        	fi
						;;

					"b")
						if [[ $(echo $limInicial | cut -d. -f1-2) == $(echo $limFinal | cut -d. -f1-2) ]]; then
                                                	valIniB=$(( $(echo $limInicial | cut -d. -f3) * 256 + $(echo $limInicial | cut -d. -f4) ))
							valFinB=$(( $(echo $limFinal | cut -d. -f3) * 256 + $(echo $limFinal | cut -d. -f4) ))
							if [[ $valIniB -lt $valFinB ]]; then
								prefijo=$(echo $limInicial | cut -d. -f1-2)
								subnet=$(echo "$prefijo.0.0")
								echo -e "\n"
								break
							else
								echo "Inserta una direccion mayor a la especificada previamente."
								continue
							fi
                                        	else
                                                	echo "Inserta una direccion IP con un prefijo valido."
                                                	continue
                                        	fi
						;;

					"c")
						if [[ $(echo $limInicial | cut -d. -f1-3) == $(echo $limFinal | cut -d. -f1-3) ]]; then
							if [[ $oct4Ini -lt $(echo $limFinal | cut -d. -f4) ]]; then
								prefijo=$(echo $limInicial | cut -d. -f1-3)
								subnet=$(echo "$prefijo.0")
								echo -e "\n"
								break
							else
								echo "Inserta una direccion mayor a la especificada previamente."
								continue
							fi
                                        	else
                                                	echo "Inserta una direccion IP con un prefijo valido."
                                                	continue
                                        	fi
						;;
				esac
			else
				echo "Inserta una direccion IP con formato valido"
				continue
			fi
		done

		while true; do
		        read -p "Inserta el Lease Time (Segundos): " segLease
		        if [[ -z "$segLease" ]]; then
		        	echo "Inserta el Lease Time.";
				continue
		        elif [[ $segLease =~ ^[0-9]+$ ]]; then
				echo -e "\n"
				break
			else
		                echo "Inserta un numero."
				continue
		        fi
		done

		oct4Fin=$(echo $limFinal | cut -d. -f4)

		while true; do
			read -p "Deseas insertar una direccion IP especifica para el Gateway? s/n " resGw
			resGw=${resGw,,}
			if [[ $resGw == "s" ]]; then 
				read -p "Inserta la direccion IP para el Gateway: $prefijo." final

				gateway="${prefijo}.${final}"

				if ! validacionIP "$gateway" || ! validarNoAptos "$gateway"; then
					echo "Inserta un Gateway valido."
					continue
				fi

				case $claseIP in
                                        "a")
                                                valGwA=$(( $(echo $gateway | cut -d. -f2) * 65536 + $(echo $gateway | cut -d. -f3) * 256 + $(echo $gateway | cut -d. -f4) ))
                                                if [[ $valGwA -lt $valIniA || $valGwA -gt $valFinA ]]; then
                                                        echo -e "\n"
                                                        break
                                                else
                                                        echo "Inserta una direccion fuera del rango previamente establecido."
                                                        continue
                                                fi
                                                ;;

                                        "b")
                                                valGwB=$(( $(echo $gateway | cut -d. -f3) * 256 + $(echo $gateway | cut -d. -f4) ))
                                                if [[ $valGwB -lt $valIniB || $valGwB -gt $valFinB ]]; then
                                                        echo -e "\n"
                                                        break
                                                else
                                                        echo "Inserta una direccion fuera del rango previamente establecido."
                                                        continue
                                                fi
                                                ;;

                                        "c")
                                                valGwC=$(( $(echo $gateway | cut -d. -f4) ))
                                                if [[ $valGwC -lt $(echo $limInicial | cut -d. -f4) || $valGwC -gt $(echo $limFinal | cut -d. -f4) ]]; then
                                                        echo -e "\n"
                                                        break
                                                else
                                                        echo "Inserta una direccion fuera del rango previamente establecido."
                                                        continue
                                                fi
                                                ;;
                                esac
			elif [[ $resGw == "n" ]]; then
				echo -e "\n"
				break
			else
				echo "Inserta una opcion valida."
				continue
			fi
		done

		while true; do
                        read -p "Deseas insertar una direccion IP especifica para el DNS Server? s/n " resDns
                        resDns=${resDns,,}
                        if [[ $resDns == "s" ]]; then
				read -p "Inserta la direccion IP para el DNS Server: " dns

				if ! validacionIP "$dns" || ! validarNoAptos "$dns" || [[ "$dns" == "$gateway" ]]; then
                                        echo "Inserta una direccion valida."
                                        continue
				else
					read -p "Deseas insertar una direccion IP secundaria para el DNS Server? s/n " resDns2
		                        resDns2=${resDns2,,}
		                        if [[ $resDns2 == "s" ]]; then
		                                read -p "Inserta la direccion IP para el DNS Server: " dns2

		                                if ! validacionIP "$dns2" || ! validarNoAptos "$dns2" || [[ "$dns2" == "$gateway" ]]; then
		                                        echo "Inserta una direccion valida."
		                                        continue
		                                else
		                                        echo -e "\n"
		                                        break
		                                fi
		                        elif [[ $resDns2 == "n" ]]; then
		                                echo -e "\n"
		                                break
		                        else
		                                echo "Inserta una opcion valida."
		                                continue
		                        fi
                                fi
			elif [[ $resDns == "n" ]]; then
				echo -e "\n"
				break
			else
				echo "Inserta una opcion valida."
				continue
			fi
		done

		if [[ -z "$gateway" ]]; then
                	gwLinea="# No se configuro el Gateway."
                else
                	gwLinea="option routers $gateway;"
                fi

		if [[ -z "$dns" ]]; then
			dnsLinea="# No se configuro el DNS."
		else
			if [[ -z "$dns2" ]]; then
				dnsLinea="option domain-name-servers $dns;"
			else
		        	dnsLinea="option domain-name-servers $dns, $dns2;"
		        fi
		fi

		if [[ -f "/etc/dhcp/dhcpd.conf" ]]; then
		    	echo "El archivo dhcpd.conf fue encontrado. Guardando... "

cat <<EOF | sudo tee /etc/dhcp/dhcpd.conf > /dev/null
ddns-update-style none;
authoritative;

subnet $subnet netmask $mask {
    range $limInicial $limFinal;
    $gwLinea
    $dnsLinea
    default-lease-time $segLease;
}
EOF

	                if [[ $? -eq 0 ]]; then
	                        echo "El archivo fue guardado correctamente."
	                        systemctl restart dhcpd
				exit 0
	                else
	                        echo "Archivo no guardado. Revisa los permisos."
	                        exit 1
	                fi
		else
			echo "Error: No se encuentra el archivo /etc/dhcp/dhcpd.conf. Por favor instala el paquete dhcp-server, o bien crea el archivo."
			exit 1
		fi

	;;

	-verconfig)
		echo -e "Configuracion actual:\n"
		sudo cat /etc/dhcp/dhcpd.conf
	;;

	-restartserv)
		echo -e "Reiniciando servicio...\n"
		systemctl restart dhcpd
		if [[ $? -eq 0 ]]; then
		        echo "Servicio iniciado correctamente."
			exit 0
		else
		        echo "Error al iniciar el servicio. Revisa la sintaxis en /etc/dhcp/dhcpd.conf, o bien instala el servicio."
			exit 1
		fi
	;;

	-monitor)
		echo -e "\nEstado del servicio:"
		if systemctl is-active dhcpd > /dev/null; then
			echo -e "El servicio esta activo.\n"
		else
			echo "El servicio esta apagado o no existe."
		fi

		echo -e "\nConcesiones activas:"
                if [[ -f "/var/lib/dhcpd/dhcpd.leases" ]]; then
                        echo "El archivo dhcpd.leases fue encontrado.\n"
		        if [ -s /var/lib/dhcpd/dhcpd.leases ]; then
		        	# Filtramos para mostrar solo IP, MAC y Nombre de equipo
		        	sudo cat /var/lib/dhcpd/dhcpd.leases
		    	else
		        	echo "No hay concesiones activas actualmente."
			fi
                else
                        echo "Error: No se encuentra el archivo /var/lib/dhcpd/dhcpd.leases. Por favor instala el paquete dhcp-server, o bien crea el archivo."
                fi

		echo -e "\nValidación de sintaxis de dhcpd.conf:"
		sudo dhcpd -t -cf /etc/dhcp/dhcpd.conf &> /dev/null
		if [ $? -eq 0 ]; then
			echo "La sintaxis de dhcpd.conf es CORRECTA"
		else
		        echo "La sintaxis de dhcpd.conf es ERRONEA"
		fi
esac
