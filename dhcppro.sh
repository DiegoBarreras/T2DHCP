source "$(dirname "$0")/funciones.sh"

if [[ $# -eq 0 ]]; then
	echo -e "\n"
	echo -e "---------------------------------------------"
	echo -e "---------- MENU SCRIPT DHCP-SERVER ----------"
	echo -e "---------------------------------------------\n"

	echo -e "Para verificar la instalacion del paquete:"
	echo -e "./dhcppro.sh --verificar\n"

	echo -e "Para re/instalar el paquete:"
	echo -e "./dhcppro.sh --instalar\n"

	echo -e "Para escribir una nueva configuracion al archivo dhcpd.conf:"
	echo -e "./dhcppro.sh --newconfig\n"

	echo -e "Para mostrar la configuracion actual:"
	echo -e "./dhcppro.sh -verconfig\n"

	echo -e "Para reiniciar el servicio:"
	echo -e "./dhcppro.sh --restartserv\n"

	echo -e "Monitor de concesiones:"
	echo -e "./dhcppro.sh --monitor\n"
fi

case $1 in
	--verificar)
		echo "Buscando al paquete dhcp-server:"
		verificar_paquete "dhcp-server"
		exit 0
	;;

	--instalar)
		verificar_paquete "dhcp-server"
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

	--newconfig)
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
			if [[ $claseIP != "a" && $claseIP != "b" && $claseIP != "c" ]]; then
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
							valIniA=$(calcular_valor_ip "$limInicial" "a")
							valFinA=$(calcular_valor_ip "$limFinal" "a")
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
							valIniB=$(calcular_valor_ip "$limInicial" "b")
							valFinB=$(calcular_valor_ip "$limFinal" "b")
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
				echo "Inserta el Lease Time."
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

				valGw=$(calcular_valor_ip "$gateway" "$claseIP")
				valIni=$(calcular_valor_ip "$limInicial" "$claseIP")
				valFin=$(calcular_valor_ip "$limFinal" "$claseIP")

				if [[ $valGw -lt $valIni || $valGw -gt $valFin ]]; then
					echo -e "\n"
					break
				else
					echo "Inserta una direccion fuera del rango previamente establecido."
					continue
				fi
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
				if ! validacionIP "$dns"; then
					echo "Inserta una direccion valida."
					continue
				else
					read -p "Deseas insertar una direccion IP secundaria para el DNS Server? s/n " resDns2
					resDns2=${resDns2,,}
					if [[ $resDns2 == "s" ]]; then
						read -p "Inserta la direccion IP para el DNS Server: " dns2
						if ! validacionIP "$dns2"; then
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
			escribir_config_dhcp
			if [[ $? -eq 0 ]]; then
				echo -e "El archivo fue guardado correctamente.\n"
				sudo systemctl restart dhcpd
			else
				echo "Archivo no guardado. Revisa los permisos."
				exit 1
			fi
		else
			echo "El archivo dhcpd.conf no fue encontrado.."
			exit 1
		fi

		while true; do
			read -p "Inserta una nueva IP para el servidor: $prefijo." finNuevaIp
			nuevaIp="${prefijo}.${finNuevaIp}"

			if ! validacionIP "$nuevaIp" || ! validarNoAptos "$nuevaIp"; then
				echo "Inserta una direccion IP valida."
				continue
			else
				valNuevaIp=$(calcular_valor_ip "$nuevaIp" "$claseIP")
				valIni=$(calcular_valor_ip "$limInicial" "$claseIP")
				valFin=$(calcular_valor_ip "$limFinal" "$claseIP")

				case $claseIP in
					"a") cidr=8 ;;
					"b") cidr=16 ;;
					"c") cidr=24 ;;
				esac

				if [[ $valNuevaIp -le $valIni || $valNuevaIp -ge $valFin ]]; then
					aplicar_ip_servidor "$nuevaIp" "$cidr"
					break
				else
					echo "Inserta una direccion fuera del rango."
					continue
				fi
			fi
		done
		;;

	--restartserv)
		echo -e "Validando configuración antes de reiniciar...\n"
		dhcpd -t -cf /etc/dhcp/dhcpd.conf > /tmp/dhcp_error 2>&1

		if [[ $? -ne 0 ]]; then
			echo "¡Error de sintaxis detectado!"
			cat /tmp/dhcp_error | grep "line"
			exit 1
		fi

		echo "Sintaxis OK. Reiniciando servicio..."
		sudo systemctl restart dhcpd

		if [[ $? -eq 0 ]]; then
			echo "Servicio iniciado correctamente."
			exit 0
		else
			echo "Error crítico: El servicio no pudo iniciar a pesar de tener sintaxis correcta."
			journalctl -u dhcpd -n 10 --no-pager
			exit 1
		fi
	;;

	--verconfig)
		echo -e "Configuracion actual:\n"
		sudo cat /etc/dhcp/dhcpd.conf
	;;

	--monitor)
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