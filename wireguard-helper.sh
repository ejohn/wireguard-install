#!/bin/bash

function is_root() {
	if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
	fi
}

function wireguard_settings() {
	SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	if [[ -z ${SERVER_PUB_IP} ]]; then
		SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	fi
	SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"

	SERVER_WG_NIC="wg0"
	SERVER_WG_IPV4="10.254.1.1"
	SERVER_WG_IPV6="fd10:25:41::1"
	SERVER_PORT=$(shuf -i49152-65535 -n1)
	CLIENT_DNS_1=1.1.1.1
	CLIENT_DNS_2=8.8.8.8
}

function install_wireguard() {
	# Run setup questions first
	wireguard_settings


	apt-get update
	apt-get install -y wireguard iptables resolvconf qrencode uuid

	# Make sure the directory exists (this does not seem the be the case on fedora)
	mkdir /etc/wireguard >/dev/null 2>&1

	chmod 600 -R /etc/wireguard/

	SERVER_PRIV_KEY=$(wg genkey)
	SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

	# Save WireGuard settings
	echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}" >/etc/wireguard/params

	# Add server interface
	echo "[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"

	if pgrep firewalld; then
		FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
		FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
		echo "PostUp = firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	else
		echo "PostUp = iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE; ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"
	fi

	# Enable routing on the server
	echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/wg.conf

	sysctl --system

	systemctl start "wg-quick@${SERVER_WG_NIC}"
	systemctl enable "wg-quick@${SERVER_WG_NIC}"

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	# WireGuard might not work if we updated the kernel. Tell the user to reboot
	if [[ ${WG_RUNNING} -ne 0 ]]; then
		echo -e "\nWARNING: WireGuard does not seem to be running."
		echo "You can check if WireGuard is running with: systemctl status wg-quick@${SERVER_WG_NIC}"
		echo "If you get something like \"Cannot find device ${SERVER_WG_NIC}\", please reboot!"
	fi

	new_client
	echo "If you want to add more clients, you simply need to run this script another time!"
}

function new_client() {
	ENDPOINT="${SERVER_PUB_IP}:${SERVER_PORT}"

	CLIENT_NAME=`uuid -v4`

	for DOT_IP in {2..254}; do
		DOT_EXISTS=$(grep -c "${SERVER_WG_IPV4::-1}${DOT_IP}" "/etc/wireguard/${SERVER_WG_NIC}.conf")
		if [[ ${DOT_EXISTS} == '0' ]]; then
			break
		fi
	done

	if [[ ${DOT_EXISTS} == '1' ]]; then
		echo ""
		echo "The subnet configured supports only 253 clients."
		exit 1
	fi

	until [[ ${IPV4_EXISTS} == '0' ]]; do
		CLIENT_WG_IPV4="${SERVER_WG_IPV4::-1}${DOT_IP}"
	done

	until [[ ${IPV6_EXISTS} == '0' ]]; do
		CLIENT_WG_IPV6="${SERVER_WG_IPV6::-1}${DOT_IP}"
	done

	# Generate key pair for the client
	CLIENT_PRIV_KEY=$(wg genkey)
	CLIENT_PUB_KEY=$(echo "${CLIENT_PRIV_KEY}" | wg pubkey)
	CLIENT_PRE_SHARED_KEY=$(wg genpsk)

	# Create client file and add the server as a peer
	echo "[Interface]
PrivateKey = ${CLIENT_PRIV_KEY}
Address = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128
DNS = ${CLIENT_DNS_1},${CLIENT_DNS_2}

[Peer]
PublicKey = ${SERVER_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
Endpoint = ${ENDPOINT}
AllowedIPs = 0.0.0.0/0,::/0" >>"${HOME_DIR}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# Add the client as a peer to the server
	echo -e "\n### Client ${CLIENT_NAME}
[Peer]
PublicKey = ${CLIENT_PUB_KEY}
PresharedKey = ${CLIENT_PRE_SHARED_KEY}
AllowedIPs = ${CLIENT_WG_IPV4}/32,${CLIENT_WG_IPV6}/128" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"

	systemctl restart "wg-quick@${SERVER_WG_NIC}"
}

function revoke_client() {
	# TODO: add check to see if client exists
	
	# match the selected number to a client name
	CLIENT_NAME=$1

	# remove [Peer] block matching $CLIENT_NAME
	sed -i "/^### Client ${CLIENT_NAME}\$/,/^$/d" "/etc/wireguard/${SERVER_WG_NIC}.conf"

	# remove generated client file
	rm -f "${HOME}/${SERVER_WG_NIC}-client-${CLIENT_NAME}.conf"

	# restart wireguard to apply changes
	systemctl restart "wg-quick@${SERVER_WG_NIC}"
}

function uninstall_wireguard() {
	systemctl stop "wg-quick@${SERVER_WG_NIC}"
	systemctl disable "wg-quick@${SERVER_WG_NIC}"

	apt-get autoremove --purge -y wireguard qrencode

	rm -rf /etc/wireguard
	rm -f /etc/sysctl.d/wg.conf

	# Reload sysctl
	sysctl --system

	# Check if WireGuard is running
	systemctl is-active --quiet "wg-quick@${SERVER_WG_NIC}"
	WG_RUNNING=$?

	if [[ ${WG_RUNNING} -eq 0 ]]; then
		echo "WireGuard failed to uninstall_wireguard properly."
		exit 1
	else
		echo "WireGuard uninstall_wireguard successfully."
		exit 0
	fi
}

# 	echo "What do you want to do?"
# 	echo "   1) Add a new user"
# 	echo "   2) Revoke existing user"
# 	echo "   3) uninstall_wireguard WireGuard"
# 	echo "   4) Exit"


is_root

# Check if WireGuard is already installed and load params
if [[ -e /etc/wireguard/params ]]; then
	source /etc/wireguard/params
fi

if [ "$1" == "install" ]; then
	install_wireguard
	exit 0
fi

if [ "$1" == "uninstall" ]; then
	uninstall_wireguard
	exit 0
fi

if [ "$1" == "add" ]; then
	new_client
	exit 0
fi

if [ "$1" == "revoke" ]; then
	if [ "$2" == "" ]; then
		echo "provide client id to revoke"
		exit 1
	fi
	revoke_client $2
	exit 0
fi
