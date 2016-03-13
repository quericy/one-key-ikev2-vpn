#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required: Debian
#   Description:  Install IKEV2 VPN
#   Author: quericy
#   Intro:  http://quericy.me/blog/699
#   Modified by Besto
#===============================================================================================

clear
echo "#############################################################"
echo "# Install IKEV2 VPN"
echo "# Intro: http://quericy.me/blog/699"
echo "#"
echo "# Author: quericy"
echo "# Modified by Besto"
echo "#"
echo "#############################################################"
echo ""

# Install IKEV2
function install_ikev2(){
	rootness
	apt_install
	get_my_ip
	pre_install
	download_files
	setup_strongswan
	get_key
	configure_ipsec
	configure_strongswan
	configure_secrets
	iptables_set
	ipsec start
	success_info
}

# Make sure only root can run our script
function rootness(){
if [[ $EUID -ne 0 ]]; then
   echo "Error:This script must be run as root!" 1>&2
   exit 1
fi
}

# Get IP address of the server
function get_my_ip(){
    echo "Preparing, Please wait a moment..."
    IP=`curl -s checkip.dyndns.com | cut -d' ' -f 6  | cut -d'<' -f 1`
    if [ -z $IP ]; then
        IP=`curl -s ifconfig.me/ip`
    fi
}



# Pre-installation settings
function pre_install(){
	echo ""
    echo "please choose the type of your VPS(Xen/KVM: 1  ,  OpenVZ: 2):"
    read -p "your choice(1 or 2):" os_choice
    if [ "$os_choice" = "1" ]; then
        os="1"
		os_str="Xen/KVM"
		else
			if [ "$os_choice" = "2" ]; then
				os="2"
				os_str="OpenVZ"
				else
				echo "wrong choice!"
				exit 1
			fi
    fi
	echo "please input the ip (or domain) of your VPS:"
    read -p "ip or domain(default_vale:${IP}):" vps_ip
	if [ "$vps_ip" = "" ]; then
		vps_ip=$IP
	fi
	echo "please input the cert country(C):"
    read -p "C(default value:com):" my_cert_c
	if [ "$my_cert_c" = "" ]; then
		my_cert_c="com"
	fi
	echo "please input the cert organization(O):"
    read -p "O(default value:myvpn):" my_cert_o
	if [ "$my_cert_o" = "" ]; then
		my_cert_o="myvpn"
	fi
	echo "please input the cert common name(CN):"
    read -p "CN(default value:VPN CA):" my_cert_cn
	if [ "$my_cert_cn" = "" ]; then
		my_cert_cn="VPN CA"
	fi
	echo "####################################"
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo "Please confirm the information:"
	echo ""
	echo -e "the type of your server: [\033[32;1m$os_str\033[0m]"
	echo -e "the ip(or domain) of your server: [\033[32;1m$vps_ip\033[0m]"
	echo -e "the cert_info:[\033[32;1mC=${my_cert_c}, O=${my_cert_o}\033[0m]"
	echo ""
    echo "Press any key to start...or Press Ctrl+C to cancel"
	char=`get_char`
	#Current folder
    cur_dir=`pwd`
    cd $cur_dir
}

#install necessary lib
function apt_install(){
	apt-get -y update
	apt-get -y install curl libpam0g-dev libssl-dev make gcc
}

# Download strongswan
function download_files(){
    if [ -f strongswan.tar.gz ];then
        echo -e "strongswan.tar.gz [\033[32;1mfound\033[0m]"
    else
        if ! wget https://download.strongswan.org/strongswan-5.3.5.tar.gz;then
            echo "Failed to download strongswan.tar.gz"
            exit 1
        fi
    fi
    tar xzf strongswan*.tar.gz
    if [ $? -eq 0 ];then
        cd $cur_dir/strongswan-*/
    else
        echo ""
        echo "Unzip strongswan.tar.gz failed! Please visit http://quericy.me/blog/699 and contact."
        exit 1
    fi
}

# configure and install strongswan
function setup_strongswan(){
	if [ "$os" = "1" ]; then
		./configure  --enable-eap-identity --enable-eap-md5 \
--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
--enable-certexpire --enable-radattr --enable-tools --enable-openssl --disable-gmp

	else
		./configure  --enable-eap-identity --enable-eap-md5 \
--enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
--enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
--enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
--enable-certexpire --enable-radattr --enable-tools --enable-openssl --disable-gmp --enable-kernel-libipsec

	fi
	make; make install
}

# configure cert and key
function get_key(){
	cd $cur_dir
    if [ -f ca.pem ];then
        echo -e "ca.pem [\033[32;1mfound\033[0m]"
    else
        echo -e "ca.pem [\033[32;1mauto create\032[0m]"
		echo "auto create ca.pem ..."
		ipsec pki --gen --outform pem > ca.pem
    fi
	
	if [ -f ca.cert.pem ];then
        echo -e "ca.cert.pem [\033[32;1mfound\033[0m]"
    else
        echo -e "ca.cert.pem [\032[33;1mauto create\032[0m]"
		echo "auto create ca.cert.pem ..."
		ipsec pki --self --in ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_cert_cn}" --ca --outform pem >ca.cert.pem
    fi
	if [ ! -d my_key ];then
        mkdir my_key
    fi
	mv ca.pem my_key/ca.pem
	mv ca.cert.pem my_key/ca.cert.pem
	cd my_key
	ipsec pki --gen --outform pem > server.pem	
	ipsec pki --pub --in server.pem | ipsec pki --issue --cacert ca.cert.pem \
--cakey ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${vps_ip}" \
--san="${vps_ip}" --flag serverAuth --flag ikeIntermediate \
--outform pem > server.cert.pem
	ipsec pki --gen --outform pem > client.pem	
	ipsec pki --pub --in client.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=VPN Client" --outform pem > client.cert.pem
	echo "configure the pkcs12 cert password(Can be empty):"
	openssl pkcs12 -export -inkey client.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "${my_cert_cn}"  -out client.cert.p12
	echo "####################################"
    get_char(){
        SAVEDSTTY=`stty -g`
        stty -echo
        stty cbreak
        dd if=/dev/tty bs=1 count=1 2> /dev/null
        stty -raw
        stty echo
        stty $SAVEDSTTY
    }
    echo "Press any key to install ikev2 VPN cert"
	cp -r ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
	cp -r server.cert.pem /usr/local/etc/ipsec.d/certs/
	cp -r server.pem /usr/local/etc/ipsec.d/private/
	cp -r client.cert.pem /usr/local/etc/ipsec.d/certs/
	cp -r client.pem  /usr/local/etc/ipsec.d/private/
	
}

# configure the ipsec.conf
function configure_ipsec(){
 cat > /usr/local/etc/ipsec.conf<<-EOF
config setup
    uniqueids=never 

conn iOS_cert
    keyexchange=ikev1
    fragmentation=yes
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add

conn android_xauth_psk
    keyexchange=ikev1
    left=%defaultroute
    leftauth=psk
    leftsubnet=0.0.0.0/0
    right=%any
    rightauth=psk
    rightauth2=xauth
    rightsourceip=10.31.2.0/24
    auto=add

conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightsourceip=10.31.2.0/24
    rightcert=client.cert.pem
    auto=add

conn windows7
    keyexchange=ikev2
    ike=aes256-sha1-modp1024!
    rekey=no
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.31.2.0/24
    rightsendcert=never
    eap_identity=%any
    auto=add

EOF
}

# configure the strongswan.conf
function configure_strongswan(){
 cat > /usr/local/etc/strongswan.conf<<-EOF
 charon {
        load_modular = yes
        duplicheck.enable = no
        compress = yes
        plugins {
                include strongswan.d/charon/*.conf
        }
        dns1 = 8.8.8.8
        dns2 = 8.8.4.4
        nbns1 = 8.8.8.8
        nbns2 = 8.8.4.4
}
include strongswan.d/*.conf
EOF
}

# configure the ipsec.secrets
function configure_secrets(){
	cat > /usr/local/etc/ipsec.secrets<<-EOF
: RSA server.pem
: PSK "myPSKkey"
: XAUTH "myXAUTHPass"
myUserName %any : EAP "myUserPass"
	EOF
}

# iptables set
function iptables_set(){
    sysctl -w net.ipv4.ip_forward=1
    iptables-save > /etc/iptables.rules.old
    iptables -F
    iptables -F -t nat
    if [ "$os" = "1" ]; then
		iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
		iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
		iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
		iptables -A INPUT -i eth0 -p esp -j ACCEPT
		iptables -A INPUT -i eth0 -p udp --dport 500 -j ACCEPT
		iptables -A INPUT -i eth0 -p tcp --dport 500 -j ACCEPT
		iptables -A INPUT -i eth0 -p udp --dport 4500 -j ACCEPT
		iptables -A INPUT -i eth0 -p udp --dport 1701 -j ACCEPT
		iptables -A INPUT -i eth0 -p tcp --dport 1723 -j ACCEPT
		iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o eth0 -j MASQUERADE
		iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o eth0 -j MASQUERADE
		iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o eth0 -j MASQUERADE
	else
		iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
		iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
		iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
		iptables -A INPUT -i venet0 -p esp -j ACCEPT
		iptables -A INPUT -i venet0 -p udp --dport 500 -j ACCEPT
		iptables -A INPUT -i venet0 -p tcp --dport 500 -j ACCEPT
		iptables -A INPUT -i venet0 -p udp --dport 4500 -j ACCEPT
		iptables -A INPUT -i venet0 -p udp --dport 1701 -j ACCEPT
		iptables -A INPUT -i venet0 -p tcp --dport 1723 -j ACCEPT
		iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o venet0 -j MASQUERADE
		iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o venet0 -j MASQUERADE
		iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o venet0 -j MASQUERADE
    fi
    iptables-save > /etc/iptables.rules
    cat > /etc/network/if-up.d/iptables<<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
    chmod +x /etc/network/if-up.d/iptables
}

# echo the success info
function success_info(){
	echo "#############################################################"
	echo -e "#"
	echo -e "# [\033[32;1mInstall Successful\033[0m]"
	echo -e "# There is the default login info of your VPN"
	echo -e "# UserName:\033[33;1m myUserName\033[0m"
	echo -e "# PassWord:\033[33;1m myUserPass\033[0m"
	echo -e "# PSK:\033[33;1m myPSKkey\033[0m"
	echo -e "# you can change UserName and PassWord in\033[32;1m /usr/local/etc/ipsec.secrets\033[0m"
	echo -e "# you must copy the cert \033[32;1m ${cur_dir}/my_key/ca.cert.pem \033[0m to the client and install it."
	echo -e "#"
	echo -e "#############################################################"
	echo -e ""
}

# Initialization step
install_ikev2
