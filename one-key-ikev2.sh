#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

clear
VER=1.2.0
echo "#############################################################"
echo "# Install IKEV2 VPN for CentOS6.x/7 (32bit/64bit) "
echo "#############################################################"
echo ""

__INTERACTIVE=""
if [ -t 1 ] ; then
    __INTERACTIVE="1"
fi

__green(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;32m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

__red(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;40m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

__yellow(){
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[1;31;33m'
    fi
    printf -- "$1"
    if [ "$__INTERACTIVE" ] ; then
        printf '\033[0m'
    fi
}

# Install IKEV2
function install_ikev2(){
    rootness
    disable_selinux
    pre_install
    setup_strongswan
    configure_secrets
    configure_ipsec
    configure_strongswan
    iptables_check
    ipsec restart
    success_info
}

# Make sure only root can run our script
function rootness(){
    if [[ $EUID -ne 0 ]]; then
    echo "Error:This script must be run as root!" 1>&2
    exit 1
    fi
}

# Disable selinux
function disable_selinux(){
    if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
        sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
        setenforce 0
    fi
}


# Pre-installation settings
function pre_install(){
    echo "Preparing, Please wait a moment..."
    echo "[$(__red "Error")]Please input the domain name of your VPS:"
    read -p "domain name:" domain_name
    if [ "$domain_name" = "" ]; then
        echo "[$(__red "Error")]Please enter the domain name of the vps."
        exit 1;
    fi

    echo -e "$(__yellow "ip address info:")"
    ip address | grep inet
    echo "The above content is the network card information of your VPS."
    echo "[$(__yellow "Important")]Please enter the name of the interface which can be connected to the public network."
    read -p "Network card interface(default_value:eth0):" interface
    if [ "$interface" = "" ]; then
        interface="eth0"
    fi

    # define the certfile , Import the files before start this script
    cert_file="/etc/ssl.cert/cert.pem"
    ca_file="/etc/ssl.cert/ca.pem"
    key_file="/etc/ssl.cert/key.pem"
    user_name="myUserName"
    user_pwd="myUserPass"
    user_pky_key="myPSKkey"
    
    
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
    echo ""
    echo -e "#######################Information############################"
    echo -e "#"
    echo -e "# - Domain Name:$(__green "${domain_name}")"
    echo -e "# - CA File:$(__green " ${ca_file}")"
    echo -e "# - Cert File:$(__green " ${cert_file}")"
    echo -e "# - Private Key File:$(__green " ${key_file}")"
    echo -e "# - UserName:$(__green " ${user_name}")"
    echo -e "# - PassWord:$(__green " ${user_pwd}")"
    echo -e "# - PSK Key:$(__green " ${user_pky_key}")"
    echo -e "#"
    echo -e "#############################################################"
    echo -e ""
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    #Current folder
    cur_dir=`pwd`
    cd $cur_dir
}


# configure and install strongswan
function setup_strongswan(){
    yum -y install strongswan strongswan-plugin-xauth-generic strongswan-plugin-eap-mschapv2 strongswan-plugin-eap-md5
}

# configure cert and key
function configure_secrets(){

    cat > /usr/local/etc/ipsec.secrets<<-EOF
: RSA ${key_file}
: PSK "myPSKkey"
myUserName %any : EAP "myUserPass"
EOF
}

# configure the ipsec.conf
function configure_ipsec(){
 cat > /usr/local/etc/ipsec.conf<<-EOF
config setup
    uniqueids=never
ca cust-ca-file
    cacert=${ca_file}
    auto=add
conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    keyexchange=ike
conn ikev2-eap-mschapv2
    keyexchange=ikev2
    leftauth=pubkey
    leftcert=${cert_file}
    leftid=${domain_name}
    leftsendcert=always
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    rightauth=eap-mschapv2
    right=%any
    rightsourceip=10.31.2.0/50
    eap_identity=%any
    auto=add
conn ikev2-eap-md5
    keyexchange=ikev2
    leftauth=pubkey
    leftcert=${cert_file}
    leftid=${domain_name}
    leftsendcert=always
    left=%defaultroute
    leftsubnet=0.0.0.0/0
    leftfirewall=yes
    rightauth=eap-md5
    eap_identity=%any
    right=%any
    rightsourceip=10.31.2.0/50
    auto=add
EOF
}

# configure the strongswan.conf
function configure_strongswan(){
 cat > /usr/local/etc/strongswan.conf<<-EOF
charon {
    load_modular = yes
    duplicheck.enable = no
    install_virtual_ip = yes
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



# iptables check
function iptables_check(){
    cat > /etc/sysctl.d/10-ipsec.conf<<-EOF
net.ipv4.ip_forward=1
EOF
    sysctl --system

    if ! grep -qs "release 7." /etc/redhat-release; then
       firewall_set
    else
       iptables_set
    fi
}

# firewall set in CentOS7
function firewall_set(){
    if ! systemctl is-active firewalld > /dev/null; then
        systemctl start firewalld
    fi
    firewall-cmd --permanent --add-service="ipsec"
    firewall-cmd --permanent --add-port=500/udp
    firewall-cmd --permanent --add-port=4500/udp
    firewall-cmd --permanent --add-masquerade
    firewall-cmd --reload
}

# iptables set
function iptables_set(){
    iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -s 10.31.2.0/50  -j ACCEPT
    iptables -A INPUT -i $interface -p esp -j ACCEPT
    iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
    iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
    #iptables -A FORWARD -j REJECT
    iptables -t nat -A POSTROUTING -s 10.31.2.0/50 -o $interface -j MASQUERADE
    
    service iptables save
}

# echo the success info
function success_info(){
    echo "#############################################################"
    echo -e "#"
    echo -e "# [$(__green "Install Complete")]"
    echo -e "# Version:$VER"
    echo -e "# There is the default login info of your IPSec/IkeV2 VPN Service"
    echo -e "# UserName:$(__green " myUserName")"
    echo -e "# PassWord:$(__green " myUserPass")"
    echo -e "# PSK:$(__green " myPSKkey")"
    echo -e "# you should change default username and password in$(__green " /usr/local/etc/ipsec.secrets")"
    echo -e "# you cert file:$(__green " ${cert_file}")"
    echo -e "# you ca file:$(__green " ${ca_file}")"
    echo -e "# you key file:$(__green " ${key_file}")"
    echo -e "# you don't need to install cert if it's be trusted."
    echo -e "#"
    echo -e "#############################################################"
    echo -e ""
}

# Initialization step
install_ikev2
