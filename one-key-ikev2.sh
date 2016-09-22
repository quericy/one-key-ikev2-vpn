#! /bin/bash
#===============================================================================================
#   System Required:  CentOS6 & 7 (32bit/64bit) , Ubuntu or Debian
#   Description:  Install IKEV2 VPN for CentOS and Ubuntu
#   Author: quericy
#   Modified: Besto, liton, xuld
#   Intro:  https://quericy.me/blog/699
#===============================================================================================

clear
echo "#############################################################"
echo "# Install IKEV2 VPN for CentOS6 & 7 (32bit/64bit) , Ubuntu or Debian"
echo "# Intro: https://quericy.me/blog/699"
echo "#"
echo "# Author: quericy"
echo "# Modified: Besto, liton, xuld"
echo "#"
echo "#############################################################"
echo ""

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize our own variables:

default_strongswan="strongswan-5.3.5"
default_user_name="vpn"
default_user_pass="pass"
default_user_psk="psk"
default_if="eth0"
default_snat=0
vpn_key_folder=`pwd`"/vpn_keys"

ca_key_url="https://raw.githubusercontent.com/xykong/one-key-ikev2-vpn/master/certs/ca.key.pem.enc"
ca_cert_url="https://raw.githubusercontent.com/xykong/one-key-ikev2-vpn/master/certs/ca.cert.pem.enc"
server_key_url="https://raw.githubusercontent.com/xykong/one-key-ikev2-vpn/master/certs/server.key.pem.enc"
client_key_url="https://raw.githubusercontent.com/xykong/one-key-ikev2-vpn/master/certs/client.key.pem.enc"
net_cert_password=""
cert_country="CN"
cert_organization="VPN ORGANIZATION"
cert_name="VPN ROOT CA"
cert_password="pass"

yum_update=0
vps_ip=""
static_ip=""
interactive=0
use_snat=0
ignore_strongswan=0
mail_address=""

function show_help() {
    echo -e "Usage: $0 [arguments]"
    echo -e "Create IKEV2/L2TP VPN on VPS by this script."
    echo -e ""
    echo -e "Mandatory arguments to long options are mandatory for short options too."
    echo -e "  -a            Update yum before install, y for update. default: \033[33;1m ${yum_update}\033[0m"
    echo -e "  -d            ip or domain address, default is ip address retrived by script."
    echo -e "  -l            static ip or network interface ip. Some servers has elastic IP (AWS) "
    echo -e "                  or mapping IP.In this case,you should input the IP address which is "
    echo -e "                  binding in network interface."
    echo -e "  -r            folder to store certs, default:\033[33;1m ${vpn_key_folder}\033[0m"
    echo -e "  -c            cert country, default: \033[33;1m ${cert_country}\033[0m"
    echo -e "  -o            cert organization, default: \033[33;1m ${cert_organization}\033[0m"
    echo -e "  -n            cert common name, default: \033[33;1m ${cert_name}\033[0m"
    echo -e "  -b            cert pkcs12 password, default: \033[33;1m ${cert_password}\033[0m"
    echo -e "  -u            username for vpn, default: \033[33;1m ${default_user_name}\033[0m"
    echo -e "  -p            password for vpn, default: \033[33;1m ${default_user_pass}\033[0m"
    echo -e "  -k            psk for vpn, default: \033[33;1m ${default_user_psk}\033[0m"
    echo -e "  -i            prompt before using default value. defalut: \033[33;1m ${interactive}\033[0m"
    echo -e "  -s            Use SNAT, y for use. defalut: \033[33;1m ${use_snat}\033[0m"
    echo -e "  -f            Network card interface, default:\033[33;1m ${default_if}\033[0m"
    echo -e "  -w            strongswan file name, default:\033[33;1m ${default_strongswan}\033[0m"
    echo -e "  -g            ignore download and build strongswan, default:\033[33;1m ${ignore_strongswan}\033[0m"
    echo -e "  -z            pass phrase source for ca, default:\033[33;1m ${net_cert_password}\033[0m"
    echo -e "  -m            send vpn server info and certs to mail address, default:\033[33;1m ${mail_address}\033[0m"
    echo -e "  -h            display this help and exit"
}

while getopts "h?ad:r:c:o:n:u:p:k:isf:w:b:l:gz:m:" opt; do
    case "$opt" in
    h|\?) show_help; exit 0 ;;
    a)  yum_update="y" ;;
    d)  vps_ip=$OPTARG ;;
    l)  static_ip=$OPTARG ;;
    r)  vpn_key_folder=$OPTARG ;;
    c)  cert_country=$OPTARG ;;
    o)  cert_organization=$OPTARG ;;
    n)  cert_name=$OPTARG ;;
    b)  cert_password=$OPTARG ;;
    u)  default_user_name=$OPTARG ;;
    p)  default_user_pass=$OPTARG ;;
    k)  default_user_psk=$OPTARG ;;
    i)  interactive=1 ;;
    s)  use_snat="y" ;;
    f)  default_if=$OPTARG ;;
    w)  default_strongswan=$OPTARG ;;
    g)  ignore_strongswan="y" ;;
    z)  net_cert_password=$OPTARG ;;
    m)  mail_address=$OPTARG ;;
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift


# Install IKEV2
function install_ikev2(){

    cur_dir=`pwd`

    rootness
    disable_selinux
    get_system
    yum_install
    get_my_ip
    pre_install
    download_files
    setup_strongswan
    get_key
    configure_ipsec
    configure_strongswan
    configure_secrets
    SNAT_set
    iptables_set
    ipsec restart
    success_info
    send_mail
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

# Ubuntu or CentOS
function get_system(){
    os_type=0

    which yum &> /dev/null
    if [ $? -eq 0 -a $os_type -eq 0 ]; then
        os_type=1
    fi

    which apt-get &> /dev/null
    if [ $? -eq 0 -a $os_type -eq 0 ]; then
        os_type=2
    fi

    if [ $os_type -eq 0 ]; then
        echo "This Script must be running at the CentOS, Ubuntu or Debian!"
        exit 1
    fi

#    echo "get_system result: os_type=$os_type"
}

# Get VPS Type of Xen KVM or Openvz
function get_virt(){
    vm_type_str=`virt-what | paste -sd "," -`
    vm_type=0

    echo "$vm_type_str" | grep -q -E "xen|kvm"
    if  [ $? -eq 0 -a $vm_type -eq 0 ]; then
        vm_type=1;
    fi
    echo "$vm_type_str" | grep -q -E "openvz"
    if  [ $? -eq 0 -a $vm_type -eq 0 ]; then
        vm_type=2;
    fi

    if [ $vm_type -eq 0 -a ${interactive} -eq 0 ]; then
        echo "Can't detect vps type, exit."
        exit 1
    fi

    if  [ $vm_type -eq 0 ]; then
        echo "This script can't detect your vps type automatically."
        echo "Choose the type of your VPS, Press Ctrl+C to quit: "
        while (( !vm_type )); do
            options=("Xen, KVM" "OpenVZ")
            select opt in "${options[@]}"; do
                vm_type_str=$opt
                case $REPLY in
                    1) vm_type=1; break ;;
                    2) vm_type=2; break ;;
                    *) echo "wrong choice, try again."; break ;;
                esac
            done
        done
    fi

    #echo -e "get_virt result: vm_type=$vm_type, vm_type_str=$vm_type_str"
}

#install necessary lib
function yum_install(){

    if [ ${interactive} -ne 0 ]; then
        echo "Update yum before install?(yes:y, other key skip):"
        read -p "your choice(y or any other):" yum_update
    fi

    if [ "$yum_update" = "y" ]; then
        if [ "$os_type" = "1" ]; then
            yum -y update
        else
            apt-get -y update
        fi
    fi

    if [ "$os_type" = "1" ]; then
        yum -y install pam-devel openssl-devel make gcc curl virt-what wget mutt
    else
        apt-get -y install libpam0g-dev libssl-dev make gcc curl virt-what wget mutt
    fi
}

# Get IP address of the server
function get_my_ip(){
    echo "Preparing, try to retrive server ip address, Please wait a moment..."

    if [ -z $IP ]; then
        IP=`curl -s ip.cn | awk -F"：| " '{print $3}'`
    fi

    if [ -z $IP ]; then
        IP=`curl -s checkip.dyndns.com | cut -d' ' -f 6  | cut -d'<' -f 1`
    fi

    if [ -z $IP ]; then
        IP=`curl -s members.3322.org/dyndns/getip`
    fi

    if [ -z $IP ]; then
        IP=`curl -s ifconfig.me/ip`
    fi
}

function get_char(){
    SAVEDSTTY=`stty -g`
    stty -echo
    stty cbreak
    dd if=/dev/tty bs=1 count=1 2> /dev/null
    stty -raw
    stty echo
    stty $SAVEDSTTY
}

# Pre-installation settings
function pre_install(){
    echo "#############################################################"
    echo "# Install IKEV2 VPN for CentOS6 & 7 (32bit/64bit) , Ubuntu or Debian"
    echo "# Intro: https://quericy.me/blog/699"
    echo "#"
    echo "# Author:quericy"
    echo "# Modified: Besto, liton, xuld"
    echo "#"
    echo "#############################################################"
    echo ""

    get_virt

    if [ "$vps_ip" = "" ]; then
        vps_ip=$IP
    fi

    if [ ${interactive} -ne 0 ]; then
        echo "please input the ip (or domain) of your VPS:"
        read -p "ip or domain(default_value:${IP}):" vps_ip
        echo "please input the cert country(C):"
        read -p "C(default value:${cert_country}):" my_cert_c
        echo "please input the cert organization(O):"
        read -p "O(default value:${cert_organization}):" my_cert_o
        echo "please input the cert common name(CN):"
        read -p "CN(default value:${cert_name}):" my_cert_cn
        echo "please input the username to login:"
        read -p "USERNAME(default ${default_user_name}):" my_user_name
        echo "please input the password to login:"
        read -p "USERPASS(default ${default_user_pass}):" my_user_pass
        echo "please input the psk key to login:"
        read -p "USERPSK(default ${default_user_psk}):" my_user_psk
    fi

    if [ "$vps_ip" = "" ]; then
        vps_ip=$IP
    fi
    if [ "$my_cert_c" = "" ]; then
        my_cert_c=${cert_country}
    fi
    if [ "$my_cert_o" = "" ]; then
        my_cert_o=${cert_organization}
    fi
    if [ "$my_cert_cn" = "" ]; then
        my_cert_cn=${cert_name}
    fi
    if [ "$my_user_name" = "" ]; then
        my_user_name=${default_user_name}
    fi
    if [ "$my_user_pass" = "" ]; then
        my_user_pass=${default_user_pass}
    fi
    if [ "$my_user_psk" = "" ]; then
        my_user_psk=${default_user_psk}
    fi

    if [ ${interactive} -ne 0 ]; then
        echo "Please confirm the information:"
        echo ""
        echo -e "the type of your server: [\033[32;1m$vm_type_str\033[0m]"
        echo -e "the ip(or domain) of your server: [\033[32;1m$vps_ip\033[0m]"
        echo -e "the cert_info:[\033[32;1mC=${my_cert_c}, O=${my_cert_o}\033[0m]"
        echo ""
        echo "Press any key to start...or Press Ctrl+C to cancel"
        char=`get_char`
    fi

    #Current folder
    cd ${cur_dir}
}

# Download strongswan
function download_files(){
    if [ "${ignore_strongswan}" = "y" ]; then
        return
    fi

    # try to download file with wget -c
    wget -c --no-check-certificate https://download.strongswan.org/${default_strongswan}.tar.gz

    # check md5sum
    curl -s https://www.strongswan.org/download.html | grep `md5sum ${default_strongswan}.tar.gz | awk '{print $1}'`
    if [ $? -ne 0 ]; then
        # something wrong with check md5. download again.
        rm -rf ${default_strongswan}.tar.gz
        if ! wget -c --no-check-certificate https://download.strongswan.org/${default_strongswan}.tar.gz; then
            echo "Failed to download ${default_strongswan}.tar.gz"
            exit 1
        fi
    fi

    if [ -f ${default_strongswan}.tar.gz ];then
        echo -e "${default_strongswan}.tar.gz [\033[32;1mfound\033[0m]"
    fi

    tar xzf ${default_strongswan}.tar.gz

    if [ $? -eq 0 ];then
        cd ${cur_dir}/${default_strongswan}/
    else
        echo ""
        echo "Unzip ${default_strongswan}.tar.gz failed! Please visit https://quericy.me/blog/699 and contact."
        exit 1
    fi
}

# configure and install strongswan
function setup_strongswan(){
    if [ "${ignore_strongswan}" = "y" ]; then
        return
    fi

    if [ "$vm_type" = "1" ]; then
        ./configure  --enable-eap-identity --enable-eap-md5 \
            --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
            --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
            --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
            --enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp
    else
        ./configure  --enable-eap-identity --enable-eap-md5 \
            --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
            --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
            --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
            --enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp --enable-kernel-libipsec
    fi

    make && make install
}

# configure cert and key
function get_key(){

    if [ ! -d ${vpn_key_folder} ];then
        mkdir -p ${vpn_key_folder}
    fi

    cd ${vpn_key_folder}

    # Create Root CA.
    if [ ! ${net_cert_password} = "" ]; then
        echo -e "ca.key.pem [\033[32;1mdownloading...\033[0m]"
        curl -fsSL ${ca_key_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out ca.key.pem
    fi
    if [ -f ca.key.pem ]; then
        echo -e "ca.key.pem [\033[32;1mfound\033[0m]"
    else
        echo -e "ca.key.pem [\033[32;1mauto create\033[0m]"
        echo "auto create ca.key.pem ..."
        ipsec pki --gen --outform pem > ca.key.pem
    fi

    if [ ! ${net_cert_password} = "" ]; then
        echo -e "ca.cert.pem [\033[32;1mdownloading...\033[0m]"
        curl -fsSL ${ca_cert_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out ca.cert.pem
    fi
    if [ -f ca.cert.pem ]; then
        echo -e "ca.cert.pem [\033[32;1mfound\033[0m]"
    else
        echo -e "ca.cert.pem [\033[33;1mauto create\033[0m]"
        echo "auto create ca.cert.pem ..."
        ipsec pki --self --in ca.key.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_cert_cn}" \
                --ca --outform pem > ca.cert.pem
    fi

    # Create Server CA.
    if [ ! ${net_cert_password} = "" ]; then
        echo -e "server.key.pem [\033[32;1mdownloading...\033[0m]"
        curl -fsSL ${server_key_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out server.key.pem
    fi
    if [ -f server.key.pem ]; then
        echo -e "server.key.pem [\033[32;1mfound\033[0m]"
    else
        echo -e "server.key.pem [\033[32;1mauto create\033[0m]"
        echo "auto create server.key.pem ..."
        ipsec pki --gen --outform pem > server.key.pem
    fi
    
    ipsec pki --pub --in server.key.pem | ipsec pki --issue --cacert ca.cert.pem \
            --cakey ca.key.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${vps_ip}" \
            --san="${vps_ip}" --flag serverAuth --flag ikeIntermediate \
            --outform pem > server.cert.pem

    # Create Client CA.
    if [ ! ${net_cert_password} = "" ]; then
        echo -e "client.key.pem [\033[32;1mdownloading...\033[0m]"
        curl -fsSL ${client_key_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out client.key.pem
    fi
    if [ -f client.key.pem ]; then
        echo -e "client.key.pem [\033[32;1mfound\033[0m]"
    else
        echo -e "client.key.pem [\033[32;1mauto create\033[0m]"
        echo "auto create client.key.pem ..."
        ipsec pki --gen --outform pem > client.key.pem
    fi
    ipsec pki --pub --in client.key.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.key.pem \
            --dn "C=${my_cert_c}, O=${my_cert_o}, CN=VPN Client ${vps_ip}" --outform pem > client.cert.pem

    if [ ${interactive} -ne 0 ]; then
        echo "configure the pkcs12 cert password(Can be empty):"
        openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "client" -certfile ca.cert.pem \
                -caname "${my_cert_cn}"  -out client.cert.p12
    else
        echo "configure the pkcs12 cert."
        openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "client" -certfile ca.cert.pem \
                -caname "${my_cert_cn}"  -out client.cert.p12 -passout pass:${cert_password}
    fi

    echo "Install ikev2 VPN cert to folder /usr/local/etc/ipsec.d/"

    cp -r ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
    cp -r server.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -r server.key.pem /usr/local/etc/ipsec.d/private/
    cp -r client.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -r client.key.pem  /usr/local/etc/ipsec.d/private/

    cd ${cur_dir}
}

# configure the ipsec.conf
function configure_ipsec(){
    cat > /usr/local/etc/ipsec.conf<<-EOF
config setup
    uniqueids=no

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
    rightsourceip=10.60.10.0/24
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
    rightsourceip=10.60.10.0/24
    auto=add

conn networkmanager-strongswan
    keyexchange=ikev2
    left=%defaultroute
    leftauth=pubkey
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=pubkey
    rightsourceip=10.60.10.0/24
    rightcert=client.cert.pem
    auto=add

conn ios_ikev2
    keyexchange=ikev2
    ike=aes256-sha256-modp2048,3des-sha1-modp2048,aes256-sha1-modp2048!
    esp=aes256-sha256,3des-sha1,aes256-sha1!
    rekey=no
    left=%defaultroute
    leftid=${vps_ip}
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    leftcert=server.cert.pem
    right=%any
    rightauth=eap-mschapv2
    rightsourceip=10.60.10.0/24
    rightsendcert=never
    eap_identity=%any
    dpdaction=clear
    fragmentation=yes
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
    rightsourceip=10.60.10.0/24
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
: RSA server.key.pem
: PSK "${my_user_psk}"
: XAUTH "${my_user_psk}"
${my_user_name} %any : EAP "${my_user_pass}"
EOF
}

function SNAT_set(){

    if [ ${interactive} -ne 0 ]; then
        echo "Use SNAT could implove the speed,but your server MUST have static ip address."
        read -p "y or any other?(default_value:${use_snat}):" use_snat

        if [ "$use_snat" = "y" ]; then
            echo "Some servers has elastic IP (AWS) or mapping IP.In this case,you should input the IP address which is binding in network interface."
            read -p "static ip or network interface ip (default_value:${IP}):" static_ip
        fi
    fi

    if [ "$static_ip" = "" ]; then
        static_ip=$IP
    fi
}

# iptables set
function iptables_set(){
    sysctl -w net.ipv4.ip_forward=1

    if [ ${interactive} -ne 0 ]; then
        ifconfig

        echo "The above content is the network card information of your VPS."
        echo "Please enter the name of the interface which can be connected to the public network."
    fi

    if [ "$vm_type" = "1" ]; then
        if [ ${interactive} -ne 0 ]; then
            read -p "Network card interface(default_value:eth0):" interface
        fi

        if [ "$interface" = "" ]; then
            interface="eth0"
        fi

        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        #iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
        #iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.60.10.0/24  -j ACCEPT
        iptables -A INPUT -i $interface -p esp -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 1701 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 1723 -j ACCEPT
        #iptables -A FORWARD -j REJECT
        if [ "$use_snat" = "y" ]; then
            #iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
            #iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.60.10.0/24 -o $interface -j SNAT --to-source $static_ip
        else
            #iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
            #iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.60.10.0/24 -o $interface -j MASQUERADE
        fi
    else
        if [ ${interactive} -ne 0 ]; then
            read -p "Network card interface(default_value:venet0):" interface
        fi

        if [ "$interface" = "" ]; then
            interface="venet0"
        fi

        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        #iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
        #iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.60.10.0/24  -j ACCEPT
        iptables -A INPUT -i $interface -p esp -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 1701 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 1723 -j ACCEPT
        #iptables -A FORWARD -j REJECT
        if [ "$use_snat" = "y" ]; then
            #iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
            #iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.60.10.0/24 -o $interface -j SNAT --to-source $static_ip
        else
            #iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
            #iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.60.10.0/24 -o $interface -j MASQUERADE
        fi
    fi
    if [ "$os_type" = "1" ]; then
        service iptables save
    else
        iptables-save > /etc/iptables.rules
        cat > /etc/network/if-up.d/iptables<<EOF
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF
        chmod +x /etc/network/if-up.d/iptables
    fi
}

# echo the success info
function success_info(){
    echo "#############################################################"
    echo -e "#"
    echo -e "# [\033[32;1mInstall Complete\033[0m]"
    echo -e "# Network card interface: [\033[32;1m${interface}\033[0m]"
    echo -e "# Ip(or domain): \033[32;1m$vps_ip\033[0m"
    echo -e "# Static ip address: \033[32;1m$static_ip\033[0m"
    echo -e "# There is the default login info of your VPN"
    echo -e "# UserName:\033[33;1m ${my_user_name}\033[0m"
    echo -e "# PassWord:\033[33;1m ${my_user_pass}\033[0m"
    echo -e "# PSK:\033[33;1m ${my_user_psk}\033[0m"
    echo -e "# you can change UserName and PassWord in\033[32;1m /usr/local/etc/ipsec.secrets\033[0m"
    echo -e "# you must copy the cert \033[32;1m ${vpn_key_folder}/ca.cert.pem \033[0m to the client and install it."
    echo -e "#"
    echo -e "#############################################################"
    echo -e ""
}

function send_mail() {
    if [ ${mail_address} = "" ]; then
        return
    fi

    echo -e "Network card interface:${interface} \n\
    Ip(or domain): $vps_ip \n\
    Static ip address: $static_ip \n\n\
    There is the default login info of your VPN \n\
    UserName:${my_user_name} \n\
    PassWord:${my_user_pass} \n\
    PSK: ${my_user_psk} \n\n\
    Strongswan: ${default_strongswan}" | mutt -a ${vpn_key_folder}/* -s "vpn ${vps_ip}" -- ${mail_address}

    echo -e "\033[32;1mmail vpn info to ${mail_address}.\033[0m"
}

# Initialization step
install_ikev2
