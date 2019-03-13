#! /bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
#===============================================================================================
#   System Required:  CentOS6.x/7 (32bit/64bit) or Ubuntu
#   Description:  Install IKEV2 VPN for CentOS and Ubuntu
#   Author: quericy
#   Intro:  https://quericy.me/blog/699
#===============================================================================================

clear
VER=1.2.0
echo "#############################################################"
echo "# Install IKEV2 VPN for CentOS6.x/7 (32bit/64bit) or Ubuntu or Debian7/8.*"
echo "# Intro: https://quericy.me/blog/699"
echo "#"
echo "# Author:quericy"
echo "#"
echo "# Version:$VER"
echo "#############################################################"
echo ""

# A POSIX variable
OPTIND=1         # Reset in case getopts has been used previously in the shell.

# Initialize our own variables:

default_strongswan="5.5.1"
default_user_name="vpn"
default_user_pass="pass"
default_user_psk="psk"
default_if="eth0"
default_snat=0
vpn_key_folder=`pwd`"/vpn_keys"

key_url="https://raw.githubusercontent.com/xykong/one-key-ikev2-vpn/master/certs"
ca_key_url="${key_url}/ca.key.pem.enc"
ca_cert_url="${key_url}/ca.cert.pem.enc"
server_key_url="${key_url}/server.key.pem.enc"
client_key_url="${key_url}/client.key.pem.enc"
mobile_config_url="https://raw.githubusercontent.com/xykong/one-key-ikev2-vpn/master/IKEv2.mobileconfig"
net_cert_password=""
cert_country="CN"
cert_organization="one-key-ikev2.sh"
cert_name="VPN ROOT CA"
default_cert_password="pass"
cert_password="pass"

yum_update="n"
vps_ip=""
static_ip=""
interactive=0
use_snat=0
ignore_strongswan=0
mail_address="xy.kong@icloud.com"

# tests a file descriptor to see if it is attached to a terminal.
if [ -t 1 ] ; then
    interactive=1
fi

__green(){
    if [ ${interactive} -ne 0 ] ; then
        printf '\033[1;31;32m'
    fi
    printf -- "$1"
    if [ ${interactive} -ne 0 ] ; then
        printf '\033[0m'
    fi
}

__red(){
    if [ ${interactive} -ne 0 ] ; then
        printf '\033[1;31;40m'
    fi
    printf -- "$1"
    if [ ${interactive} -ne 0 ] ; then
        printf '\033[0m'
    fi
}

__yellow(){
    if [ ${interactive} -ne 0 ] ; then
        printf '\033[1;31;33m'
    fi
    printf -- "$1"
    if [ ${interactive} -ne 0 ] ; then
        printf '\033[0m'
    fi
}

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
    echo -e "  -u            base url to download certs. default: $(__green "${key_url}")"
    echo -e "  -r            folder to store certs, default:\033[33;1m ${vpn_key_folder}\033[0m"
    echo -e "  -c            cert country, default: \033[33;1m ${cert_country}\033[0m"
    echo -e "  -o            cert organization, default: \033[33;1m ${cert_organization}\033[0m"
    echo -e "  -n            cert common name, default: \033[33;1m ${cert_name}\033[0m"
    echo -e "  -b            cert pkcs12 password, default: \033[33;1m ${default_cert_password}\033[0m"
    echo -e "  -u            username for vpn, default: \033[33;1m ${default_user_name}\033[0m"
    echo -e "  -p            password for vpn, default: \033[33;1m ${default_user_pass}\033[0m"
    echo -e "  -k            psk for vpn, default: \033[33;1m ${default_user_psk}\033[0m"
    echo -e "  -i            prompt before using default value. defalut: \033[33;1m ${interactive}\033[0m"
    echo -e "  -y            no prompt before using default value. defalut: \033[33;1m ${interactive}\033[0m"
    echo -e "  -s            Use SNAT, y for use. defalut: \033[33;1m ${use_snat}\033[0m"
    echo -e "  -f            Network card interface, default:\033[33;1m ${default_if}\033[0m"
    echo -e "  -v            strongswan file version, default:\033[33;1m ${default_strongswan}\033[0m"
    echo -e "  -g            ignore download and build strongswan, default:\033[33;1m ${ignore_strongswan}\033[0m"
    echo -e "  -z            pass phrase source for ca, default:\033[33;1m ${net_cert_password}\033[0m"
    echo -e "  -m            send vpn server info and certs to mail address, default:\033[33;1m ${mail_address}\033[0m"
    echo -e "  -h            display this help and exit"
}

while getopts "h?ad:r:c:o:n:u:p:k:iysf:v:b:l:gz:m:" opt; do
    case "$opt" in
    h|\?) show_help; exit 0 ;;
    a)  yum_update="y" ;;
    d)  vps_ip=$OPTARG ;;
    l)  static_ip=$OPTARG ;;
    r)  vpn_key_folder=$OPTARG ;;
    c)  cert_country=$OPTARG ;;
    o)  cert_organization=$OPTARG ;;
    n)  cert_name=$OPTARG ;;
    b)  default_cert_password=$OPTARG ;;
    u)  default_user_name=$OPTARG ;;
    p)  default_user_pass=$OPTARG ;;
    k)  default_user_psk=$OPTARG ;;
    i)  interactive=1 ;;
    y)  interactive=0 ;;
    s)  use_snat="y" ;;
    f)  default_if=$OPTARG ;;
    v)  default_strongswan=$OPTARG ;;
    g)  ignore_strongswan="y" ;;
    z)  net_cert_password=$OPTARG ;;
    m)  mail_address=$OPTARG ;;
    esac
done

shift $((OPTIND-1))

[ "$1" = "--" ] && shift


# Install IKEV2
function install_ikev2(){
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
    iptables_check
    ipsec restart
    success_info
    generate_mobile_config
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
    if grep -Eqi "CentOS" /etc/issue || grep -Eq "CentOS" /etc/*-release; then
        os_type="0"
    elif  grep -Eqi "AMI" /etc/issue || grep -Eq "AMI" /etc/*-release; then
        os_type="0"
    elif  grep -Eqi "Ubuntu" /etc/issue || grep -Eq "Ubuntu" /etc/*-release; then
        os_type="1"
    elif  grep -Eqi "Debian" /etc/issue || grep -Eq "Debian" /etc/*-release; then
        os_type="1"
    elif  grep -Eqi "Raspbian" /etc/issue || grep -Eq "Raspbian" /etc/*-release; then
        os_type="1"
    else
        echo "This Script must be running at the CentOS or Ubuntu or Debian!"
        exit 1
    fi

    echo "get_system result: [$(__green "os_type=$os_type")]"
}


# Get VPS Type of Xen KVM or Openvz
function get_vps_type(){
    os_str=`virt-what | paste -sd "," -`
    os=0

    echo "$os_str" | grep -q -E "xen|kvm"
    if  [ $? -eq 0 -a $os -eq 0 ]; then
        os=1;
    fi
    echo "$os_str" | grep -q -E "openvz"
    if  [ $? -eq 0 -a $os -eq 0 ]; then
        os=2;
    fi

    if [ $os -eq 0 ] && [ ${interactive} -ne 0 ]; then
        echo "Can't detect vps type, exit."
        exit 1
    fi

    if  [ $os -eq 0 ]; then
        echo "This script can't detect your vps type automatically."
        echo "Choose the type of your VPS, Press Ctrl+C to quit: "
        while (( !os )); do
            options=("Xen, KVM" "OpenVZ")
            select opt in "${options[@]}"; do
                os_str=$opt
                case $REPLY in
                    1) os=1; break ;;
                    2) os=2; break ;;
                    *) echo "wrong choice, try again."; break ;;
                esac
            done
        done
    fi

    echo -e "get_vps_type result: [$(__green "os=$os, os_str=$os_str")]"
}

#install necessary lib
function yum_install(){

    if [ ${interactive} -ne 0 ]; then
        echo "Update yum before install?(yes:y, other key skip, default:[$(__green "${yum_update}")]:"
        read -p "your choice(y or any other):" yum_update
    fi

    if [ "$yum_update" = "y" ]; then
        if [ "$os_type" = "0" ]; then
            yum -y update
        else
            apt-get -y update
        fi
    fi

    echo -e "$(__green "Install required packages...")"
    if [ "$os_type" = "0" ]; then
        yum -y install pam-devel openssl-devel make gcc curl virt-what wget mutt
    else
        apt-get -y install libpam0g-dev libssl-dev make gcc curl virt-what wget mutt
    fi
}

# Get IP address of the server
function get_my_ip(){
    echo -e "$(__green "Preparing, try to retrieve server ip address, Please wait a moment...")"

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

    echo -e "get_my_ip result: [$(__green "IP=$IP")]"
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

    get_vps_type

    if [ ${interactive} -ne 0 ] ; then
        echo "please input the ip (or domain) of your VPS:"
        read -p "ip or domain(default_value:$(__green "${IP}")):" vps_ip
    fi

    if [ "$vps_ip" = "" ]; then
        vps_ip=$IP
    fi


    have_cert="0"
    if [ ${interactive} -ne 0 ] ; then
        echo "Would you want to import existing cert? You NEED copy your cert file to the same directory of this script"
        read -p "yes or no?(default_value:no):" have_cert
        if [ "$have_cert" = "yes" ]; then
            have_cert="1"
        fi
    fi

    if [ ${interactive} -ne 0 ] && [ "$have_cert" = "0" ]; then
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
        echo "please input the pkcs12 cert password:"
        read -p "Enter Export Password, default:${default_cert_password}):" cert_password
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
    if [ "$cert_password" = "" ]; then
        cert_password=${default_cert_password}
    fi


    echo "####################################"
    echo "Please confirm the information:"
    echo ""
    echo -e "the type of your server: [$(__green $os_str)]"
    echo -e "the ip(or domain) of your server: [$(__green $vps_ip)]"
    if [ "$have_cert" = "1" ]; then
        echo -e "$(__yellow "These are the certificate you MUST be prepared:")"
        echo -e "[$(__green "ca.cert.pem")]:The CA cert or the chain cert."
        echo -e "[$(__green "server.cert.pem")]:Your server cert."
        echo -e "[$(__green "server.key.pem")]:Your  key of the server cert."
        echo -e "[$(__yellow "Please copy these file to the same directory of this script before start!")]"
    else
        echo -e "the cert_info:[$(__green "C=${my_cert_c}, O=${my_cert_o}")]"
    fi
    echo ""
    echo "Press any key to start...or Press Ctrl+C to cancel"
    char=`get_char`
    #Current folder
    cur_dir=`pwd`
    cd $cur_dir
}

# Download strongswan
function download_files(){
    if [ "${ignore_strongswan}" = "y" ]; then
        return
    fi

    # try to download file with wget -c
    wget -c --no-check-certificate https://download.strongswan.org/strongswan-${default_strongswan}.tar.gz

    # check md5sum
    curl -s https://download.strongswan.org/strongswan-${default_strongswan}.tar.gz.md5 | grep `md5sum strongswan-${default_strongswan}.tar.gz | awk '{print $1}'`
    if [ $? -ne 0 ]; then
        # something wrong with check md5. download again.
        rm -rf strongswan-${default_strongswan}.tar.gz
        if ! wget -c --no-check-certificate https://download.strongswan.org/strongswan-${default_strongswan}.tar.gz; then
            echo "Failed to download strongswan-${default_strongswan}.tar.gz"
            exit 1
        fi
    fi

    if [ -f strongswan-${default_strongswan}.tar.gz ];then
        echo -e "strongswan-${default_strongswan}.tar.gz [$(__green "found")]"
    fi

    tar xzf strongswan-${default_strongswan}.tar.gz

    if [ $? -eq 0 ];then
        cd ${cur_dir}/strongswan-${default_strongswan}/
    else
        echo ""
        echo "Unzip strongswan-${default_strongswan}.tar.gz failed! Please visit https://quericy.me/blog/699 and contact."
        exit 1
    fi
}

# configure and install strongswan
function setup_strongswan(){
    if [ "${ignore_strongswan}" = "y" ]; then
        return
    fi

    echo -e "$(__green "strongswan configure...")"

    if [ "$os" = "1" ]; then
        ./configure  --enable-eap-identity --enable-eap-md5 \
            --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
            --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
            --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
            --enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp > /dev/null
    else
        ./configure  --enable-eap-identity --enable-eap-md5 \
            --enable-eap-mschapv2 --enable-eap-tls --enable-eap-ttls --enable-eap-peap  \
            --enable-eap-tnc --enable-eap-dynamic --enable-eap-radius --enable-xauth-eap  \
            --enable-xauth-pam  --enable-dhcp  --enable-openssl  --enable-addrblock --enable-unity  \
            --enable-certexpire --enable-radattr --enable-swanctl --enable-openssl --disable-gmp --enable-kernel-libipsec > /dev/null
    fi

    echo -e "$(__green "strongswan make...")"
    make > /dev/null

    echo -e "$(__green "strongswan make install...")"
    make install > /dev/null
}

# configure cert and key
function get_key(){
    cd $cur_dir

    if [ ! -d ${vpn_key_folder} ];then
        mkdir -p ${vpn_key_folder}
    fi

    if [ "$have_cert" = "1" ]; then
        import_cert
    fi

    cd ${vpn_key_folder}

    if [ ! ${net_cert_password} = "" ]; then
        download_cert
    fi

    create_cert

    echo "####################################"
    echo "Install ikev2 VPN cert to folder /usr/local/etc/ipsec.d/..."

    cp -f ca.cert.pem /usr/local/etc/ipsec.d/cacerts/
    cp -f server.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -f server.key.pem /usr/local/etc/ipsec.d/private/
    cp -f client.cert.pem /usr/local/etc/ipsec.d/certs/
    cp -f client.key.pem  /usr/local/etc/ipsec.d/private/

    echo "Cert copy completed"
}

# import cert if user has ssl certificate
function import_cert(){

    if [ -f ca.cert.pem ];then
        cp -f ca.cert.pem my_key/ca.cert.pem
        echo -e "ca.cert.pem [$(__green "found")]"
    else
        echo -e "ca.cert.pem [$(__red "Not found!")]"
        exit
    fi
    if [ -f server.cert.pem ];then
        cp -f server.cert.pem my_key/server.cert.pem
        cp -f server.cert.pem my_key/client.cert.pem
        echo -e "server.cert.pem [$(__green "found")]"
        echo -e "client.cert.pem [$(__green "auto create")]"
    else
        echo -e "server.cert.pem [$(__red "Not found!")]"
        exit
    fi
    if [ -f server.key.pem ];then
        cp -f server.key.pem my_key/server.key.pem
        cp -f server.key.pem my_key/client.key.pem
        echo -e "server.key.pem [$(__green "found")]"
        echo -e "client.key.pem [$(__green "auto create")]"
    else
        echo -e "server.key.pem [$(__red "Not found!")]"
        exit
    fi
    cd my_key
}

# auto create certificate
function create_cert(){

    ipsec pki --gen --outform pem > ca.key.pem
    ipsec pki --self --in ca.key.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${my_cert_cn}" --ca --outform pem >ca.cert.pem
    ipsec pki --gen --outform pem > server.key.pem
    ipsec pki --pub --in server.key.pem | ipsec pki --issue --cacert ca.cert.pem \
            --cakey ca.key.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=${vps_ip}" \
            --san="${vps_ip}" --flag serverAuth --flag ikeIntermediate \
            --outform pem > server.cert.pem
    ipsec pki --gen --outform pem > client.key.pem
    ipsec pki --pub --in client.key.pem | ipsec pki --issue --cacert ca.cert.pem --cakey ca.key.pem --dn "C=${my_cert_c}, O=${my_cert_o}, CN=VPN Client" --outform pem > client.cert.pem

    openssl pkcs12 -export -inkey ca.key.pem -in ca.cert.pem -certfile ca.cert.pem -out ca.cert.p12 -passout pass:${cert_password}
    openssl pkcs12 -export -inkey client.key.pem -in client.cert.pem -name "client" -certfile ca.cert.pem -caname "${my_cert_cn}"  -out client.cert.p12 -passout pass:${cert_password}
}

function download_cert() {

    # Download Root CA.
    echo -e "ca.key.pem $(__green "downloading...")"
    curl -fsSL ${ca_key_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out ca.key.pem

    echo -e "ca.cert.pem $(__green "downloading...")"
    curl -fsSL ${ca_cert_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out ca.cert.pem

    # Download Server Cert.
    echo -e "server.key.pem $(__green "downloading...")"
    curl -fsSL ${server_key_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out server.key.pem

    # Download Client Cert.
    echo -e "client.key.pem $(__green "downloading...")"
    curl -fsSL ${client_key_url} | openssl enc -aes-256-cbc -a -k ${net_cert_password} -d -out client.key.pem
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
    rightsourceip=10.31.2.0/24
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
: RSA server.key.pem
: PSK "${my_user_psk}"
: XAUTH "${my_user_psk}"
${my_user_name} %any : EAP "${my_user_pass}"
EOF
}

function SNAT_set(){

    use_SNAT_str="0"

    if [ ${interactive} -ne 0 ] ; then
        echo "Use SNAT could implove the speed,but your server MUST have static ip address."
        read -p "yes or no?(default_value:no):" use_SNAT
        if [ "$use_SNAT" = "yes" ]; then
            use_SNAT_str="1"
            echo -e "$(__yellow "ip address info:")"
            ip address | grep inet
            echo "Some servers has elastic IP (AWS) or mapping IP.In this case,you should input the IP address which is binding in network interface."
            read -p "static ip or network interface ip (default_value:${IP}):" static_ip

            if [ "$static_ip" = "" ]; then
                static_ip=$IP
            fi
        fi
    fi
}

# iptables check
function iptables_check(){
        cat > /etc/sysctl.d/10-ipsec.conf<<-EOF
net.ipv4.ip_forward=1
EOF
        sysctl --system
    echo "Do you use firewall in CentOS7 instead of iptables?"
    read -p "yes or no?(default_value:no):" use_firewall
    if [ "$use_firewall" = "yes" ]; then
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
    echo -e "$(__yellow "ip address info:")"
    ip address | grep inet
    echo "The above content is the network card information of your VPS."
    echo "[$(__yellow "Important")]Please enter the name of the interface which can be connected to the public network."
    if [ "$os" = "1" ]; then

        if [ ${interactive} -ne 0 ]; then
            read -p "Network card interface(default_value:eth0):" interface
        fi

        if [ "$interface" = "" ]; then
            interface="eth0"
        fi

        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
        iptables -A INPUT -i $interface -p esp -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 1701 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 1723 -j ACCEPT
        #iptables -A FORWARD -j REJECT
        if [ "$use_SNAT_str" = "1" ]; then
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j SNAT --to-source $static_ip
        else
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j MASQUERADE
        fi
    else
        if [ ${interactive} -ne 0 ]; then
        read -p "Network card interface(default_value:venet0):" interface
        fi

        if [ "$interface" = "" ]; then
            interface="venet0"
        fi

        iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
        iptables -A FORWARD -s 10.31.0.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.1.0/24  -j ACCEPT
        iptables -A FORWARD -s 10.31.2.0/24  -j ACCEPT
        iptables -A INPUT -i $interface -p esp -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 4500 -j ACCEPT
        iptables -A INPUT -i $interface -p udp --dport 1701 -j ACCEPT
        iptables -A INPUT -i $interface -p tcp --dport 1723 -j ACCEPT
        #iptables -A FORWARD -j REJECT
        if [ "$use_SNAT_str" = "1" ]; then
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j SNAT --to-source $static_ip
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j SNAT --to-source $static_ip
        else
            iptables -t nat -A POSTROUTING -s 10.31.0.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.1.0/24 -o $interface -j MASQUERADE
            iptables -t nat -A POSTROUTING -s 10.31.2.0/24 -o $interface -j MASQUERADE
        fi
    fi
    if [ "$os_type" = "0" ]; then
        service iptables save
    else
        iptables-save > /etc/iptables.rules
        cat > /etc/network/if-up.d/iptables<<-EOF
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
    echo -e "# [$(__green "Install Complete")]"
    echo -e "# Version:$VER"
    echo -e "# Network card interface: $(__green "${interface}")"
    echo -e "# Ip(or domain): $(__green "${vps_ip}")"
    echo -e "# Static ip address: $(__green "${static_ip}")"
    echo -e "# There is the default login info of your IPSec/IkeV2 VPN Service"
    echo -e "# UserName:$(__green " ${my_user_name}")"
    echo -e "# PassWord:$(__green " ${my_user_pass}")"
    echo -e "# PSK:$(__green " ${my_user_psk}")"
    echo -e "# you should change default username and password in$(__green " /usr/local/etc/ipsec.secrets")"
    echo -e "# you cert:$(__green " ${cur_dir}/my_key/ca.cert.pem ")"
    if [ "$have_cert" = "1" ]; then
    echo -e "# you don't need to install cert if it's be trusted."
    else
    echo -e "# you must copy the cert to the client and install it."
    fi
    echo -e "#"
    echo -e "#############################################################"
    echo -e ""
}

function generate_mobile_config() {

    #my_user_name
    #my_user_pass
    #vps_ip
    vpn_name=`curl -s ip.cn?ip=$vps_ip | awk -F " |：" '{print $2"("$4")"}'`
    ca_pfx_base64=`base64 ${vpn_key_folder}/ca.cert.p12 | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n//g'`
    #my_cert_cn
    #cert_password
    vpn_desc="This profile is generated by one-key-ikev2.sh download from https://github.com/xykong/one-key-ikev2-vpn"
    #my_cert_o
    vpn_profile_id="${vps_ip}.65C5030D-4E4D-4236-B341-D3EA53AB4E25"

    curl -fsSL ${mobile_config_url} |
    sed "s#{my_user_name}#${my_user_name}#g" |
    sed "s#{my_user_pass}#${my_user_pass}#g" |
    sed "s#{vps_ip}#${vps_ip}#g" |
    sed "s#{vpn_name}#${vpn_name}#g" |
    sed "s#{ca_pfx_base64}#${ca_pfx_base64}#g" |
    sed "s#{my_cert_cn}#${my_cert_cn}#g" |
    sed "s#{cert_password}#${cert_password}#g" |
    sed "s#{vpn_desc}#${vpn_desc}#g" |
    sed "s#{my_cert_o}#${my_cert_o}#g" |
    sed "s#{vpn_profile_id}#${vpn_profile_id}#g" > ${vpn_key_folder}/${vps_ip}.IKEv2.mobileconfig
}

function send_mail() {
    if [ ${mail_address} = "" ]; then
        return
    fi

    vps_region=`curl -s ip.cn?ip=$vps_ip`
    static_region=`curl -s ip.cn?ip=$static_ip`

    echo -e "\
    Network card interface:${interface} \n\
    Ip(or domain): $vps_ip \n\
    Region: $vps_region \n\
    Static ip address: $static_ip \n\n\
    Region: $static_region \n\
    There is the default login info of your VPN \n\
    UserName:${my_user_name} \n\
    PassWord:${my_user_pass} \n\
    PSK: ${my_user_psk} \n\n\
    Strongswan: strongswan-${default_strongswan}" |

    mutt -e "set envelope_from=yes" -e "set from=xy.kong@gmail.com" -a ${vpn_key_folder}/* -s "VPN ${vps_region}" -- ${mail_address}

    echo -e "$(__green "send ikev2 configuration to ${mail_address}.")"
}

# Initialization step
install_ikev2
