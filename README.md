# 一键搭建适用于Ubuntu/CentOS的IKEV2/L2TP的VPN

------
[![Author](https://img.shields.io/badge/author-%40quericy-blue.svg)](https://quericy.me)   [![Platform](https://img.shields.io/badge/Platform-%20Ubuntu%2CCentOS%20-green.svg)]()  [![GitHub stars](https://img.shields.io/github/stars/quericy/one-key-ikev2-vpn.svg)](https://github.com/quericy/one-key-ikev2-vpn/stargazers)  [![GitHub license](https://img.shields.io/badge/license-GPLv3-yellowgreen.svg)](https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/LICENSE)

使用bash脚本一键搭建Ikev2的vpn服务端.

特性
=============
> * 服务端要求：Ubuntu或者CentOS-6.*
> * 客户端：
 - iOS/OSX=>ikev1,ikev2
 - Andriod=>ikev1
 - WindowsPhone=>ikev2
 - 其他Windows平台=>ikev2
> * 可使用自己的私钥和根证书，也可自动生成
> * 证书可绑定域名或ip
> * 要是图方便可一路回车

最近更新
==========
> - 使用新版strongswan(5.3.5),编译参数修改;
> - 优化iptables包处理;
> - 添加接口判断选择;
> - 加入对iOS9的ikev2支持;

服务端安装说明
==========
1.下载脚本:
```shell
 wget --no-check-certificate https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/one-key-ikev2.sh
```
> * 注:如需使用其他分支的脚本,请将上述url中的master修改为分支名称,各分支区别详见本页的[分支说明](#分支说明)节点

2.运行(**如果有需要使用自己的根证书请将私钥命名为ca.pem，将根证书命名为ca.cert.pem，放到脚本的相同目录下再运行该脚本**)：
```shell
chmod +x one-key-ikev2.sh
bash one-key-ikev2.sh
```

3.等待自动配置部分内容后，选择vps类型（OpenVZ还是Xen、KVM），**选错将无法成功连接，请务必核实服务器的类型**。输入服务器ip或者绑定的域名(连接vpn时服务器地址将需要与此保持一致)，以及证书的相关信息(C,O,CN)，为空将使用默认值(default value)，确认无误后按任意键继续

4.是否使用SNAT规则(可选).使用前请确保服务器具有不变的**静态公网ip**,可提升防火墙对数据包的处理速度.默认为不使用.

5.补充网卡接口信息,为空则使用默认值(Xen、KVM默认使用eth0,OpenVZ默认使用venet0).如果服务器使用其他公网接口需要在此指定接口名称,否则连接后可能无法访问外网)

6.输入两次pkcs12证书的密码(可以为空)

7.看到install Complete字样即表示安装完成。默认用户名密码将以黄字显示，可根据提示自行修改配置文件中的用户名密码,保存并重启服务生效。

8.将提示信息中的证书文件ca.cert.pem拷贝到客户端，修改后缀名为.cer后导入。ios设备使用Ikev1无需导入证书，而是需要在连接时输入共享密钥，共享密钥即是提示信息中的黄字PSK.

客户端配置说明:
=====
* 连接的服务器地址和证书保持一致,即取决于签发证书ca.cert.pem时使用的是ip还是域名;
 
* **Android/iOS/OSX** 可使用ikeV1,认证方式为用户名+密码+预共享密钥(PSK);

* **iOS/OSX/Windows7+/WindowsPhone8.1+/Linux** 均可使用IkeV2,认证方式为用户名+密码,均需要先导入证书,可将ca.cert.pem更改后缀名作为邮件附件发送给客户端,其中:
 * **iOS/OSX** 的远程ID和服务器地址保持一致,用户鉴定选择"用户名";
 * **Windows PC** 系统导入证书需要导入到"本地计算机"的"受信任的根证书颁发机构",以"当前用户"的导入方式是无效的.推荐运行mmc添加本地计算机的证书管理单元来操作;
 * **WindowsPhone8.1** 登录时的用户名需要带上域信息,即wp"关于"页面的设备名称\用户名,也可以使用%any %any : EAP "密码"进行任意用户名登录,但指定了就不能添加其他用户名了.
 * **WindowPhone10** 的vpn貌似还存在bug(截至10586.164),ikeV2方式可连接但系统流量不会走vpn.

卸载方式:
===
1.进入脚本所在目录的strongswan文件夹执行:
```bash
make uninstall
```

2.删除脚本所在目录的相关文件(one-key-ikev2.sh,strongswan.tar.gz,strongswan文件夹,my_key文件夹).

3.卸载后记得检查iptables配置.

PS:
======
* 服务器重启后默认ipsec不会自启动，请命令手动开启,或添加/usr/local/sbin/ipsec start到自启动脚本文件中(如rc.local等)：
```bash
ipsec start
```

* 连上服务器后无法链接外网：
1.打开sysctl文件:
```bash
vim /etc/sysctl.conf
```
2.修改net.ipv4.ip_forward=1后保存并关闭文件
3.使用以下指令刷新sysctl：
```bash
sysctl -p
```
4.如遇报错信息，请重新打开/etc/syctl并将报错的那些代码用#号注释，保存后再刷新sysctl直至不会报错为止。

分支说明
==========
* [master](https://github.com/quericy/one-key-ikev2-vpn/tree/master)分支:经过测试的相对稳定的版本,使用strongswan-5.3.5;
* [dev-debian](https://github.com/quericy/one-key-ikev2-vpn/tree/dev-debian)分支:如需在Debian6/7 下使用,请使用该分支的脚本,该脚本由[bestoa](https://github.com/bestoa)修改提供;
* [dev](https://github.com/quericy/one-key-ikev2-vpn/tree/dev)分支:开发分支,使用最新版本的strongswan,未进过充分测试,用于尝试和添加一些新的功能,未来可能添加对L2TP的兼容支持;

如有其他疑问请戳本人博客：[https://quericy.me/blog/699](https://quericy.me/blog/699)
