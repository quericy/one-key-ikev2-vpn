# 一键搭建适用于Ubuntu/CentOS的IKEV2/L2TP的VPN

------
[![Author](https://img.shields.io/badge/author-%40quericy-blue.svg)](https://quericy.me)   [![Platform](https://img.shields.io/badge/Platform-%20Ubuntu%2CCentOS%20-green.svg)]()  [![GitHub stars](https://img.shields.io/github/stars/quericy/one-key-ikev2-vpn.svg)](https://github.com/quericy/one-key-ikev2-vpn/stargazers)  [![GitHub license](https://img.shields.io/badge/license-GPLv3-yellowgreen.svg)](https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/LICENSE)

使用bash脚本一键搭建Ikev2的vpn服务端.

特性
=============
> * 服务端要求：Ubuntu或者CentOS-6/7或者Debian
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
> - 添加SSL证书自动申请自动更新并应用于IKEv2的解决方案,详见这篇博文:[SSL证书自动更新并应用到IKEv2, Nginx](https://quericy.me/blog/860/) ;
> - 添加对CentOS7的firewall防火墙的支持;
> - 使用ip address替换已被废弃的ifconfig;
> - 生成单独的sysctl配置文件/etc/sysctl.d/10-ipsec.conf单独加载，用于开启ipv4转发(如以后卸载或需要关闭net.ipv4.ip_forward,请记得删除此文件);
> - 升级strongswan版本到5.5.1,解决iOS9和iOS10的兼容性问题(感谢[caasiu](https://github.com/caasiu)的提醒[#21](https://github.com/quericy/one-key-ikev2-vpn/issues/21));
> - 添加导入SSL证书的支持,安装时可选使用证书颁发机构签发的证书还是生成自签名证书;

服务端安装说明
==========
1. 下载脚本:
    ```shell
    wget --no-check-certificate https://raw.githubusercontent.com/quericy/one-key-ikev2-vpn/master/one-key-ikev2.sh
    ```
    * 注:如需使用其他分支的脚本,请将上述url中的master修改为分支名称,各分支区别详见本页的[分支说明](#分支说明)节点

2. 运行脚本：
    ```shell
    chmod +x one-key-ikev2.sh
    bash one-key-ikev2.sh
    ```

3. 等待自动配置部分内容后，选择vps类型（OpenVZ还是Xen、KVM），**选错将无法成功连接，请务必核实服务器的类型**。输入服务器ip或者绑定的域名(连接vpn时服务器地址将需要与此保持一致,如果是导入泛域名证书这里需要写`*.域名`的形式)；

4. 选择使用使用证书颁发机构签发的SSL证书还是生成自签名证书：

    - 如果选择no,`使用自签名证书`（客户端如果使用IkeV2方式连接，将需要导入生成的证书并信任）则需要填写证书的相关信息(C,O,CN)，为空将使用默认值(default value)，确认无误后按任意键继续,后续安装过程中会出现输入两次pkcs12证书的密码的提示(可以设置为空)

    - 如果选择yes，`使用SSL证书`（如果证书是被信任的，后续步骤客户端将无需导入证书）请在继续下一步之前，将以下文件按提示命名并放在**脚本相同的目录下**（SSL证书详细配置和自动续期方案可见[https://quericy.me/blog/860/](https://quericy.me/blog/860/) ）：
        1. **ca.cert.pem** 证书颁发机构的CA，比如Let‘s Encrypt的证书,或者其他链证书；
        2. **server.cert.pem** 签发的域名证书；
        3. **server.pem** 签发域名证书时用的私钥；

5. 是否使用SNAT规则(可选).默认为不使用.使用前请确保服务器具有不变的**静态公网ip**,可提升防火墙对数据包的处理速度.如果服务器网络设置了NAT(如AWS的弹性ip机制),则填写网卡连接接口的ip地址(参见[KinonC](https://github.com/KinonC)提供的方案:[#36](https://github.com/quericy/one-key-ikev2-vpn/issues/36)).

6. 防火墙配置.默认配置iptables(如果使用的是firewall(如CentOS7)请选择yes自动配置firewall,将无视SNAT并跳过后续的补充网卡接口步骤).补充网卡接口信息,为空则使用默认值(Xen、KVM默认使用eth0,OpenVZ默认使用venet0).如果服务器使用其他公网接口需要在此指定接口名称,**填写错误VPN连接后将无法访问外网**)

7. 看到install Complete字样即表示安装完成。默认用户名密码将以黄字显示，可根据提示自行修改配置文件中的用户名密码,多用户则在配置文件中按格式一行一个(多用户时用户名不能使用%any),保存并重启服务生效。

8. 将提示信息中的证书文件ca.cert.pem拷贝到客户端，修改后缀名为.cer后导入。ios设备使用Ikev1无需导入证书，而是需要在连接时输入共享密钥，共享密钥即是提示信息中的黄字PSK.

客户端配置说明
=====
* 连接的服务器地址和证书保持一致,即取决于签发证书ca.cert.pem时使用的是ip还是域名;
 
* **Android/iOS/OSX** 可使用ikeV1,认证方式为用户名+密码+预共享密钥(PSK);

* **iOS/OSX/Windows7+/WindowsPhone8.1+/Linux** 均可使用IkeV2,认证方式为用户名+密码。`使用SSL证书`则无需导入证书；`使用自签名证书`则需要先导入证书才能连接,可将ca.cert.pem更改后缀名作为邮件附件发送给客户端,手机端也可通过浏览器导入,其中:
 * **iOS/OSX** 的远程ID和服务器地址保持一致,用户鉴定选择"用户名".如果通过浏览器导入,将证书放在可访问的远程外链上,并在**系统浏览器**(Safari)中访问外链地址.OSX证书需要设置为始终信任(添加方法见**[#58](https://github.com/quericy/one-key-ikev2-vpn/issues/58)**中[JiaHaoGong](https://github.com/JiaHaoGong)的截图);
 * **Windows PC** 系统导入证书需要导入到**"本地计算机"**的"受信任的根证书颁发机构",以"当前用户"的导入方式是无效的.推荐运行mmc添加本地计算机的证书管理单元来操作;
 * **WindowsPhone8.1** 登录时的用户名需要带上域信息,即wp"关于"页面的设备名称\用户名,也可以使用%any %any : EAP "密码"进行任意用户名登录,但指定了就不能添加其他用户名了.
 * **WindowsPhone10** ~~的vpn还存在bug(截至10586.164),ikeV2方式可连接但系统流量不会走vpn,只能等微软解决.~~ (截至14393.5 ,此bug已经得到修复,现在WP10已经可以正常使用IkeV2.)
 * **Windows10** 也存在此bug,部分Win10系统连接后ip不变,没有自动添加路由表,使用以下方法可解决(本方法由 bigbigfish 童鞋提供):
    * 手动关闭vpn的split tunneling功能(在远程网络上使用默认网关);
    * 也可使用powershell修改,进入CMD窗口,运行如下命令:
    ```powershell
    powershell    #进入ps控制台
    get-vpnconnection    #检查vpn连接的设置（包括vpn连接的名称）
    set-vpnconnection "vpn连接名称" -splittunneling $false    #关闭split tunneling
    get-vpnconnection   #检查修改结果
    exit   #退出ps控制台
    ```

卸载方式
===
1. 进入脚本所在目录的strongswan文件夹执行:
    ```bash
    make uninstall
    ```

2. 删除脚本所在目录的相关文件(one-key-ikev2.sh,strongswan.tar.gz,strongswan文件夹,my_key文件夹).

3. 卸载后记得检查iptables配置.

分支说明
==========
* [master](https://github.com/quericy/one-key-ikev2-vpn/tree/master)分支:经过测试的相对稳定的版本;
* dev-debian分支:~~Debian6/7测试分支,该脚本由[bestoa](https://github.com/bestoa)修改提供~~.主分支已提供对Debian的支持,该分支已废弃:[#59](https://github.com/quericy/one-key-ikev2-vpn/issues/59);
* [dev](https://github.com/quericy/one-key-ikev2-vpn/tree/dev)分支:开发分支,使用最新版本的strongswan,未进过充分测试,用于尝试和添加一些新的功能,未来可能添加对L2TP的兼容支持,以及对ipv6的支持;

部分问题解决方案
======
* ipsec启动问题：服务器重启后默认ipsec不会自启动，请命令手动开启,或添加/usr/local/sbin/ipsec start到自启动脚本文件中(如rc.local等)：
    ```bash
    ipsec start
    ```

* ipsec常用指令:
    ```bash
    ipsec start   #启动服务
    ipsec stop    #关闭服务
    ipsec restart #重启服务
    ipsec reload  #重新读取
    ipsec status  #查看状态
    ipsec --help  #查看帮助
    ```

* 可连接但是无法访问网络：
    - 检查iptables是否正常启用,检查iptables规则是否与其他地方冲突,或根据服务器防火墙的实际情况手动修改配置。
    - 检查sysctl是否开启ip_forward:
        1. 打开sysctl文件:`vim /etc/sysctl.conf`                
        2. 修改net.ipv4.ip_forward=1后保存并关闭文件    
        3. 使用以下指令刷新sysctl：`sysctl -p`
        4. 如执行后正常回显则表示生效。如显示错误信息，请重新打开/etc/syctl并根据错误信息对应部分用#号注释，保存后再刷新sysctl直至不会报错为止。

* 如果之前使用的自签名证书，后改用SSL证书，部分客户端可能需要卸载之前安装的自签名证书,否则可能会报`Ike凭证不可接受`的错误:
    * iOS：设置-通用，删除证书对应的描述文件即可；
    * Windows：Win+R,运行mmc打开Microsoft管理控制台,文件->添加管理单元,添加证书管理单元(必须选计算机账户),展开受信任的根证书颁发机构,找到对应的自签名证书,右键删除即可;
    * Windows Phone:暂时没有找到可以卸载证书的方法(除非越狱),目前只能重置来解决此问题;

* * *

如有其他疑问请戳本人博客：[https://quericy.me/blog/699](https://quericy.me/blog/699)
