# 一键搭建适用于Debian的IKEV2/L2TP的VPN

------
使用bash脚本一键搭建Ikev2的vpn

说明
=============
> * 服务端要求：Debian7/8.*
> * 客户端：
 - iOS=>ikev1
 - Andriod=>ikev1
 - WindowsPhone=>ikev2
 - 其他Windows平台=>ikev2
> * 可使用自己的私钥和根证书，也可自动生成
> * 证书可绑定域名或ip
> * 要是图方便可一路回车

使用方法
==========
* 运行(**如果有需要使用自己的根证书请将私钥命名为ca.pem，将根证书命名为ca.cert.pem，放到脚本的相同目录下再运行该脚本**)：
```shell
chmod +x one-key-ikev2.sh
bash one-key-ikev2.sh
```
* 将提示信息中的证书文件ca.cert.pem拷贝到客户端，修改后缀名为.cer后导入。ios设备使用Ikev1无需导入证书，而是需要在连接时输入共享密钥，共享密钥即是提示信息中的黄字PSK.

PS:
======
* 服务器重启后默认ipsec不会自启动，请自行添加，或使用命令手动开启：
```bash
ipsec start
```
* 连上服务器后无法链接外网：
```bash
vim /etc/sysctl
```
修改net.ipv4.ip_forward=1后保存并关闭文件
然后使用以下指令刷新sysctl：
```bash
sysctl -p
```
如遇报错信息，请重新打开/etc/syctl并将报错的那些代码用#号注释，保存后再刷新sysctl直至不会报错为止。

根据quericy的程序魔改而成，如有其他疑问请戳原作者博客：[http://quericy.me/blog/699](http://quericy.me/blog/699)
