#!/bin/bash

# 定义Snell、shadow-tls版本和下载链接
SNELL_VERSION="v5.0.0"
SHADOW_TLS_VERSION="v0.2.25"

SNELL_URL="https://dl.nssurge.com/snell/snell-server-$SNELL_VERSION-linux-amd64.zip"
SHADOW_TLS_URL="https://github.com/ihciah/shadow-tls/releases/download/$SHADOW_TLS_VERSION/shadow-tls-x86_64-unknown-linux-musl"

# 更新系统包并安装必要的软件
apt update && apt upgrade -y && apt install -y wget openssl unzip vim git

# 下载并解压Snell服务器、SHADOW_TLS
wget $SNELL_URL -O snell.zip
unzip snell.zip -d /usr/local/bin
rm snell.zip

wget $SHADOW_TLS_URL -O /usr/local/bin/shadow-tls

# 赋予执行权限
chmod +x /usr/local/bin/snell-server
chmod +x /usr/local/bin/shadow-tls

# 创建配置文件目录
mkdir -p /etc/snell

# 生成随机的psk
PSK1=$(openssl rand -base64 18)
PSK2=$(openssl rand -base64 18)

# 创建Snell配置文件
cat > /etc/snell/snell-server.conf << EOF
[snell-server]
dns = 1.1.1.1, 9.9.9.9, 2606:4700:4700::1111
listen = 0.0.0.0:36139
psk = $PSK1
ipv6 = false
EOF

# 创建Snell服务
cat > /etc/systemd/system/snell.service << EOF
[Unit]
Description=Snell Proxy Service
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Type=simple
DynamicUser=yes
LimitNOFILE=32768
ExecStart=/usr/local/bin/snell-server -c /etc/snell/snell-server.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

# 创建shadow-tls服务
cat > /etc/systemd/system/shadow-tls.service << EOF
[Unit]
Description=Shadow-TLS Server Service
Documentation=man:sstls-server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment=MONOIO_FORCE_LEGACY_DRIVER=1
ExecStart=/usr/local/bin/shadow-tls --fastopen --v3 server --listen ::0:56139 --server 127.0.0.1:36139 --tls  quark.cn  --password $PSK2
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=shadow-tls

[Install]
WantedBy=multi-user.target
EOF

# 启用并启动Snell服务
sudo systemctl daemon-reload
sudo systemctl enable snell
sudo systemctl start snell

sudo systemctl enable shadow-tls.service
sudo systemctl daemon-reload
sudo systemctl start shadow-tls.service


# 获取本机公网IP地址
PUBLIC_IP=$(curl -s ifconfig.me)

# 提示用户输入代理节点名称
read -p "Enter the agent name: " AGENT_NAME

# 调整 kernel 网络性能,并开启 BBR
echo "Network tuning..."
cat <<EOF >> /etc/sysctl.conf
# 开启 BBR 和 FQ
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
# 开启 TCP Fast Open，可以降低建立 TCP 连接时的延迟
net.ipv4.tcp_fastopen = 3
# 建议开启 ECN，有助于网络拥塞控制
net.ipv4.tcp_ecn = 1
EOF

sysctl -p

# 输出PSK
echo "$AGENT_NAME = snell, $PUBLIC_IP, 56139, psk=$PSK1, version=5, reuse=true, tfo=true, ecn=true, shadow-tls-password=$PSK2, shadow-tls-sni=quark.cn, shadow-tls-version=3"
