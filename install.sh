#!/bin/bash

CONFIG_FILE="/usr/local/etc/xray/config.json"
GEOIP_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
GEOSITE_URL="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"

DEST_SERVER_NAME=""
DEST_SERVER_NAME_LIST=("learn.microsoft.com" "www.samsung.com" "www.tesla.com" "www.yahoo.com")

DEFAULT_TIMEOUT=15

TEMP_DIR=$(mktemp -d)
TEMP_ZIP="$TEMP_DIR/Xray-linux-64.zip"
TEMP_ZIP_DGST="$TEMP_DIR/Xray-linux-64.zip.dgst"

VERSION=""
XRAY_URL=""
XRAY_DGST_URL=""
VLESS_LINK=""

_red='\033[1;31m'
_green='\033[1;32m'
_yellow='\033[1;33m'
_magenta='\033[1;35m'
_plain='\033[0m'

red() { echo -e "${_red}$1${_plain}"; }
green() { echo -e "${_green}$1${_plain}"; }
yellow() { echo -e "${_yellow}$1${_plain}"; }
magenta() { echo -e "${_magenta}$1${_plain}"; }
plain() { echo -e "${_plain}$1${_plain}"; }

cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
        magenta "\n临时文件已清除。脚本已退出执行。"
    else
        magenta "\n临时目录不存在，无需清理。脚本已退出执行。"
    fi
}

trap cleanup EXIT

welcome_msg() {
    magenta "欢迎使用此脚本！\n此脚本将自动安装最新版本的 Xray-core 并生成 Reality 协议配置。\n"
}

check_root() {
    yellow "正在检查权限..."

    if [[ "$EUID" -ne 0 ]]; then
        red "错误：此脚本必须以 root 权限运行！"
        exit 1
    fi

    green "所需权限已验证。\n"
}

check_architecture() {
    yellow "正在检查系统架构..."

    local arch=$(uname -m)
    if [[ "$arch" != "x86_64" && "$arch" != "x64" && "$arch" != "amd64" ]]; then
        red "不支持的系统架构: $arch。"
        exit 1
    fi

    green "系统架构已验证。\n"
}

check_system() {
    yellow "正在检查系统兼容性..."

    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
    elif [[ -f /usr/lib/os-release ]]; then
        source /usr/lib/os-release
    else
        red "无法检测到系统信息。" >&2
        exit 1
    fi

    os_version=${VERSION_ID:-0}
    os_version=${os_version//[^0-9]/}

    check_version() {
        local required_version=$1

        if [[ "$os_version" -lt "$required_version" ]]; then
            red "请使用 ${ID^} ${required_version} 或更高版本。" >&2
            exit 1
        fi
    }

    case "$ID" in
    debian)
        check_version 10
        ;;
    ubuntu)
        check_version 20
        ;;
    fedora)
        check_version 38
        ;;
    *)
        red "不支持的操作系统：$ID，请使用 Debian 10+、Ubuntu 20+ 或 Fedora 38+。"
        exit 1
        ;;
    esac

    green "系统兼容性已验证。\n"
}

install_dependencies() {
    yellow "正在检查必要依赖工具..."

    if ! command -v curl &>/dev/null; then
        yellow "未找到 curl，开始安装 curl..."
        if command -v apt &>/dev/null; then
            apt update -y && apt install -y curl
            green "curl 安装成功。"
        elif command -v yum &>/dev/null; then
            yum install -y curl
            green "curl 安装成功。"
        else
            red "无法安装 curl，请手动安装。"
            exit 1
        fi
    fi

    if ! command -v unzip &>/dev/null; then
        yellow "未找到 unzip，开始安装 unzip..."
        if command -v apt &>/dev/null; then
            apt update -y && apt install -y unzip
            green "unzip 安装成功。"
        elif command -v yum &>/dev/null; then
            yum install -y unzip
            green "unzip 安装成功。"
        else
            red "无法安装 unzip，请手动安装。"
            exit 1
        fi
    fi

    if ! command -v jq &>/dev/null; then
        yellow "未找到 jq，开始安装 jq..."
        if command -v apt &>/dev/null; then
            apt update -y && apt install -y jq
            green "jq 安装成功。"
        elif command -v yum &>/dev/null; then
            yum install -y jq
            green "jq 安装成功。"
        else
            red "无法安装 jq，请手动安装。"
            exit 1
        fi
    fi

    green "必要依赖工具已安装。\n"
}

curl_with_retry() {
    local url=$1
    local output=$2
    local max_retries=3

    for ((i = 1; i <= max_retries; i++)); do
        if [[ -n "$output" ]]; then
            curl -L --max-time 30 "$url" -o "$output" && return 0
        else
            curl -sL --max-time 30 "$url" && return 0
        fi

        yellow "下载失败，正在重试... ($i/$max_retries)"
        for ((j = DEFAULT_TIMEOUT; j > 0; j--)); do
            echo -ne "等待 $j 秒...\r"
            sleep 1
        done
        echo ""
    done

    red "下载失败，超过最大重试次数。\n"
    exit 1
}

check_installed_version() {
    yellow "正在检查已安装的 Xray-core 版本..."

    if [[ -f /usr/local/bin/xray ]]; then
        local full_version_output=$(/usr/local/bin/xray -version 2>/dev/null)
        local installed_version=$(echo "$full_version_output" | grep -oP 'Xray \K\d+\.\d+\.\d+')

        if [[ "$installed_version" == "$VERSION" ]]; then
            green "已安装的 Xray-core 版本 $installed_version 是最新版本，无需下载。\n"
            create_vless_link
            exit 0
        else
            yellow "发现新版本：$VERSION。当前版本：$installed_version。即将更新...\n"
        fi
    else
        yellow "未检测到已安装的 Xray-core，将继续下载最新版本...\n"
    fi
}

get_latest_version() {
    yellow "开始获取 Xray-core 最新版本信息..."

    local url="https://api.github.com/repos/XTLS/Xray-core/releases/latest"
    VERSION=$(curl_with_retry "$url" "-" | jq -r '.tag_name' | sed 's/^v//')
    if [[ -z "$VERSION" ]]; then
        red "获取最新版本失败。\n"
        exit 1
    fi
    XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/v${VERSION}/Xray-linux-64.zip"
    XRAY_DGST_URL="https://github.com/XTLS/Xray-core/releases/download/v${VERSION}/Xray-linux-64.zip.dgst"

    green "获取 Xray-core 最新版本成功，当前最新版本为 $VERSION。\n"
}

install_xray() {
    mkdir -p /usr/local/bin /usr/local/etc/xray /usr/local/share/xray /var/log/xray

    yellow "开始下载 Xray-core..."
    curl_with_retry "$XRAY_URL" "$TEMP_ZIP" || { red "下载 Xray-core 失败。" && exit 1; }
    green "Xray-core 下载完成。\n"

    yellow "开始下载 Xray-core 校验文件..."
    curl_with_retry "$XRAY_DGST_URL" "$TEMP_ZIP_DGST" || { red "下载 Xray-core 校验文件失败。" && exit 1; }
    green "Xray-core 校验文件下载完成。\n"

    yellow "正在验证 Xray-core 文件完整性..."
    local expected_hash=$(grep -i 'SHA2-256' "$TEMP_ZIP_DGST" | awk '{print $2}')
    if [[ -z "$expected_hash" ]]; then
        red "校验文件格式无效，找不到 SHA2-256 哈希值。\n"
        exit 1
    fi

    local actual_hash=$(sha256sum "$TEMP_ZIP" | awk '{print $1}')

    if [[ "$expected_hash" != "$actual_hash" ]]; then
        red "校验失败，文件完整性验证未通过。\n"
        exit 1
    else
        green "文件校验通过！\n"
    fi

    yellow "开始解压并安装 Xray-core..."
    unzip -o "$TEMP_ZIP" -d /usr/local/bin || { red "解压 Xray-core 失败。" && exit 1; }
    green "Xray-core 解压并安装成功。\n"

    yellow "正在赋予 Xray-core 执行权限..."
    chmod +x /usr/local/bin/xray || { red "赋予 Xray-core 执行权限失败。" && exit 1; }
    green "赋予 Xray-core 执行权限成功。\n"

    yellow "开始下载 geoip 数据..."
    curl_with_retry "$GEOIP_URL" "/usr/local/share/xray/geoip.dat" || { red "下载 geoip 数据失败。" && exit 1; }
    green "geoip 数据下载完成。\n"

    yellow "开始下载 geosite 数据..."
    curl_with_retry "$GEOSITE_URL" "/usr/local/share/xray/geosite.dat" || { red "下载 geosite 数据失败。" && exit 1; }
    green "geosite 数据下载完成。\n"

    yellow "正在写入 Xray-core 服务..."
    cat <<EOF >/etc/systemd/system/xray.service
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xray -config /usr/local/etc/xray/config.json
Restart=on-failure
StandardOutput=journal
StandardError=journal
TimeoutStartSec=30
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF
    green "Xray-core 服务已写入。"

    systemctl enable xray.service
    yellow "已设置允许 Xray-core 服务自启动。"

    systemctl start xray.service
    yellow "已启动 Xray-core 服务。"

    green "Xray-core 安装完成。\n"
}

setup_cron_job() {
    yellow "正在添加 GEO 数据自动更新的定时任务..."
    local cron_job="5 6 * * * curl -L $GEOIP_URL -o /usr/local/share/xray/geoip.dat && curl -L $GEOSITE_URL -o /usr/local/share/xray/geosite.dat"

    if crontab -l | grep -qF "$cron_job"; then
        green "定时任务已存在，跳过添加。\n"
    else
        (crontab -l; echo "$cron_job") | crontab -
        green "已设置每天早上 6:05 自动更新 GEO 数据的定时任务。\n"
    fi
}

generate_config() {
    yellow "开始创建 Reality 协议配置文件..."

    if [[ -f $CONFIG_FILE ]]; then
        read -p "$(echo -e "配置文件已存在，是否覆盖重新生成[默认 ${_red}n${_plain}]（${_green}y${_plain}/${_red}n${_plain}）: ")" OVERWRITE_CONFIG
        OVERWRITE_CONFIG=${OVERWRITE_CONFIG:-n}
        if [[ "$OVERWRITE_CONFIG" == "n" ]]; then
            yellow "配置文件已存在，跳过重新生成。\n"
            return 1
        fi
    fi

    while true; do
        echo "请选择要使用的 DNS 解析："
        echo -e "  ${_magenta}1${_plain}）Cloudflare"
        echo -e "  ${_magenta}2${_plain}）Cloudflare 家庭保护版"
        echo -e "  ${_magenta}3${_plain}）${_plain}Google"
        echo -e "  ${_magenta}4${_plain}）${_plain}自定义 DNS 服务器"

        echo -ne "\r输入选项[默认 ${_magenta}1${_plain}]："
        read DNS_OPTION
        DNS_OPTION=${DNS_OPTION:-1}

        if [[ "$DNS_OPTION" =~ ^[1-4]$ ]]; then
            break
        else
            red "无效输入，请选择 1-4 的选项。"
        fi
    done

    case $DNS_OPTION in
    1)
        DNS_SERVERS=("https://dns.cloudflare.com/dns-query")
        ;;
    2)
        DNS_SERVERS=("https://family.cloudflare-dns.com/dns-query")
        ;;
    3)
        DNS_SERVERS=("https://dns.google/dns-query")
        ;;
    4)
        while true; do
            read -p "请输入自定义 DoH 服务器地址：" CUSTOM_DNS

            if [[ "$CUSTOM_DNS" =~ ^https?://[a-zA-Z0-9.-]+/dns-query$ ]]; then
                DNS_SERVERS=("$CUSTOM_DNS")
                break
            else
                red "无效的 DoH 服务器地址，请重新输入。"
            fi
        done
        ;;
    esac

    while true; do
        echo -ne "是否屏蔽色情内容[${_green}y${_plain}/${_red}n${_plain}，默认 y]："
        read BLOCK_PORN
        BLOCK_PORN=${BLOCK_PORN:-y}
        BLOCK_PORN=$(echo "$BLOCK_PORN" | tr '[:upper:]' '[:lower:]')

        if [[ "$BLOCK_PORN" == "y" || "$BLOCK_PORN" == "n" ]]; then
            break
        else
            red "无效输入，请输入 y 或 n。"
        fi
    done

    while true; do
        echo -ne "是否屏蔽公共跟踪器[${_green}y${_plain}/${_red}n${_plain}，默认 y]："
        read BLOCK_TRACKER
        BLOCK_TRACKER=${BLOCK_TRACKER:-y}
        BLOCK_TRACKER=$(echo "$BLOCK_TRACKER" | tr '[:upper:]' '[:lower:]')

        if [[ "$BLOCK_TRACKER" == "y" || "$BLOCK_TRACKER" == "n" ]]; then
            break
        else
            red "无效输入，请输入 y 或 n。"
        fi
    done

    echo -ne "请输入端口[按回车随机选择]："
    read PORT
    if [[ ! "$PORT" =~ ^[0-9]+$ || "$PORT" -lt 10000 || "$PORT" -gt 65535 ]]; then
        PORT=$((RANDOM % (65525 - 10000 + 1) + 10000))
    fi

    DEST_SERVER_NAME=${DEST_SERVER_NAME:-$(shuf -n1 -e "${DEST_SERVER_NAME_LIST[@]}")}

    echo -ne "请输入指向本机 IP 的域名[若无，请直接回车]："
    read CUSTOM_OUTBOUND_ADDRESS
    OUTBOUND_ADDRESS=${CUSTOM_OUTBOUND_ADDRESS:-$(hostname -I | awk '{print $1}')}

    UUID=$(xray uuid)
    KEYS=$(xray x25519)
    PRIVATE_KEY=$(echo "$KEYS" | grep 'Private key' | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEYS" | grep 'Public key' | awk '{print $3}')
    SHORT_ID=$(openssl rand -hex 6)

    cat <<EOF >$CONFIG_FILE
{
    "log": {
        "access": "none",
        "error": "/var/log/xray/error.log",
        "loglevel": "error",
        "dnsLog": false,
        "maskAddress": "half"
    },
    "dns": {
        "hosts": {
            "geosite:category-ads-all": [
                "::1",
                "127.0.0.1"
            ]
        },
        "servers": [
EOF

    for server in "${DNS_SERVERS[@]}"; do
        echo "            \"$server\"," >>$CONFIG_FILE
    done

    cat <<EOF >>$CONFIG_FILE
            "localhost"
        ]
    },
    "routing": {
        "domainStrategy": "IPIfNonMatch",
        "rules": [
            {
                "inboundTag": [
                    "dokodemo-in"
                ],
                "domain": [
                    "$DEST_SERVER_NAME"
                ],
                "outboundTag": "direct"
            },
            {
                "inboundTag": [
                    "dokodemo-in"
                ],
                "outboundTag": "block"
            },
            {
                "ip": [
                    "geoip:cn",
                    "geoip:private"
                ],
                "outboundTag": "block"
            },
            {
                "domain": [
                    "geosite:category-ads-all"
EOF

    if [[ "$BLOCK_PORN" == "y" ]]; then
        echo ", \"                    geosite:category-porn\"" >>$CONFIG_FILE
    fi

    if [[ "$BLOCK_TRACKER" == "y" ]]; then
        echo ", \"                    geosite:category-public-tracker\"" >>$CONFIG_FILE
    fi

    cat <<EOF >>$CONFIG_FILE
                ],
                "outboundTag": "block"
            }
        ]
    },
    "inbounds": [
        {
            "tag": "dokodemo-in",
            "port": 443,
            "protocol": "dokodemo-door",
            "settings": {
                "address": "127.0.0.1",
                "port": $PORT,
                "network": "tcp"
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        },
        {
            "listen": "::",
            "port": $PORT,
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": "$UUID",
                        "flow": "xtls-rprx-vision"
                    }
                ],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "dest": "$DEST_SERVER_NAME:443",
                    "serverNames": [
                        "$DEST_SERVER_NAME"
                    ],
                    "privateKey": "$PRIVATE_KEY",
                    "shortIds": [
                        "$SHORT_ID"
                    ],
                    "fingerprint": "chrome"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "routeOnly": true
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "tag": "direct"
        },
        {
            "protocol": "blackhole",
            "tag": "block"
        }
    ]
}
EOF

    green "Reality 协议配置文件创建成功。\n"
}

create_vless_link() {
    if [[ -f "$CONFIG_FILE" ]]; then
        UUID=$(jq -r '.inbounds[1].settings.clients[0].id' "$CONFIG_FILE")
        OUTBOUND_ADDRESS=$(jq -r '.inbounds[1].listen // ""' "$CONFIG_FILE")
        PORT=$(jq -r '.inbounds[1].port' "$CONFIG_FILE")
        DEST_SERVER_NAME=$(jq -r '.inbounds[1].streamSettings.realitySettings.dest' "$CONFIG_FILE" | cut -d':' -f1)
        PRIVATE_KEY=$(jq -r '.inbounds[1].streamSettings.realitySettings.privateKey' "$CONFIG_FILE")

        PUBLIC_KEY=$(xray x25519 -i "$PRIVATE_KEY" | grep 'Public key' | awk '{print $3}')
        SHORT_ID=$(jq -r '.inbounds[1].streamSettings.realitySettings.shortIds[0]' "$CONFIG_FILE")

        if [[ "$OUTBOUND_ADDRESS" =~ ^[0-9a-fA-F:]+$ ]]; then
            OUTBOUND_ADDRESS="[$OUTBOUND_ADDRESS]"
        fi

        VLESS_LINK="vless://${UUID}@${OUTBOUND_ADDRESS}:${PORT}?flow=xtls-rprx-vision&encryption=none&type=tcp&security=reality&sni=${DEST_SERVER_NAME}&fp=chrome&pbk=${PUBLIC_KEY}&sid=${SHORT_ID}&spx=/reality&#vless-reality"

        if [[ -n "$VLESS_LINK" ]]; then
            green "分享链接："
            echo "$VLESS_LINK"
        fi
    else
        red "配置文件不存在，无法生成 VLESS 链接。"
    fi
}

restart_service() {
    yellow "正在重新启动 Xray-core..."
    systemctl restart xray.service

    if [[ $? -ne 0 ]]; then
        red "重启 Xray-core 服务失败！"
        return
    fi

    if systemctl is-active --quiet xray.service; then
        green "Xray-core 服务重新启动成功！\n"
        echo -e "---------- 各文件所在位置 ----------"
        echo "  /usr/local/bin/xray"
        echo "  /usr/local/etc/xray/config.json"
        echo "  /usr/local/share/xray/geoip.dat"
        echo "  /usr/local/share/xray/geosite.dat"
        echo "  /var/log/xray/error.log"
        echo "  /etc/systemd/system/xray.service"
        echo -e "------------------------------------\n"
    else
        red "Xray-core 服务启动失败！\n"
    fi
}

main() {
    welcome_msg
    check_root
    check_system
    install_dependencies
    get_latest_version
    check_installed_version
    install_xray
    setup_cron_job
    generate_config
    restart_service
    create_vless_link
}

main
