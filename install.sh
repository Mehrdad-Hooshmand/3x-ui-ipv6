#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
plain='\033[0m'

cur_dir=$(pwd)

xui_folder="${XUI_MAIN_FOLDER:=/usr/local/x-ui}"
xui_service="${XUI_SERVICE:=/etc/systemd/system}"

# check root
[[ $EUID -ne 0 ]] && echo -e "${red}Fatal error: ${plain} Please run this script with root privilege \n " && exit 1

# Check OS and set release variable
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
elif [[ -f /usr/lib/os-release ]]; then
    source /usr/lib/os-release
    release=$ID
else
    echo "Failed to check the system OS, please contact the author!" >&2
    exit 1
fi
echo "The OS release is: $release"

arch() {
    case "$(uname -m)" in
    x86_64 | x64 | amd64) echo 'amd64' ;;
    i*86 | x86) echo '386' ;;
    armv8* | armv8 | arm64 | aarch64) echo 'arm64' ;;
    armv7* | armv7 | arm) echo 'armv7' ;;
    armv6* | armv6) echo 'armv6' ;;
    armv5* | armv5) echo 'armv5' ;;
    s390x) echo 's390x' ;;
    *) echo -e "${green}Unsupported CPU architecture! ${plain}" && rm -f install.sh && exit 1 ;;
    esac
}

echo "Arch: $(arch)"

# Simple helpers
is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && return 0 || return 1
}

is_ipv6() {
    [[ "$1" =~ : ]] && return 0 || return 1
}

is_ip() {
    is_ipv4 "$1" || is_ipv6 "$1"
}

is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+[A-Za-z]{2,}$ ]] && return 0 || return 1
}

install_base() {
    case "${release}" in
    ubuntu | debian | armbian)
        apt-get update && apt-get install -y -q curl tar tzdata socat
        ;;
    fedora | amzn | virtuozzo | rhel | almalinux | rocky | ol)
        dnf -y update && dnf install -y -q curl tar tzdata socat
        ;;
    centos)
        if [[ "${VERSION_ID}" =~ ^7 ]]; then
            yum -y update && yum install -y curl tar tzdata socat
        else
            dnf -y update && dnf install -y -q curl tar tzdata socat
        fi
        ;;
    arch | manjaro | parch)
        pacman -Syu && pacman -Syu --noconfirm curl tar tzdata socat
        ;;
    opensuse-tumbleweed | opensuse-leap)
        zypper refresh && zypper -q install -y curl tar timezone socat
        ;;
    alpine)
        apk update && apk add curl tar tzdata socat
        ;;
    *)
        apt-get update && apt-get install -y -q curl tar tzdata socat
        ;;
    esac
}

gen_random_string() {
    local length="$1"
    local random_string=$(LC_ALL=C tr -dc 'a-zA-Z0-9' </dev/urandom | fold -w "$length" | head -n 1)
    echo "$random_string"
}

install_acme() {
    echo -e "${green}Installing acme.sh for SSL certificate management...${plain}"
    cd ~ || return 1
    curl -s https://get.acme.sh | sh
    if [ $? -ne 0 ]; then
        echo -e "${red}Failed to install acme.sh${plain}"
        return 1
    else
        # Source the acme.sh environment
        source ~/.bashrc 2>/dev/null || true
        echo -e "${green}acme.sh installed successfully${plain}"
    fi
    return 0
}

setup_ssl_certificate() {
    local domain="$1"
    local server_ip="$2"
    local existing_port="$3"
    local existing_webBasePath="$4"
    
    echo -e "${green}Setting up SSL certificate...${plain}"
    
    # Check if acme.sh is installed
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${yellow}Failed to install acme.sh, skipping SSL setup${plain}"
            return 1
        fi
    fi
    
    # Create certificate directory
    local certPath="/root/cert/${domain}"
    mkdir -p "$certPath"
    
    # Issue certificate
    echo -e "${green}Issuing SSL certificate for ${domain}...${plain}"
    echo -e "${yellow}Note: Port 80 must be open and accessible from the internet${plain}"
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport 80 --force
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Failed to issue certificate for ${domain}${plain}"
        echo -e "${yellow}Please ensure port 80 is open and try again later with: x-ui${plain}"
        rm -rf ~/.acme.sh/${domain} 2>/dev/null
        rm -rf "$certPath" 2>/dev/null
        return 1
    fi
    
    # Install certificate
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem \
        --reloadcmd "systemctl restart x-ui" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Failed to install certificate${plain}"
        return 1
    fi
    
    # Enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1
    
    # Secure permissions: private key readable only by owner
    chmod 600 $certPath/privkey.pem 2>/dev/null
    chmod 644 $certPath/fullchain.pem 2>/dev/null
    
    # Set certificate for panel
    local webCertFile="/root/cert/${domain}/fullchain.pem"
    local webKeyFile="/root/cert/${domain}/privkey.pem"
    
    if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
        ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile" >/dev/null 2>&1
        echo -e "${green}SSL certificate installed and configured successfully!${plain}"
        return 0
    else
        echo -e "${yellow}Certificate files not found${plain}"
        return 1
    fi
}

setup_ipv6_only_certificate() {
    local ipv6="$1"

    echo -e "${green}Setting up Let's Encrypt IPv6 certificate (shortlived profile)...${plain}"
    echo -e "${yellow}Note: IP certificates are valid for ~6 days and will auto-renew.${plain}"
    echo -e "${yellow}Port 80 must be open and accessible from the internet.${plain}"

    # Check for acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${red}Failed to install acme.sh${plain}"
            return 1
        fi
    fi

    # Validate IPv6 address
    if [[ -z "$ipv6" ]]; then
        echo -e "${red}IPv6 address is required${plain}"
        return 1
    fi

    if ! is_ipv6 "$ipv6"; then
        echo -e "${red}Invalid IPv6 address: $ipv6${plain}"
        return 1
    fi

    # Create certificate directory
    local certDir="/root/cert/ip"
    mkdir -p "$certDir"

    # Set reload command
    local reloadCmd="systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null || true"

    # Stop panel if running
    if [[ $release == "alpine" ]]; then
        rc-service x-ui stop >/dev/null 2>&1
    else
        systemctl stop x-ui >/dev/null 2>&1
    fi

    # Issue certificate for IPv6
    echo -e "${green}Issuing IPv6 certificate for [${ipv6}]...${plain}"
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    
    ~/.acme.sh/acme.sh --issue \
        -d "${ipv6}" \
        --standalone \
        --listen-v6 \
        --server letsencrypt \
        --certificate-profile shortlived \
        --days 6 \
        --httpport 80 \
        --force

    if [ $? -ne 0 ]; then
        echo -e "${red}Failed to issue IPv6 certificate${plain}"
        echo -e "${yellow}Please ensure port 80 is open and accessible from the internet${plain}"
        rm -rf ~/.acme.sh/${ipv6} 2>/dev/null
        rm -rf ${certDir} 2>/dev/null
        return 1
    fi

    echo -e "${green}Certificate issued successfully, installing...${plain}"

    # Install certificate
    ~/.acme.sh/acme.sh --installcert -d "${ipv6}" \
        --key-file "${certDir}/privkey.pem" \
        --fullchain-file "${certDir}/fullchain.pem" \
        --reloadcmd "${reloadCmd}" 2>&1 || true

    # Verify certificate files exist
    if [[ ! -f "${certDir}/fullchain.pem" || ! -f "${certDir}/privkey.pem" ]]; then
        echo -e "${red}Certificate files not found after installation${plain}"
        rm -rf ~/.acme.sh/${ipv6} 2>/dev/null
        rm -rf ${certDir} 2>/dev/null
        return 1
    fi
    
    echo -e "${green}Certificate files installed successfully${plain}"

    # Enable auto-upgrade
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1

    # Secure permissions
    chmod 600 ${certDir}/privkey.pem 2>/dev/null
    chmod 644 ${certDir}/fullchain.pem 2>/dev/null

    # Configure panel
    echo -e "${green}Setting certificate paths for the panel...${plain}"
    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem"
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Warning: Could not set certificate paths automatically${plain}"
    else
        echo -e "${green}Certificate paths configured successfully${plain}"
    fi

    echo -e "${green}IPv6 certificate installed and configured successfully!${plain}"
    return 0
}

setup_ip_certificate() {
    local ipv4="$1"
    local ipv6="$2"  # optional

    echo -e "${green}Setting up Let's Encrypt IP certificate (shortlived profile)...${plain}"
    echo -e "${yellow}Note: IP certificates are valid for ~6 days and will auto-renew.${plain}"
    echo -e "${yellow}Port 80 must be open and accessible from the internet.${plain}"

    # Check for acme.sh
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        install_acme
        if [ $? -ne 0 ]; then
            echo -e "${red}Failed to install acme.sh${plain}"
            return 1
        fi
    fi

    # Validate IP address
    if [[ -z "$ipv4" ]]; then
        echo -e "${red}IPv4 address is required${plain}"
        return 1
    fi

    if ! is_ipv4 "$ipv4"; then
        echo -e "${red}Invalid IPv4 address: $ipv4${plain}"
        return 1
    fi

    # Create certificate directory
    local certDir="/root/cert/ip"
    mkdir -p "$certDir"

    # Build domain arguments
    local domain_args="-d ${ipv4}"
    if [[ -n "$ipv6" ]] && is_ipv6 "$ipv6"; then
        domain_args="${domain_args} -d ${ipv6}"
        echo -e "${green}Including IPv6 address: ${ipv6}${plain}"
    fi

    # Set reload command for auto-renewal
    local reloadCmd="systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null || true"

    # Issue certificate with shortlived profile
    echo -e "${green}Issuing IP certificate for ${ipv4}...${plain}"
    
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
    
    ~/.acme.sh/acme.sh --issue \
        ${domain_args} \
        --standalone \
        --server letsencrypt \
        --certificate-profile shortlived \
        --days 6 \
        --httpport 80 \
        --force

    if [ $? -ne 0 ]; then
        echo -e "${red}Failed to issue IP certificate${plain}"
        echo -e "${yellow}Please ensure port 80 is open and accessible from the internet${plain}"
        rm -rf ~/.acme.sh/${ipv4} 2>/dev/null
        [[ -n "$ipv6" ]] && rm -rf ~/.acme.sh/${ipv6} 2>/dev/null
        rm -rf ${certDir} 2>/dev/null
        return 1
    fi

    echo -e "${green}Certificate issued successfully, installing...${plain}"

    # Install certificate
    ~/.acme.sh/acme.sh --installcert -d ${ipv4} \
        --key-file "${certDir}/privkey.pem" \
        --fullchain-file "${certDir}/fullchain.pem" \
        --reloadcmd "${reloadCmd}" 2>&1 || true

    # Verify certificate files exist
    if [[ ! -f "${certDir}/fullchain.pem" || ! -f "${certDir}/privkey.pem" ]]; then
        echo -e "${red}Certificate files not found after installation${plain}"
        rm -rf ~/.acme.sh/${ipv4} 2>/dev/null
        [[ -n "$ipv6" ]] && rm -rf ~/.acme.sh/${ipv6} 2>/dev/null
        rm -rf ${certDir} 2>/dev/null
        return 1
    fi
    
    echo -e "${green}Certificate files installed successfully${plain}"

    # Enable auto-upgrade for acme.sh
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade >/dev/null 2>&1

    # Secure permissions
    chmod 600 ${certDir}/privkey.pem 2>/dev/null
    chmod 644 ${certDir}/fullchain.pem 2>/dev/null

    # Configure panel to use the certificate
    echo -e "${green}Setting certificate paths for the panel...${plain}"
    ${xui_folder}/x-ui cert -webCert "${certDir}/fullchain.pem" -webCertKey "${certDir}/privkey.pem"
    
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Warning: Could not set certificate paths automatically${plain}"
        echo -e "${yellow}Certificate files are at:${plain}"
        echo -e "  Cert: ${certDir}/fullchain.pem"
        echo -e "  Key: ${certDir}/privkey.pem"
    else
        echo -e "${green}Certificate paths configured successfully${plain}"
    fi

    echo -e "${green}IP certificate installed and configured successfully!${plain}"
    echo -e "${green}Certificate valid for ~6 days, auto-renews via acme.sh cron job.${plain}"
    echo -e "${yellow}acme.sh will automatically renew and reload x-ui before expiry.${plain}"
    return 0
}

ssl_cert_issue() {
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep 'webBasePath:' | awk -F': ' '{print $2}' | tr -d '[:space:]' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep 'port:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    
    # check for acme.sh first
    if ! command -v ~/.acme.sh/acme.sh &>/dev/null; then
        echo "acme.sh could not be found. Installing now..."
        cd ~ || return 1
        curl -s https://get.acme.sh | sh
        if [ $? -ne 0 ]; then
            echo -e "${red}Failed to install acme.sh${plain}"
            return 1
        else
            echo -e "${green}acme.sh installed successfully${plain}"
        fi
    fi

    # get the domain here
    local domain=""
    while true; do
        read -rp "Please enter your domain name: " domain
        domain="${domain// /}"  # Trim whitespace
        
        if [[ -z "$domain" ]]; then
            echo -e "${red}Domain name cannot be empty. Please try again.${plain}"
            continue
        fi
        
        if ! is_domain "$domain"; then
            echo -e "${red}Invalid domain format: ${domain}. Please enter a valid domain name.${plain}"
            continue
        fi
        
        break
    done
    echo -e "${green}Your domain is: ${domain}, checking it...${plain}"

    # check if there already exists a certificate
    local currentCert=$(~/.acme.sh/acme.sh --list | tail -1 | awk '{print $1}')
    if [ "${currentCert}" == "${domain}" ]; then
        local certInfo=$(~/.acme.sh/acme.sh --list)
        echo -e "${red}System already has certificates for this domain. Cannot issue again.${plain}"
        echo -e "${yellow}Current certificate details:${plain}"
        echo "$certInfo"
        return 1
    else
        echo -e "${green}Your domain is ready for issuing certificates now...${plain}"
    fi

    # create a directory for the certificate
    certPath="/root/cert/${domain}"
    if [ ! -d "$certPath" ]; then
        mkdir -p "$certPath"
    else
        rm -rf "$certPath"
        mkdir -p "$certPath"
    fi

    # get the port number
    local WebPort=80
    read -rp "Please choose which port to use (default is 80): " WebPort
    if [[ ${WebPort} -gt 65535 || ${WebPort} -lt 1 ]]; then
        echo -e "${yellow}Your input ${WebPort} is invalid, will use default port 80.${plain}"
        WebPort=80
    fi
    echo -e "${green}Will use port: ${WebPort} to issue certificates. Please make sure this port is open.${plain}"

    # Stop panel temporarily
    echo -e "${yellow}Stopping panel temporarily...${plain}"
    systemctl stop x-ui 2>/dev/null || rc-service x-ui stop 2>/dev/null

    # issue the certificate
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d ${domain} --listen-v6 --standalone --httpport ${WebPort} --force
    if [ $? -ne 0 ]; then
        echo -e "${red}Issuing certificate failed, please check logs.${plain}"
        rm -rf ~/.acme.sh/${domain}
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    else
        echo -e "${green}Issuing certificate succeeded, installing certificates...${plain}"
    fi

    # Setup reload command
    reloadCmd="systemctl restart x-ui || rc-service x-ui restart"
    echo -e "${green}Default --reloadcmd for ACME is: ${yellow}systemctl restart x-ui || rc-service x-ui restart${plain}"
    echo -e "${green}This command will run on every certificate issue and renew.${plain}"
    read -rp "Would you like to modify --reloadcmd for ACME? (y/n): " setReloadcmd
    if [[ "$setReloadcmd" == "y" || "$setReloadcmd" == "Y" ]]; then
        echo -e "\n${green}\t1.${plain} Preset: systemctl reload nginx ; systemctl restart x-ui"
        echo -e "${green}\t2.${plain} Input your own command"
        echo -e "${green}\t0.${plain} Keep default reloadcmd"
        read -rp "Choose an option: " choice
        case "$choice" in
        1)
            echo -e "${green}Reloadcmd is: systemctl reload nginx ; systemctl restart x-ui${plain}"
            reloadCmd="systemctl reload nginx ; systemctl restart x-ui"
            ;;
        2)
            echo -e "${yellow}It's recommended to put x-ui restart at the end${plain}"
            read -rp "Please enter your custom reloadcmd: " reloadCmd
            echo -e "${green}Reloadcmd is: ${reloadCmd}${plain}"
            ;;
        *)
            echo -e "${green}Keeping default reloadcmd${plain}"
            ;;
        esac
    fi

    # install the certificate
    ~/.acme.sh/acme.sh --installcert -d ${domain} \
        --key-file /root/cert/${domain}/privkey.pem \
        --fullchain-file /root/cert/${domain}/fullchain.pem --reloadcmd "${reloadCmd}"

    if [ $? -ne 0 ]; then
        echo -e "${red}Installing certificate failed, exiting.${plain}"
        rm -rf ~/.acme.sh/${domain}
        systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null
        return 1
    else
        echo -e "${green}Installing certificate succeeded, enabling auto renew...${plain}"
    fi

    # enable auto-renew
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    if [ $? -ne 0 ]; then
        echo -e "${yellow}Auto renew setup had issues, certificate details:${plain}"
        ls -lah /root/cert/${domain}/
        chmod 600 $certPath/privkey.pem 2>/dev/null
        chmod 644 $certPath/fullchain.pem 2>/dev/null
    else
        echo -e "${green}Auto renew succeeded, certificate details:${plain}"
        ls -lah /root/cert/${domain}/
        chmod 600 $certPath/privkey.pem 2>/dev/null
        chmod 644 $certPath/fullchain.pem 2>/dev/null
    fi

    # start panel
    systemctl start x-ui 2>/dev/null || rc-service x-ui start 2>/dev/null

    # Prompt user to set panel paths
    read -rp "Would you like to set this certificate for the panel? (y/n): " setPanel
    if [[ "$setPanel" == "y" || "$setPanel" == "Y" ]]; then
        local webCertFile="/root/cert/${domain}/fullchain.pem"
        local webKeyFile="/root/cert/${domain}/privkey.pem"

        if [[ -f "$webCertFile" && -f "$webKeyFile" ]]; then
            ${xui_folder}/x-ui cert -webCert "$webCertFile" -webCertKey "$webKeyFile"
            echo -e "${green}Certificate paths set for the panel${plain}"
            echo -e "${green}Certificate File: $webCertFile${plain}"
            echo -e "${green}Private Key File: $webKeyFile${plain}"
            echo ""
            echo -e "${green}Access URL: https://${domain}:${existing_port}/${existing_webBasePath}${plain}"
            echo -e "${yellow}Panel will restart to apply SSL certificate...${plain}"
            systemctl restart x-ui 2>/dev/null || rc-service x-ui restart 2>/dev/null
        else
            echo -e "${red}Error: Certificate or private key file not found for domain: $domain.${plain}"
        fi
    else
        echo -e "${yellow}Skipping panel path setting.${plain}"
    fi
    
    return 0
}

prompt_and_setup_ssl() {
    local panel_port="$1"
    local web_base_path="$2"
    local server_ip="$3"

    local ssl_choice=""

    echo -e "${yellow}Choose SSL certificate setup method:${plain}"
    
    # Check if domain is configured
    if [[ "${PANEL_USE_DOMAIN}" == "true" && -n "${PANEL_HOST}" ]]; then
        echo -e "${green}✓ Domain detected: ${PANEL_HOST}${plain}"
        echo ""
        echo -e "${green}1.${plain} Let's Encrypt for Domain (90-day validity, auto-renews)"
        echo -e "${green}2.${plain} Skip SSL setup"
        read -rp "Choose an option (default 1): " ssl_choice
        ssl_choice="${ssl_choice// /}"
        
        [[ -z "${ssl_choice}" ]] && ssl_choice="1"
        
        if [[ "${ssl_choice}" == "1" ]]; then
            echo -e "${green}Setting up SSL for domain: ${PANEL_HOST}${plain}"
            # Use domain SSL setup
            setup_ssl_certificate "${PANEL_HOST}" "${server_ip}" "${panel_port}" "${web_base_path}"
            SSL_HOST="${PANEL_HOST}"
        else
            echo -e "${yellow}Skipping SSL setup${plain}"
            SSL_HOST="${PANEL_HOST}"
        fi
    else
        # IP-based panel - use PANEL_SERVER_IP instead of PANEL_HOST
        local actual_ip="${PANEL_SERVER_IP:-${server_ip}}"
        echo -e "${green}Panel configured with IP: ${actual_ip}${plain}"
        echo ""
        echo -e "${green}1.${plain} Let's Encrypt for IP Address (6-day validity, auto-renews)"
        echo -e "${green}2.${plain} Skip SSL setup"
        echo -e "${blue}Note:${plain} IP certificates require port 80 open and use shortlived profile."
        read -rp "Choose an option (default 1): " ssl_choice
        ssl_choice="${ssl_choice// /}"
        
        [[ -z "${ssl_choice}" ]] && ssl_choice="1"
        
        if [[ "${ssl_choice}" == "1" ]]; then
            echo -e "${green}Setting up SSL for IP: ${actual_ip}${plain}"
            
            # Stop panel if running
            if [[ $release == "alpine" ]]; then
                rc-service x-ui stop >/dev/null 2>&1
            else
                systemctl stop x-ui >/dev/null 2>&1
            fi
            
            # Check if server_ip is IPv6
            if is_ipv6 "${actual_ip}"; then
                echo -e "${green}✓ IPv6 detected${plain}"
                setup_ipv6_only_certificate "${actual_ip}"
            else
                # IPv4 - check if user also has IPv6
                if [[ -n "${detected_ipv6}" ]]; then
                    echo ""
                    read -rp "Do you also want to add IPv6 (${detected_ipv6}) to certificate? (y/n, default n): " add_ipv6
                    if [[ "${add_ipv6}" == "y" || "${add_ipv6}" == "Y" ]]; then
                        setup_ip_certificate "${actual_ip}" "${detected_ipv6}"
                    else
                        setup_ip_certificate "${actual_ip}" ""
                    fi
                else
                    setup_ip_certificate "${actual_ip}" ""
                fi
            fi
            
            if [ $? -eq 0 ]; then
                SSL_HOST="${actual_ip}"
                echo -e "${green}✓ SSL certificate configured successfully${plain}"
            else
                echo -e "${red}✗ SSL setup failed${plain}"
                SSL_HOST="${actual_ip}"
            fi
        else
            echo -e "${yellow}Skipping SSL setup${plain}"
            SSL_HOST="${actual_ip}"
        fi
    fi
}

# ============================================================================
# MODIFIED: Clean Installation Flow with IPv6 Support
# ============================================================================

detect_server_ips() {
    # Try IPv4
    local URL_lists_v4=(
        "https://api4.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.api.ipinfo.io/ip"
        "https://4.ident.me"
    )
    
    # Try IPv6
    local URL_lists_v6=(
        "https://api6.ipify.org"
        "https://ipv6.icanhazip.com"
        "https://v6.api.ipinfo.io/ip"
        "https://6.ident.me"
    )
    
    detected_ipv4=""
    detected_ipv6=""
    
    echo -e "${yellow}Detecting server IPs...${plain}"
    
    # Get IPv4
    for ip_address in "${URL_lists_v4[@]}"; do
        detected_ipv4=$(curl -4 -s --max-time 3 "${ip_address}" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "${detected_ipv4}" ]]; then
            break
        fi
    done
    
    # Get IPv6
    for ip_address in "${URL_lists_v6[@]}"; do
        detected_ipv6=$(curl -6 -s --max-time 3 "${ip_address}" 2>/dev/null | tr -d '[:space:]')
        if [[ -n "${detected_ipv6}" ]]; then
            break
        fi
    done
    
    if [[ -n "${detected_ipv4}" ]]; then
        echo -e "${green}✓ IPv4 detected: ${detected_ipv4}${plain}"
    fi
    
    if [[ -n "${detected_ipv6}" ]]; then
        echo -e "${green}✓ IPv6 detected: ${detected_ipv6}${plain}"
    fi
    
    if [[ -z "${detected_ipv4}" && -z "${detected_ipv6}" ]]; then
        echo -e "${yellow}⚠ No IP auto-detected${plain}"
    fi
}

ask_for_panel_ip() {
    echo ""
    echo -e "${green}═══════════════════════════════════════════════${plain}"
    echo -e "${green}       3X-UI Panel Installation Setup        ${plain}"
    echo -e "${green}═══════════════════════════════════════════════${plain}"
    echo ""
    
    # Step 1: Detect IPs
    detect_server_ips
    
    echo ""
    echo -e "${blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${plain}"
    echo -e "${yellow}STEP 1: Select IP Type${plain}"
    echo -e "${blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${plain}"
    echo ""
    echo -e "${green}1.${plain} IPv4"
    echo -e "${green}2.${plain} IPv6"
    echo ""
    read -rp "Choose IP type (1 or 2): " ip_type
    ip_type="${ip_type// /}"
    
    # Validate choice
    if [[ "${ip_type}" != "1" && "${ip_type}" != "2" ]]; then
        echo -e "${yellow}Invalid choice, defaulting to IPv4${plain}"
        ip_type="1"
    fi
    
    # Step 2: Enter and confirm IP
    echo ""
    echo -e "${blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${plain}"
    echo -e "${yellow}STEP 2: Enter Your Server IP${plain}"
    echo -e "${blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${plain}"
    echo ""
    
    local suggested_ip=""
    if [[ "${ip_type}" == "1" ]]; then
        echo -e "${yellow}Selected: IPv4${plain}"
        if [[ -n "${detected_ipv4}" ]]; then
            suggested_ip="${detected_ipv4}"
            echo -e "${green}Detected IPv4: ${suggested_ip}${plain}"
        fi
    else
        echo -e "${yellow}Selected: IPv6${plain}"
        if [[ -n "${detected_ipv6}" ]]; then
            suggested_ip="${detected_ipv6}"
            echo -e "${green}Detected IPv6: ${suggested_ip}${plain}"
        fi
    fi
    
    echo ""
    if [[ -n "${suggested_ip}" ]]; then
        read -rp "Enter your server IP (press Enter to use ${suggested_ip}): " user_ip
        user_ip="${user_ip// /}"
        if [[ -z "${user_ip}" ]]; then
            selected_panel_ip="${suggested_ip}"
            echo -e "${green}✓ Using detected IP: ${selected_panel_ip}${plain}"
        else
            selected_panel_ip="${user_ip}"
            echo -e "${green}✓ Using entered IP: ${selected_panel_ip}${plain}"
        fi
    else
        read -rp "Enter your server IP: " user_ip
        user_ip="${user_ip// /}"
        if [[ -z "${user_ip}" ]]; then
            echo -e "${red}✗ Error: IP cannot be empty!${plain}"
            exit 1
        fi
        selected_panel_ip="${user_ip}"
        echo -e "${green}✓ IP confirmed: ${selected_panel_ip}${plain}"
    fi
    
    # Validate IP format
    if [[ "${ip_type}" == "1" ]]; then
        if ! is_ipv4 "${selected_panel_ip}"; then
            echo -e "${red}✗ Error: Invalid IPv4 format!${plain}"
            exit 1
        fi
    else
        if ! is_ipv6 "${selected_panel_ip}"; then
            echo -e "${red}✗ Error: Invalid IPv6 format!${plain}"
            exit 1
        fi
    fi
    
    # Step 3: Choose panel host (IP or Domain)
    echo ""
    echo -e "${blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${plain}"
    echo -e "${yellow}STEP 3: Panel Access Configuration${plain}"
    echo -e "${blue}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${plain}"
    echo ""
    echo -e "${yellow}Do you want to access panel via IP or Domain?${plain}"
    echo ""
    echo -e "${green}1.${plain} IP Address  (https://${selected_panel_ip}:port/path)"
    echo -e "${green}2.${plain} Domain Name (https://yourdomain.com:port/path)"
    echo ""
    read -rp "Choose access method (1 or 2, default 1): " access_choice
    access_choice="${access_choice// /}"
    
    [[ -z "${access_choice}" ]] && access_choice="1"
    
    if [[ "${access_choice}" == "2" ]]; then
        # User wants domain
        echo ""
        echo -e "${yellow}Enter your domain name:${plain}"
        echo -e "${yellow}(Example: panel.example.com)${plain}"
        read -rp "Domain: " user_domain
        user_domain="${user_domain// /}"
        
        if [[ -z "${user_domain}" ]]; then
            echo -e "${yellow}⚠ No domain entered, using IP instead${plain}"
            panel_host="${selected_panel_ip}"
            use_domain=false
        elif ! is_domain "${user_domain}"; then
            echo -e "${yellow}⚠ Invalid domain format, using IP instead${plain}"
            panel_host="${selected_panel_ip}"
            use_domain=false
        else
            panel_host="${user_domain}"
            use_domain=true
            echo -e "${green}✓ Domain confirmed: ${panel_host}${plain}"
        fi
    else
        # User wants IP
        panel_host="${selected_panel_ip}"
        use_domain=false
        echo -e "${green}✓ Panel will be accessed via IP: ${panel_host}${plain}"
    fi
    
    # Summary
    echo ""
    echo -e "${green}═══════════════════════════════════════════════${plain}"
    echo -e "${green}           Configuration Summary             ${plain}"
    echo -e "${green}═══════════════════════════════════════════════${plain}"
    echo -e "${blue}Server IP:    ${green}${selected_panel_ip}${plain}"
    echo -e "${blue}Panel Host:   ${green}${panel_host}${plain}"
    if [[ "${use_domain}" == true ]]; then
        echo -e "${blue}Access Type:  ${green}Domain${plain}"
    else
        echo -e "${blue}Access Type:  ${green}IP Address${plain}"
    fi
    echo -e "${green}═══════════════════════════════════════════════${plain}"
    echo ""
    
    # Export for use in other functions
    export PANEL_SERVER_IP="${selected_panel_ip}"
    export PANEL_HOST="${panel_host}"
    export PANEL_USE_DOMAIN="${use_domain}"
    
    # Return the server IP (for backwards compatibility)
    echo "${selected_panel_ip}"
}

# ============================================================================
# Main Configuration Function
# ============================================================================

config_after_install() {
    local existing_hasDefaultCredential=$(${xui_folder}/x-ui setting -show true | grep -Eo 'hasDefaultCredential: .+' | awk '{print $2}')
    local existing_webBasePath=$(${xui_folder}/x-ui setting -show true | grep -Eo 'webBasePath: .+' | awk '{print $2}' | sed 's#^/##')
    local existing_port=$(${xui_folder}/x-ui setting -show true | grep -Eo 'port: .+' | awk '{print $2}')
    local existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
    
    # MODIFIED: Ask user for panel IP (supports IPv6)
    local server_ip=$(ask_for_panel_ip)

    if [[ ${#existing_webBasePath} -lt 4 ]]; then
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_webBasePath=$(gen_random_string 18)
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            
            read -rp "Would you like to customize the Panel Port settings? (If not, a random port will be applied) [y/n]: " config_confirm
            if [[ "${config_confirm}" == "y" || "${config_confirm}" == "Y" ]]; then
                read -rp "Please set up the panel port: " config_port
                echo -e "${yellow}Your Panel Port is: ${config_port}${plain}"
            else
                local config_port=$(shuf -i 1024-62000 -n 1)
                echo -e "${yellow}Generated random port: ${config_port}${plain}"
            fi
            
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}" -port "${config_port}" -webBasePath "${config_webBasePath}"
            
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL Certificate Setup (MANDATORY)     ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}For security, SSL certificate is required for all panels.${plain}"
            echo -e "${yellow}Let's Encrypt now supports both domains and IP addresses!${plain}"
            echo ""

            prompt_and_setup_ssl "${config_port}" "${config_webBasePath}" "${server_ip}"
            
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     Panel Installation Complete!         ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}Username:    ${config_username}${plain}"
            echo -e "${green}Password:    ${config_password}${plain}"
            echo -e "${green}Port:        ${config_port}${plain}"
            echo -e "${green}WebBasePath: ${config_webBasePath}${plain}"
            echo -e "${green}Access URL:  https://${SSL_HOST}:${config_port}/${config_webBasePath}${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}⚠ IMPORTANT: Save these credentials securely!${plain}"
            echo -e "${yellow}⚠ SSL Certificate: Enabled and configured${plain}"
        else
            local config_webBasePath=$(gen_random_string 18)
            echo -e "${yellow}WebBasePath is missing or too short. Generating a new one...${plain}"
            ${xui_folder}/x-ui setting -webBasePath "${config_webBasePath}"
            echo -e "${green}New WebBasePath: ${config_webBasePath}${plain}"

            if [[ -z "${existing_cert}" ]]; then
                echo ""
                echo -e "${green}═══════════════════════════════════════════${plain}"
                echo -e "${green}     SSL Certificate Setup (RECOMMENDED)   ${plain}"
                echo -e "${green}═══════════════════════════════════════════${plain}"
                echo -e "${yellow}Let's Encrypt now supports both domains and IP addresses!${plain}"
                echo ""
                prompt_and_setup_ssl "${existing_port}" "${config_webBasePath}" "${server_ip}"
                echo -e "${green}Access URL:  https://${SSL_HOST}:${existing_port}/${config_webBasePath}${plain}"
            else
                echo -e "${green}Access URL: https://${server_ip}:${existing_port}/${config_webBasePath}${plain}"
            fi
        fi
    else
        if [[ "$existing_hasDefaultCredential" == "true" ]]; then
            local config_username=$(gen_random_string 10)
            local config_password=$(gen_random_string 10)
            
            echo -e "${yellow}Default credentials detected. Security update required...${plain}"
            ${xui_folder}/x-ui setting -username "${config_username}" -password "${config_password}"
            echo -e "Generated new random login credentials:"
            echo -e "###############################################"
            echo -e "${green}Username: ${config_username}${plain}"
            echo -e "${green}Password: ${config_password}${plain}"
            echo -e "###############################################"
        else
            echo -e "${green}Username, Password, and WebBasePath are properly set.${plain}"
        fi

        existing_cert=$(${xui_folder}/x-ui setting -getCert true | grep 'cert:' | awk -F': ' '{print $2}' | tr -d '[:space:]')
        if [[ -z "$existing_cert" ]]; then
            echo ""
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${green}     SSL Certificate Setup (RECOMMENDED)   ${plain}"
            echo -e "${green}═══════════════════════════════════════════${plain}"
            echo -e "${yellow}Let's Encrypt now supports both domains and IP addresses!${plain}"
            echo ""
            prompt_and_setup_ssl "${existing_port}" "${existing_webBasePath}" "${server_ip}"
            echo -e "${green}Access URL: https://${SSL_HOST}:${existing_port}/${existing_webBasePath}${plain}"
        else
            echo -e "${green}SSL certificate already configured. No action needed.${plain}"
        fi
    fi
    
    ${xui_folder}/x-ui migrate
}

install_x-ui() {
    cd ${xui_folder%/x-ui}/
    
    if [ $# == 0 ]; then
        tag_version=$(curl -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
        if [[ ! -n "$tag_version" ]]; then
            echo -e "${yellow}Trying to fetch version with IPv4...${plain}"
            tag_version=$(curl -4 -Ls "https://api.github.com/repos/MHSanaei/3x-ui/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            if [[ ! -n "$tag_version" ]]; then
                echo -e "${red}Failed to fetch x-ui version, it may be due to GitHub API restrictions, please try it later${plain}"
                exit 1
            fi
        fi
        echo -e "Got x-ui latest version: ${tag_version}, beginning the installation..."
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Downloading x-ui failed, please be sure that your server can access GitHub ${plain}"
            exit 1
        fi
    else
        tag_version=$1
        tag_version_numeric=${tag_version#v}
        min_version="2.3.5"
        
        if [[ "$(printf '%s\n' "$min_version" "$tag_version_numeric" | sort -V | head -n1)" != "$min_version" ]]; then
            echo -e "${red}Please use a newer version (at least v2.3.5). Exiting installation.${plain}"
            exit 1
        fi
        
        url="https://github.com/MHSanaei/3x-ui/releases/download/${tag_version}/x-ui-linux-$(arch).tar.gz"
        echo -e "Beginning to install x-ui $1"
        curl -4fLRo ${xui_folder}-linux-$(arch).tar.gz ${url}
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Download x-ui $1 failed, please check if the version exists ${plain}"
            exit 1
        fi
    fi
    
    curl -4fLRo /usr/bin/x-ui-temp https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.sh
    if [[ $? -ne 0 ]]; then
        echo -e "${red}Failed to download x-ui.sh${plain}"
        exit 1
    fi
    
    # Stop x-ui service and remove old resources
    if [[ -e ${xui_folder}/ ]]; then
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop
        else
            systemctl stop x-ui
        fi
        rm ${xui_folder}/ -rf
    fi
    
    # Extract resources
    tar zxvf x-ui-linux-$(arch).tar.gz
    rm x-ui-linux-$(arch).tar.gz -f
    
    cd x-ui
    chmod +x x-ui
    chmod +x x-ui.sh
    
    if [[ $(arch) == "armv5" || $(arch) == "armv6" || $(arch) == "armv7" ]]; then
        mv bin/xray-linux-$(arch) bin/xray-linux-arm
        chmod +x bin/xray-linux-arm
    fi
    chmod +x x-ui bin/xray-linux-$(arch)
    
    mv -f /usr/bin/x-ui-temp /usr/bin/x-ui
    chmod +x /usr/bin/x-ui
    mkdir -p /var/log/x-ui
    
    config_after_install

    # Etckeeper compatibility
    if [ -d "/etc/.git" ]; then
        if [ -f "/etc/.gitignore" ]; then
            if ! grep -q "x-ui/x-ui.db" "/etc/.gitignore"; then
                echo "" >> "/etc/.gitignore"
                echo "x-ui/x-ui.db" >> "/etc/.gitignore"
                echo -e "${green}Added x-ui.db to /etc/.gitignore for etckeeper${plain}"
            fi
        else
            echo "x-ui/x-ui.db" > "/etc/.gitignore"
            echo -e "${green}Created /etc/.gitignore and added x-ui.db for etckeeper${plain}"
        fi
    fi
    
    if [[ $release == "alpine" ]]; then
        curl -4fLRo /etc/init.d/x-ui https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.rc
        if [[ $? -ne 0 ]]; then
            echo -e "${red}Failed to download x-ui.rc${plain}"
            exit 1
        fi
        chmod +x /etc/init.d/x-ui
        rc-update add x-ui
        rc-service x-ui start
    else
        service_installed=false
        
        if [ -f "x-ui.service" ]; then
            echo -e "${green}Found x-ui.service in extracted files, installing...${plain}"
            cp -f x-ui.service ${xui_service}/ >/dev/null 2>&1
            if [[ $? -eq 0 ]]; then
                service_installed=true
            fi
        fi
        
        if [ "$service_installed" = false ]; then
            case "${release}" in
                ubuntu | debian | armbian)
                    if [ -f "x-ui.service.debian" ]; then
                        echo -e "${green}Found x-ui.service.debian in extracted files, installing...${plain}"
                        cp -f x-ui.service.debian ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
                *)
                    if [ -f "x-ui.service.rhel" ]; then
                        echo -e "${green}Found x-ui.service.rhel in extracted files, installing...${plain}"
                        cp -f x-ui.service.rhel ${xui_service}/x-ui.service >/dev/null 2>&1
                        if [[ $? -eq 0 ]]; then
                            service_installed=true
                        fi
                    fi
                ;;
            esac
        fi
        
        if [ "$service_installed" = false ]; then
            echo -e "${yellow}Service files not found in tar.gz, downloading from GitHub...${plain}"
            case "${release}" in
                ubuntu | debian | armbian)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.debian >/dev/null 2>&1
                ;;
                *)
                    curl -4fLRo ${xui_service}/x-ui.service https://raw.githubusercontent.com/MHSanaei/3x-ui/main/x-ui.service.rhel >/dev/null 2>&1
                ;;
            esac
            
            if [[ $? -ne 0 ]]; then
                echo -e "${red}Failed to install x-ui.service from GitHub${plain}"
                exit 1
            fi
            service_installed=true
        fi
        
        if [ "$service_installed" = true ]; then
            echo -e "${green}Setting up systemd unit...${plain}"
            chown root:root ${xui_service}/x-ui.service >/dev/null 2>&1
            chmod 644 ${xui_service}/x-ui.service >/dev/null 2>&1
            systemctl daemon-reload
            systemctl enable x-ui
            systemctl start x-ui
        else
            echo -e "${red}Failed to install x-ui.service file${plain}"
            exit 1
        fi
    fi
    
    echo -e "${green}x-ui ${tag_version}${plain} installation finished, it is running now..."
    echo -e ""
    echo -e "┌───────────────────────────────────────────────────────┐"
    echo -e "│  ${blue}x-ui control menu usages (subcommands):${plain}              │"
    echo -e "│                                                       │"
    echo -e "│  ${blue}x-ui${plain}              - Admin Management Script          │"
    echo -e "│  ${blue}x-ui start${plain}        - Start                            │"
    echo -e "│  ${blue}x-ui stop${plain}         - Stop                             │"
    echo -e "│  ${blue}x-ui restart${plain}      - Restart                          │"
    echo -e "│  ${blue}x-ui status${plain}       - Current Status                   │"
    echo -e "│  ${blue}x-ui settings${plain}     - Current Settings                 │"
    echo -e "│  ${blue}x-ui enable${plain}       - Enable Autostart on OS Startup   │"
    echo -e "│  ${blue}x-ui disable${plain}      - Disable Autostart on OS Startup  │"
    echo -e "│  ${blue}x-ui log${plain}          - Check logs                       │"
    echo -e "│  ${blue}x-ui banlog${plain}       - Check Fail2ban ban logs          │"
    echo -e "│  ${blue}x-ui update${plain}       - Update                           │"
    echo -e "│  ${blue}x-ui legacy${plain}       - Legacy version                   │"
    echo -e "│  ${blue}x-ui install${plain}      - Install                          │"
    echo -e "│  ${blue}x-ui uninstall${plain}    - Uninstall                        │"
    echo -e "└───────────────────────────────────────────────────────┘"
}

echo -e "${green}Running...${plain}"
install_base
install_x-ui $1
