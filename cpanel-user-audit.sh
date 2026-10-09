#!/usr/bin/env bash

# cPanel / CloudLinux / LiteSpeed / Apache / WordPress Audit
# Read-only diagnostic script
#
# Usage:
#   chmod 750 /root/audit-v2.sh
#   /root/audit-v2.sh CPANEL_USER
#
# Optional:
#   AUDIT_UA="TorobBot" /root/audit-v2.sh CPANEL_USER
#   CF_API_TOKEN="..." CF_ZONE_ID="..." /root/audit-v2.sh CPANEL_USER

set -uo pipefail

SCRIPT_NAME="$(basename "$0")"
USER_NAME="${1:-}"
AUDIT_UA="${AUDIT_UA:-TorobBot}"
START_TS="$(date +%s)"
HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"

declare -a FINDINGS=()
declare -a DOMAINS=()
declare -a DOCROOTS=()
declare -a WP_ROOTS=()
declare -a LOG_FILES=()

RED='\033[1;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
CYAN='\033[1;36m'
WHITE='\033[1;37m'
RESET='\033[0m'

section() {
    printf "\n${YELLOW}[%s]${RESET}\n" "$1"
}

subsection() {
    printf "${CYAN}--- %s ---${RESET}\n" "$1"
}

info() {
    printf "%s\n" "$*"
}

warn() {
    printf "${YELLOW}[WARN]${RESET} %s\n" "$*"
}

error() {
    printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2
}

finding() {
    local severity="$1"
    shift

    FINDINGS+=("${severity}|$*")

    case "$severity" in
        CRITICAL)
            printf "${RED}[CRITICAL]${RESET} %s\n" "$*"
            ;;
        HIGH)
            printf "${RED}[HIGH]${RESET} %s\n" "$*"
            ;;
        MEDIUM)
            printf "${YELLOW}[MEDIUM]${RESET} %s\n" "$*"
            ;;
        LOW)
            printf "${CYAN}[LOW]${RESET} %s\n" "$*"
            ;;
        INFO)
            printf "${GREEN}[INFO]${RESET} %s\n" "$*"
            ;;
    esac
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

run_as_user() {
    if command_exists runuser; then
        runuser -u "$USER_NAME" -- env \
            HOME="/home/$USER_NAME" \
            WP_CLI_CACHE_DIR="/home/$USER_NAME/.wp-cli/cache" \
            "$@"
    else
        su - "$USER_NAME" -s /bin/bash -c "$(printf '%q ' "$@")"
    fi
}

wp_run() {
    local root="$1"
    shift

    if ! command_exists wp; then
        return 127
    fi

    timeout 20 run_as_user wp "$@" --path="$root"
}

human_bytes() {
    awk -v bytes="${1:-0}" '
        function human(x) {
            if (x < 1024) return sprintf("%.0f B", x)
            if (x < 1024^2) return sprintf("%.2f KB", x/1024)
            if (x < 1024^3) return sprintf("%.2f MB", x/1024^2)
            if (x < 1024^4) return sprintf("%.2f GB", x/1024^3)
            return sprintf("%.2f TB", x/1024^4)
        }
        BEGIN { print human(bytes) }
    '
}

require_root() {
    if [ "${EUID:-9999}" -ne 0 ]; then
        error "This script must be executed as root."
        exit 1
    fi
}

validate_user() {
    if [ "$#" -ne 1 ]; then
        error "Usage: $SCRIPT_NAME <cpanel_username>"
        exit 1
    fi

    if [[ ! "$USER_NAME" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_-]{0,15}$ ]]; then
        error "Invalid cPanel username: $USER_NAME"
        exit 1
    fi

    if ! id "$USER_NAME" >/dev/null 2>&1; then
        error "User '$USER_NAME' does not exist."
        exit 1
    fi
}

check_dependencies() {
    local required=(
        awk
        grep
        sed
        sort
        uniq
        head
        tail
        cut
        find
        du
        df
        ps
        curl
        timeout
    )

    local missing=()

    for cmd in "${required[@]}"; do
        if ! command_exists "$cmd"; then
            missing+=("$cmd")
        fi
    done

    if [ "${#missing[@]}" -gt 0 ]; then
        warn "Missing commands: ${missing[*]}"
        warn "Some sections will be skipped."
    fi
}

detect_domains() {
    local domain user_line
    local true_domains="/etc/trueuserdomains"

    if [ -f "$true_domains" ]; then
        while IFS= read -r domain; do
            [ -n "$domain" ] || continue
            DOMAINS+=("$domain")
        done < <(
            awk -F: -v user="$USER_NAME" '
                $2 ~ "^[[:space:]]*" user "[[:space:]]*$" {
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $1)
                    print $1
                }
            ' "$true_domains"
        )
    fi

    # Fallback to cPanel user file.
    if [ "${#DOMAINS[@]}" -eq 0 ] && [ -f "/var/cpanel/users/$USER_NAME" ]; then
        domain="$(
            awk -F= '
                $1 == "DNS" || $1 == "DNS1" {
                    print $2
                    exit
                }
            ' "/var/cpanel/users/$USER_NAME"
        )"

        [ -n "$domain" ] && DOMAINS+=("$domain")
    fi

    # Final fallback.
    if [ "${#DOMAINS[@]}" -eq 0 ]; then
        DOMAINS+=("$USER_NAME.com")
        warn "Could not read cPanel domain mappings. Using fallback domain."
    fi

    # Remove duplicate domains.
    mapfile -t DOMAINS < <(printf '%s\n' "${DOMAINS[@]}" | awk 'NF && !seen[$0]++')
}

get_docroot_from_userdatadomains() {
    local domain="$1"
    local line field
    local result=""

    [ -f /etc/userdatadomains ] || return 1

    line="$(
        awk -F'==' -v domain="$domain" -v user="$USER_NAME" '
            $1 == domain {
                for (i = 1; i <= NF; i++) {
                    if ($i == user || $i ~ "^/home/" user "(/|$)") {
                        print $0
                        exit
                    }
                }
            }
        ' /etc/userdatadomains
    )"

    [ -n "$line" ] || return 1

    while IFS= read -r field; do
        if [[ "$field" == /home/"$USER_NAME"/* ]] && [ -d "$field" ]; then
            result="$field"
            break
        fi
    done < <(printf '%s\n' "$line" | tr '=' '\n' | sed '/^$/d')

    [ -n "$result" ] || return 1

    printf '%s\n' "$result"
}

detect_docroots() {
    local domain root

    for domain in "${DOMAINS[@]}"; do
        root="$(get_docroot_from_userdatadomains "$domain" 2>/dev/null || true)"

        if [ -z "$root" ]; then
            if [ "$domain" = "${DOMAINS[0]}" ]; then
                root="/home/$USER_NAME/public_html"
            else
                root="/home/$USER_NAME/$domain"
            fi
        fi

        DOMAINS_ROOTS+=("$domain"$'\t'"$root")
    done
}

declare -a DOMAINS_ROOTS=()

print_identity() {
    section "IDENTITY AND PATHS"

    printf "Host:       %s\n" "$HOSTNAME_SHORT"
    printf "User:       %s\n" "$USER_NAME"
    printf "UID:        %s\n" "$(id -u "$USER_NAME" 2>/dev/null)"
    printf "Home:       %s\n" "/home/$USER_NAME"

    subsection "Domains and document roots"

    while IFS=$'\t' read -r domain root; do
        [ -n "$domain" ] || continue

        printf "%-40s %s\n" "$domain" "$root"

        if [ ! -d "$root" ]; then
            finding HIGH "Document root does not exist: $domain -> $root"
        else
            DOCROOTS+=("$root")
        fi
    done < <(printf '%s\n' "${DOMAINS_ROOTS[@]}")
}

collect_log_files() {
    local domain file
    local -a candidates=()

    shopt -s nullglob

    for domain in "${DOMAINS[@]}"; do
        candidates=(
            "/etc/apache2/logs/domlogs/${domain}"
            "/etc/apache2/logs/domlogs/${domain}"*
            "/usr/local/apache/domlogs/${domain}"
            "/usr/local/apache/domlogs/${domain}"*
        )

        for file in "${candidates[@]}"; do
            [ -f "$file" ] || continue
            case "$file" in
                *.gz|*.offset) continue ;;
            esac
            LOG_FILES+=("$file")
        done
    done

    shopt -u nullglob

    mapfile -t LOG_FILES < <(
        printf '%s\n' "${LOG_FILES[@]}" |
        awk 'NF && !seen[$0]++'
    )
}

cache_headers_audit() {
    section "LIVE HTTP CACHE AND HEADERS"

    if ! command_exists curl; then
        warn "curl is not installed."
        return
    fi

    local domain output code total

    for domain in "${DOMAINS[@]}"; do
        subsection "$domain"

        printf "HEAD response:\n"
        curl -kILsS \
            --connect-timeout 5 \
            --max-time 15 \
            -A "$AUDIT_UA" \
            "https://$domain/" 2>/dev/null |
            grep -iE '^(HTTP/|cache-control:|x-cache:|x-litespeed:|x-litespeed-cache:|cf-cache-status:|cf-ray:|server:|set-cookie:|location:|retry-after:)' |
            sed 's/\r$//' |
            head -n 30

        output="$(
            curl -kLsS -o /dev/null \
                --connect-timeout 5 \
                --max-time 15 \
                -A "$AUDIT_UA" \
                -w 'code=%{http_code} connect=%{time_connect}s starttransfer=%{time_starttransfer}s total=%{time_total}s size=%{size_download}\n' \
                "https://$domain/" 2>/dev/null
        )"

        printf "GET timing: %s\n" "${output:-failed}"

        code="$(printf '%s' "$output" | sed -n 's/.*code=\([0-9]*\).*/\1/p')"

        case "$code" in
            403|406|409|429)
                finding HIGH "$domain returns HTTP $code for User-Agent '$AUDIT_UA'. Possible WAF/Bot protection."
                ;;
            5??)
                finding HIGH "$domain returns server error HTTP $code."
                ;;
            301|302)
                info "$domain redirects with HTTP $code."
                ;;
            200)
                info "$domain is reachable with HTTP 200."
                ;;
            "")
                finding HIGH "Could not connect to https://$domain/"
                ;;
        esac
    done
}

disk_and_inode_audit() {
    section "DISK, QUOTA, INODES AND LARGE DIRECTORIES"

    subsection "Filesystem"
    df -h "/home/$USER_NAME" 2>/dev/null || true
    df -ih "/home/$USER_NAME" 2>/dev/null || true

    subsection "cPanel quota"
    if command_exists repquota; then
        repquota -u "$USER_NAME" 2>/dev/null |
            awk -v user="$USER_NAME" '
                $0 ~ user {
                    print
                }
            ' || true
    else
        warn "repquota is not available."
    fi

    local used_kb inode_count
    used_kb="$(du -sk "/home/$USER_NAME" 2>/dev/null | awk '{print $1}')"
    inode_count="$(find "/home/$USER_NAME" -xdev -type f 2>/dev/null | wc -l)"

    printf "Home directory size: %s\n" "$(human_bytes "${used_kb:-0}" 2>/dev/null)"
    printf "Regular file count:  %s\n" "$inode_count"

    if [ "${inode_count:-0}" -gt 500000 ]; then
        finding HIGH "User has more than 500,000 regular files. Inode pressure is likely."
    elif [ "${inode_count:-0}" -gt 200000 ]; then
        finding MEDIUM "User has more than 200,000 regular files."
    fi

    subsection "Largest directories"

    local root
    for root in "${DOCROOTS[@]}"; do
        [ -d "$root" ] || continue

        printf "\n%s\n" "$root"

        timeout 30 du -xhd1 "$root" 2>/dev/null |
            sort -hr |
            head -n 15

        if [ -d "$root/wp-content" ]; then
            printf "\nwp-content:\n"
            timeout 30 du -xhd1 "$root/wp-content" 2>/dev/null |
                sort -hr |
                head -n 15
        fi
    done
}

php_server_audit() {
    section "PHP, LSAPI, PHP-FPM AND SERVER OVERRIDES"

    subsection "PHP binaries"

    if command_exists php; then
        php -v 2>/dev/null | head -n 2
        printf "PHP binary: %s\n" "$(command -v php)"
        php -m 2>/dev/null | tr '\n' ' '
        printf "\n"
    else
        warn "php command is not available."
    fi

    subsection "Running PHP processes"

    ps -eo user,pid,ppid,etime,%cpu,%mem,rss,args --sort=-%cpu 2>/dev/null |
        awk -v user="$USER_NAME" '
            NR == 1 || $1 == user && ($0 ~ /lsphp|php-fpm|php-cgi/)
        ' |
        head -n 20

    subsection "Configuration files"

    local root file found
    for root in "${DOCROOTS[@]}"; do
        for file in "$root/.user.ini" "$root/php.ini" "$root/.htaccess"; do
            [ -f "$file" ] || continue

            found=1
            printf "\n%s\n" "$file"

            grep -vE '^[[:space:]]*(#|;|$)' "$file" 2>/dev/null |
                grep -Ei 'memory_limit|max_execution_time|max_input_vars|auto_prepend|auto_append|opcache|php_value|php_flag|expiresbytype|rewritecond' |
                head -n 30 || true
        done
    done

    [ "${found:-0}" = 1 ] || info "No custom PHP or web-server override files found."

    subsection "OPcache"

    if command_exists php; then
        php --ri opcache 2>/dev/null |
            grep -Ei 'opcache.enable|memory_consumption|interned_strings|revalidate|hit_rate|misses|cached_scripts' |
            head -n 30 || true
    fi
}

wordpress_audit_one() {
    local root="$1"
    local wp_version active_plugins db_prefix autoload_bytes autoload_mb
    local plugin_updates theme_updates
    local admin_count cron_count
    local option_sql

    [ -f "$root/wp-config.php" ] || return 0

    if printf '%s\n' "${WP_ROOTS[@]}" | grep -Fxq "$root"; then
        return 0
    fi

    WP_ROOTS+=("$root")

    subsection "WordPress: $root"

    if ! command_exists wp; then
        warn "WP-CLI is not installed."
        return
    fi

    wp_version="$(wp_run "$root" core version 2>/dev/null | tail -n 1)"
    printf "WordPress version: %s\n" "${wp_version:-unknown}"

    if [ -z "$wp_version" ]; then
        finding HIGH "WP-CLI could not load WordPress at $root."
    fi

    active_plugins="$(wp_run "$root" plugin list --status=active --format=count 2>/dev/null | tail -n 1)"
    printf "Active plugins: %s\n" "${active_plugins:-unknown}"

    if [[ "$active_plugins" =~ ^[0-9]+$ ]] && [ "$active_plugins" -gt 40 ]; then
        finding MEDIUM "$root has $active_plugins active plugins."
    fi

    db_prefix="$(wp_run "$root" db prefix 2>/dev/null | tail -n 1 | tr -d '[:space:]')"

    if [[ "$db_prefix" =~ ^[a-zA-Z0-9_]+$ ]]; then
        option_sql="SELECT COALESCE(SUM(LENGTH(option_value)),0) FROM ${db_prefix}options WHERE autoload='yes';"

        autoload_bytes="$(
            wp_run "$root" db query "$option_sql" --skip-column-names 2>/dev/null |
            tr -dc '0-9' |
            tail -c 20
        )"

        if [[ "$autoload_bytes" =~ ^[0-9]+$ ]]; then
            autoload_mb="$(awk -v b="$autoload_bytes" 'BEGIN {printf "%.2f", b/1024/1024}')"
            printf "Autoload size: %s MB\n" "$autoload_mb"

            if awk -v mb="$autoload_mb" 'BEGIN {exit !(mb > 5)}'; then
                finding HIGH "$root autoload size is ${autoload_mb} MB."
            elif awk -v mb="$autoload_mb" 'BEGIN {exit !(mb > 2)}'; then
                finding MEDIUM "$root autoload size is ${autoload_mb} MB."
            fi

            printf "Largest autoload options:\n"
            wp_run "$root" db query \
                "SELECT option_name, LENGTH(option_value) AS bytes FROM ${db_prefix}options WHERE autoload='yes' ORDER BY bytes DESC LIMIT 15;" \
                --skip-column-names 2>/dev/null |
                column -t 2>/dev/null || true
        else
            warn "Could not read WordPress autoload size."
        fi
    else
        warn "Could not determine a safe database prefix."
    fi

    subsection "WordPress integrity"

    wp_run "$root" core verify-checksums 2>/dev/null ||
        finding HIGH "WordPress core checksum verification failed at $root."

    wp_run "$root" plugin verify-checksums --all 2>/dev/null ||
        warn "Plugin checksum verification failed or is unavailable at $root."

    wp_run "$root" theme verify-checksums --all 2>/dev/null ||
        warn "Theme checksum verification failed or is unavailable at $root."

    subsection "WordPress updates"

    plugin_updates="$(wp_run "$root" plugin list --update=available --format=count 2>/dev/null | tail -n 1)"
    theme_updates="$(wp_run "$root" theme list --update=available --format=count 2>/dev/null | tail -n 1)"

    printf "Plugin updates: %s\n" "${plugin_updates:-unknown}"
    printf "Theme updates:  %s\n" "${theme_updates:-unknown}"

    if [[ "$plugin_updates" =~ ^[0-9]+$ ]] && [ "$plugin_updates" -gt 0 ]; then
        finding MEDIUM "$root has $plugin_updates plugins with available updates."
    fi

    if [[ "$theme_updates" =~ ^[0-9]+$ ]] && [ "$theme_updates" -gt 0 ]; then
        finding LOW "$root has $theme_updates themes with available updates."
    fi

    subsection "WordPress users and Cron"

    admin_count="$(wp_run "$root" user list --role=administrator --format=count 2>/dev/null | tail -n 1)"
    printf "Administrator users: %s\n" "${admin_count:-unknown}"

    if [[ "$admin_count" =~ ^[0-9]+$ ]] && [ "$admin_count" -gt 5 ]; then
        finding MEDIUM "$root has $admin_count WordPress administrator users."
    fi

    cron_count="$(wp_run "$root" cron event list --format=count 2>/dev/null | tail -n 1)"
    printf "Scheduled WP-Cron events: %s\n" "${cron_count:-unknown}"

    if [[ "$cron_count" =~ ^[0-9]+$ ]] && [ "$cron_count" -gt 300 ]; then
        finding HIGH "$root has $cron_count scheduled WP-Cron events."
    fi

    subsection "Suspicious PHP files"

    find "$root" \
        -path "$root/wp-content/cache" -prune -o \
        -path "$root/wp-content/uploads/cache" -prune -o \
        -type f -name '*.php' -mtime -14 -print 2>/dev/null |
        head -n 50

    find "$root/wp-content/uploads" -type f -name '*.php' -print 2>/dev/null |
        head -n 30 |
        while IFS= read -r file; do
            finding HIGH "PHP file found under uploads: $file"
        done

    if [ -f "$root/wp-content/debug.log" ]; then
        local debug_size
        debug_size="$(stat -c '%s' "$root/wp-content/debug.log" 2>/dev/null || printf '0')"
        printf "debug.log size: %s\n" "$(human_bytes "$debug_size")"

        if [ "$debug_size" -gt $((100 * 1024 * 1024)) ]; then
            finding MEDIUM "Large WordPress debug.log: $root/wp-content/debug.log"
        fi
    fi
}

wordpress_audit() {
    section "WORDPRESS DEEP HEALTH"

    local root
    for root in "${DOCROOTS[@]}"; do
        wordpress_audit_one "$root"
    done

    if [ "${#WP_ROOTS[@]}" -eq 0 ]; then
        info "No WordPress installation detected."
    fi
}

mail_audit() {
    section "EXIM MAIL QUEUE"

    if ! command_exists exim; then
        warn "Exim is not installed."
        return
    fi

    local total user_sent user_received oldest
    total="$(exim -bpc 2>/dev/null || printf '0')"

    printf "Total queue size: %s\n" "$total"

    if command_exists exiqgrep; then
        user_sent="$(exiqgrep -i -f "$USER_NAME" 2>/dev/null | wc -l)"
        user_received="$(exiqgrep -i -r "$USER_NAME" 2>/dev/null | wc -l)"

        printf "Messages from user: %s\n" "$user_sent"
        printf "Messages to user:   %s\n" "$user_received"

        if [ "${user_sent:-0}" -gt 100 ]; then
            finding HIGH "More than 100 queued messages appear to originate from $USER_NAME."
        fi
    fi

    oldest="$(exim -bpr 2>/dev/null | tail -n +2 | tail -n 1)"
    [ -n "$oldest" ] && printf "Oldest queue entry: %s\n" "$oldest"
}

cron_audit() {
    section "CRON JOBS"

    subsection "User crontab"

    if command_exists crontab; then
        crontab -l -u "$USER_NAME" 2>/dev/null |
            grep -vE '^[[:space:]]*(#|$)' ||
            info "No user crontab."
    fi

    subsection "Cron references"

    grep -R "$USER_NAME" /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null |
        head -n 50 || true

    subsection "Cron-like files in home"

    find "/home/$USER_NAME" -xdev -type f \
        \( -path '*/cron/*' -o -name '*.cron' \) \
        -ls 2>/dev/null |
        head -n 50
}

access_log_audit() {
    section "ACCESS LOG ANALYSIS"

    collect_log_files

    if [ "${#LOG_FILES[@]}" -eq 0 ]; then
        warn "No Apache/LiteSpeed domain logs found."
        return
    fi

    printf "Log files:\n"
    printf '%s\n' "${LOG_FILES[@]}"

    local all_logs
    all_logs="$(printf '%s\n' "${LOG_FILES[@]}")"

    subsection "Top source IPs"

    timeout 30 awk '
        NF >= 1 { print $1 }
    ' "${LOG_FILES[@]}" 2>/dev/null |
        sort | uniq -c | sort -nr | head -n 20

    subsection "Status codes"

    timeout 30 awk '
        NF >= 9 { print $9 }
    ' "${LOG_FILES[@]}" 2>/dev/null |
        sort | uniq -c | sort -nr | head -n 20

    subsection "Top requested paths"

    timeout 30 awk '
        NF >= 7 {
            path=$7
            sub(/\?.*/, "", path)
            print path
        }
    ' "${LOG_FILES[@]}" 2>/dev/null |
        sort | uniq -c | sort -nr | head -n 30

    subsection "WordPress and WooCommerce endpoints"

    timeout 30 awk '
        NF >= 9 {
            url=$7
            if (
                url ~ /wp-login\.php/ ||
                url ~ /xmlrpc\.php/ ||
                url ~ /admin-ajax\.php/ ||
                url ~ /wp-cron\.php/ ||
                url ~ /wp-admin/ ||
                url ~ /wc-ajax/ ||
                url ~ /\/cart/ ||
                url ~ /\/checkout/
            ) {
                print $1, $6, url, $9
            }
        }
    ' "${LOG_FILES[@]}" 2>/dev/null |
        head -n 100

    subsection "POST wp-login brute-force sources"

    timeout 30 awk '
        NF >= 9 && $6 == "\"POST" && $7 ~ /\/wp-login\.php/ {
            print $1
        }
    ' "${LOG_FILES[@]}" 2>/dev/null |
        sort | uniq -c | sort -nr | head -n 20

    subsection "Potential bots by User-Agent"

    timeout 30 awk '
        /bot|crawl|spider|gptbot|claudebot|bytespider|semrush|ahrefs|bingbot|yandex/i {
            print
        }
    ' "${LOG_FILES[@]}" 2>/dev/null |
        awk -F\" '
            NF >= 2 { print $2 }
        ' |
        sort | uniq -c | sort -nr | head -n 30

    subsection "Recent PHP and WordPress errors"

    local root
    for root in "${DOCROOTS[@]}"; do
        for file in \
            "$root/error_log" \
            "$root/php_errorlog" \
            "$root/wp-content/debug.log"; do

            [ -f "$file" ] || continue

            printf "\n%s\n" "$file"
            stat -c 'size=%s bytes modified=%y' "$file" 2>/dev/null || true
            tail -n 20 "$file" 2>/dev/null
        done
    done
}

resource_audit() {
    section "LIVE PROCESSES AND RESOURCE USAGE"

    subsection "User processes"

    ps -u "$USER_NAME" -o pid,ppid,stat,etime,%cpu,%mem,rss,args --sort=-%cpu 2>/dev/null |
        head -n 30

    subsection "CPU and memory summary"

    ps -u "$USER_NAME" -o %cpu=,%mem=,rss= 2>/dev/null |
        awk '
            {cpu += $1; mem += $2; rss += $3}
            END {
                printf "CPU total: %.2f%%\n", cpu
                printf "MEM total: %.2f%%\n", mem
                printf "RSS total: %.2f MB\n", rss/1024
            }
        '

    subsection "Open files and network connections"

    if command_exists lsof; then
        printf "Open files: "
        lsof -u "$USER_NAME" 2>/dev/null | tail -n +2 | wc -l

        printf "Network connections:\n"
        lsof -nP -a -u "$USER_NAME" -i 2>/dev/null |
            head -n 30
    else
        warn "lsof is not installed."
    fi

    subsection "CloudLinux LVE"

    if command_exists lveps; then
        lveps -p 2>/dev/null |
            grep -E "ID|$USER_NAME" |
            head -n 30 || true
    else
        warn "lveps is not installed."
    fi

    if command_exists lveinfo; then
        printf "\nFaults during last hour:\n"
        lveinfo --user="$USER_NAME" --period=1h --by-fault=any --limit=20 2>/dev/null ||
            warn "This lveinfo syntax is not supported on this server."

        printf "\nResource summary during last 24 hours:\n"
        lveinfo --user="$USER_NAME" --period=1d --by-resource=cpu --limit=10 2>/dev/null || true
        lveinfo --user="$USER_NAME" --period=1d --by-resource=pmem --limit=10 2>/dev/null || true
        lveinfo --user="$USER_NAME" --period=1d --by-resource=io --limit=10 2>/dev/null || true
        lveinfo --user="$USER_NAME" --period=1d --by-resource=ep --limit=10 2>/dev/null || true
    else
        warn "lveinfo is not installed."
    fi
}

mysql_audit() {
    section "MYSQL / MARIADB"

    if ! command_exists mysqladmin; then
        warn "mysqladmin is not installed."
        return
    fi

    subsection "Active queries"

    mysqladmin processlist 2>/dev/null |
        awk -v user="$USER_NAME" '
            NR == 1 || ($0 ~ user && $0 !~ /Sleep/)
        ' |
        head -n 30 || true

    subsection "Database names from cPanel user config"

    if [ -f "/home/$USER_NAME/.my.cnf" ]; then
        awk '
            /^[[:space:]]*\[/ || /^[[:space:]]*database[[:space:]]*=/ {
                print
            }
        ' "/home/$USER_NAME/.my.cnf" 2>/dev/null || true
    fi

    if command_exists mysql; then
        printf "\nServer process summary:\n"
        mysql -NBe '
            SELECT COMMAND, COUNT(*)
            FROM information_schema.PROCESSLIST
            GROUP BY COMMAND
            ORDER BY COUNT(*) DESC;
        ' 2>/dev/null || true
    fi
}

file_security_audit() {
    section "FILE PERMISSIONS AND SUSPICIOUS FILES"

    local home="/home/$USER_NAME"

    subsection "World-writable files"

    find "$home" -xdev -type f -perm -0002 -ls 2>/dev/null |
        head -n 50

    subsection "PHP files under uploads"

    find "$home" -xdev -type f \
        \( -path '*/uploads/*.php' -o -path '*/upload/*.php' \) \
        -ls 2>/dev/null |
        head -n 50 |
        while IFS= read -r line; do
            finding HIGH "PHP file under uploads: $line"
        done

    subsection "Recently modified PHP files"

    find "$home" -xdev -type f -name '*.php' -mtime -3 -ls 2>/dev/null |
        head -n 100

    subsection "Potential obfuscation patterns"

    grep -RIlE \
        --include='*.php' \
        --exclude-dir='cache' \
        --exclude-dir='node_modules' \
        --exclude-dir='vendor' \
        'eval[[:space:]]*\(|base64_decode[[:space:]]*\(|gzinflate[[:space:]]*\(|shell_exec[[:space:]]*\(|proc_open[[:space:]]*\(' \
        "$home" 2>/dev/null |
        head -n 100
}

cloudflare_api_audit() {
    section "CLOUDFLARE API EVENTS"

    if [ -z "${CF_API_TOKEN:-}" ] || [ -z "${CF_ZONE_ID:-}" ]; then
        info "Cloudflare API variables are not set."
        info "To enable this section:"
        info "CF_API_TOKEN='token' CF_ZONE_ID='zone-id' $SCRIPT_NAME $USER_NAME"
        return
    fi

    if ! command_exists curl; then
        warn "curl is not available."
        return
    fi

    local response
    response="$(
        curl -fsS --max-time 20 \
            -H "Authorization: Bearer $CF_API_TOKEN" \
            -H "Content-Type: application/json" \
            "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/security/events?per_page=50" \
            2>/dev/null
    )"

    if [ -z "$response" ]; then
        warn "No response received from Cloudflare API."
        return
    fi

    if command_exists jq; then
        printf '%s\n' "$response" |
            jq -r '
                .result[]? |
                [
                    (.datetime // .occurred_at // "-"),
                    (.action // "-"),
                    (.rule_id // "-"),
                    (.client_ip // "-"),
                    (.http_host // "-"),
                    (.http_method // "-"),
                    (.uri // "-"),
                    (.user_agent // "-")
                ] | @tsv
            ' 2>/dev/null |
            head -n 100
    else
        warn "jq is not installed. Raw JSON was intentionally not printed."
    fi
}

summary() {
    section "AUDIT SUMMARY"

    local elapsed="$(( $(date +%s) - START_TS ))"
    local critical=0 high=0 medium=0 low=0 info_count=0
    local item severity message

    for item in "${FINDINGS[@]}"; do
        severity="${item%%|*}"
        message="${item#*|}"

        case "$severity" in
            CRITICAL) critical=$((critical + 1)) ;;
            HIGH) high=$((high + 1)) ;;
            MEDIUM) medium=$((medium + 1)) ;;
            LOW) low=$((low + 1)) ;;
            INFO) info_count=$((info_count + 1)) ;;
        esac
    done

    printf "Duration: %ss\n" "$elapsed"
    printf "Critical: %s\n" "$critical"
    printf "High:     %s\n" "$high"
    printf "Medium:   %s\n" "$medium"
    printf "Low:      %s\n" "$low"
    printf "Info:     %s\n" "$info_count"

    subsection "Findings"

    if [ "${#FINDINGS[@]}" -eq 0 ]; then
        printf "${GREEN}No findings were generated.${RESET}\n"
    else
        for item in "${FINDINGS[@]}"; do
            severity="${item%%|*}"
            message="${item#*|}"
            printf "[%s] %s\n" "$severity" "$message"
        done
    fi

    printf "\n${BLUE}==================== AUDIT COMPLETED ====================${RESET}\n"
}

main() {
    require_root
    validate_user "$@"
    check_dependencies
    detect_domains
    detect_docroots
    print_identity

    cache_headers_audit
    disk_and_inode_audit
    php_server_audit
    wordpress_audit
    mail_audit
    cron_audit
    access_log_audit
    resource_audit
    mysql_audit
    file_security_audit
    cloudflare_api_audit
    summary
}

main "$@"

