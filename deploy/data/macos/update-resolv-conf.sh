#!/bin/bash

# Mac name-resolution updater based on @cl's script here:
# https://blog.netnerds.net/2011/10/openvpn-update-client-dns-on-mac-os-x-using-from-the-command-line/
# Openvpn envar parsing taken from the script in debian's openvpn package.
# Smushed together and improved by @andrewgdotcom.

# Parses DHCP options from openvpn to update resolv.conf
# To use set as 'up' and 'down' script in your openvpn *.conf:
# up /etc/openvpn/update-resolv-conf
# down /etc/openvpn/update-resolv-conf

readonly TRUSTED_PATH='/usr/sbin:/usr/bin:/sbin:/bin'
PATH="$TRUSTED_PATH"
LC_ALL=C
LANG=C
readonly PATH LC_ALL LANG
export PATH LC_ALL LANG

# OpenVPN must not pass loader or shell startup controls to this root script.
# The launcher and pull-filter enforce that boundary before /bin/bash starts;
# clear them again before invoking any child process.
set +x
builtin unset BASH_ENV ENV CDPATH GLOBIGNORE BASH_XTRACEFD PS4 POSIXLY_CORRECT \
  LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE \
  DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
  DYLD_FALLBACK_LIBRARY_PATH DYLD_FALLBACK_FRAMEWORK_PATH
IFS=$' \t\n'
umask 077

builtin printf '%s\n' "*** starting update-resolv-config script ***"

case "$script_type" in
  up|down) ;;
  *) exit 0 ;;
esac
[[ "$dev" =~ ^[A-Za-z0-9_.:-]{1,64}$ ]] || exit 0

NMSRVRS=()
SRCHS=()

run_networksetup()
{
        /usr/bin/env -i PATH="$TRUSTED_PATH" LC_ALL=C LANG=C \
                /usr/sbin/networksetup "$@"
}

# Get adapter list
adapters=()
while IFS= read -r adapter; do
        [[ -n "$adapter" ]] || continue
        [[ "$adapter" == *"denotes that a network service is disabled"* ]] && continue
        adapter="${adapter#\*}"
        [[ -n "$adapter" ]] && adapters+=("$adapter")
done < <(run_networksetup -listallnetworkservices)

update_all_dns()
{
        for adapter in "${adapters[@]}"
        do
        builtin printf 'updating dns for %s\n' "$adapter"
        # set dns server to the vpn dns server
        if (( ${#SRCHS[@]} )); then
            run_networksetup -setsearchdomains "$adapter" "${SRCHS[@]}"
        fi
        if (( ${#NMSRVRS[@]} )); then
            run_networksetup -setdnsservers "$adapter" "${NMSRVRS[@]}"
        fi
        done
}

clear_all_dns()
{
        for adapter in "${adapters[@]}"
        do
        builtin printf 'updating dns for %s\n' "$adapter"
        run_networksetup -setdnsservers "$adapter" empty
        run_networksetup -setsearchdomains "$adapter" empty
        done
}

case "$script_type" in
  up)
        for optionvarname in "${!foreign_option_@}" ; do
                option="${!optionvarname}"
                builtin printf '%s\n' "$option"
                builtin read -r part1 part2 part3 _ <<< "$option"
                if [ "$part1" = "dhcp-option" ] ; then
                        if [ "$part2" = "DNS" ] && [ -n "$part3" ] ; then
                                NMSRVRS+=("$part3")
                        elif { [ "$part2" = "DOMAIN" ] || [ "$part2" = "DOMAIN-SEARCH" ]; } \
                                && [ -n "$part3" ]; then
                                SRCHS+=("$part3")
                        fi
                fi
        done
        update_all_dns
        ;;
  down)
        clear_all_dns
        ;;
esac

builtin printf '%s\n' "*** finished update-resolv-config script ***"
