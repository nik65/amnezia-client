#!/bin/bash
#
# Parses DHCP options from openvpn to update resolv.conf
# To use set as 'up' and 'down' script in your openvpn *.conf:
# up /etc/openvpn/update-resolv-conf
# down /etc/openvpn/update-resolv-conf
#
# Used snippets of resolvconf script by Thomas Hood <jdthood@yahoo.co.uk>
# and Chris Hanson
# Licensed under the GNU GPL.  See /usr/share/common-licenses/GPL.
# 07/2013 colin@daedrum.net Fixed intent name
# 05/2006 chlauber@bnc.ch
#
# Example envs set from openvpn:
# foreign_option_1='dhcp-option DNS 193.43.27.132'
# foreign_option_2='dhcp-option DNS 193.43.27.133'
# foreign_option_3='dhcp-option DOMAIN be.bnc.ch'
# foreign_option_4='dhcp-option DOMAIN-SEARCH bnc.local'

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

case "$script_type" in
  up|down) ;;
  *) exit 0 ;;
esac

[[ "$dev" =~ ^[A-Za-z0-9_.:-]{1,64}$ ]] || exit 0

RESOLVCONF=''
for candidate in /usr/sbin/resolvconf /sbin/resolvconf /usr/bin/resolvconf /bin/resolvconf; do
  if [[ -x "$candidate" ]]; then
    RESOLVCONF="$candidate"
    break
  fi
done
[[ -n "$RESOLVCONF" ]] || exit 0
readonly RESOLVCONF

case "$script_type" in

up)
  DNS_NAMESERVERS=()
  DNS_SEARCH=()
  for optionname in "${!foreign_option_@}" ; do
    option="${!optionname}"
    builtin printf '%s\n' "$option"
    part1=''
    part2=''
    part3=''
    builtin read -r part1 part2 part3 _ <<< "$option"
    if [[ "$part1" == "dhcp-option" ]] ; then
      if [[ "$part2" == "DNS" && -n "$part3" ]] ; then
        DNS_NAMESERVERS+=("$part3")
      fi
      if [[ ( "$part2" == "DOMAIN" || "$part2" == "DOMAIN-SEARCH" ) && -n "$part3" ]] ; then
        DNS_SEARCH+=("$part3")
      fi
    fi
  done
  R=''
  if (( ${#DNS_SEARCH[@]} )); then
    R='search'
    for DS in "${DNS_SEARCH[@]}" ; do
      R+=" $DS"
    done
    R+=$'\n'
  fi

  for NS in "${DNS_NAMESERVERS[@]}" ; do
    R+="nameserver $NS"$'\n'
  done
  builtin printf '%s' "$R" \
    | /usr/bin/env -i PATH="$TRUSTED_PATH" LC_ALL=C LANG=C \
        "$RESOLVCONF" -x -a "${dev}.inet"
  ;;
down)
  /usr/bin/env -i PATH="$TRUSTED_PATH" LC_ALL=C LANG=C \
    "$RESOLVCONF" -d "${dev}.inet"
  ;;
esac

# Workaround / jm@epiclabs.io
# force exit with no errors. Due to an apparent conflict with the Network Manager
# $RESOLVCONF sometimes exits with error code 6 even though it has performed the
# action correctly and OpenVPN shuts down.
exit 0
