#!/bin/sh
#
# SPDX-FileCopyrightText: 2026 David Peter, Tangent Networks
#
# SPDX-License-Identifier: BSD-3-Clause
#
# =============================================================================
# TN_VIRSH_NET_SET.sh -- Tangent Networks virsh Network Definition Generator
# =============================================================================
# VERSION: 2.0.0
#
# Purpose:
#   Given an IPv4 CIDR subnet, derive a matching ULA IPv6 /64, display the
#   full subnet analysis, and optionally write a virsh XML network definition
#   ready for `virsh net-define`.  Supports three topology profiles:
#
#   NAT      -- Host is default gateway.  libvirt runs dnsmasq for DHCPv4 and
#               DHCPv6.  VMs share host internet via NAT.  Standard isolated LAN.
#
#   Route    -- A VM acts as the egress router for this segment.  libvirt
#               creates the bridge and adds a host route; it does NOT start
#               dnsmasq and does NOT assign an address to the bridge.  The VM
#               owns DHCPv4, DHCPv6, and RA (radvd/radv) on the segment.
#               Host bridge acquires its IPv6 from the VM via DHCPv6 client,
#               or is configured statically after net-start.
#
#   Isolated -- Air-gapped segment; no external routing of any kind.
#               DHCP subprofile: libvirt (dnsmasq) | vm | none (static only).
#
# ULA derivation scheme (deterministic, TN-internal):
#   fd[hex(oct1)]:[hex(oct2)hex(oct3)]::/64
#   e.g. 10.0.5.0/24   -> fd0a:0005::/64
#        192.168.1.0/24 -> fdc0:a801::/64
#        10.10.10.0/24  -> fd0a:0a0a::/64
#   Global ID is IPv4-derived for predictability within the TN scheme
#   rather than pseudo-random per RFC 4193 -- still valid ULA (fd::/8, L=1).
#
# DHCP convention: start at host offset +10 for both IPv4 and IPv6.
#   IPv4: network+10  to  broadcast-1
#   IPv6: ::a         to  ::fe
#
# Stage flow:
#   1   Mode selection  (console-only vs virsh)
#   2   IPv4 subnet input and arithmetic
#   3   IPv6 ULA derivation and display
#   4   Topology profiling  (NAT | Route | Isolated + subquestions)
#   5   virsh network name
#   6   Output directory
#   7   XML generation  (topology-specific)
#   8   Summary and activation hints  (topology-specific)
#
# XML output: net_<virsh_name>.xml in user-specified directory.
# Bridge naming: virbr-<name>, truncated so total length <= 15 chars (IFNAMSIZ).
#
# Requirements: sh, printf, cut, tr, grep, mkdir  (all POSIX/GNU base)
# =============================================================================

set -e
umask 022

VERSION="2.0.0"
SCRIPT_NAME="TN_VIRSH_NET_SET.sh"

# =============================================================================
# TERMINAL COLOURS
# =============================================================================
if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    MAGENTA='\033[0;35m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    BOLD=''
    MAGENTA=''
    NC=''
fi

# =============================================================================
# LOGGING HELPERS
# =============================================================================
ok() { printf "  ${GREEN}[OK]${NC}   %s\n" "$1"; }
err() { printf "  ${RED}[ERR]${NC}  %s\n" "$1" >&2; }
warn() { printf "  ${YELLOW}[WARN]${NC} %s\n" "$1"; }
info() { printf "  ${CYAN}[INFO]${NC} %s\n" "$1"; }

print_header() {
    printf "\n============================================================\n"
    printf "  ${BOLD}%s${NC}\n" "$1"
    printf "============================================================\n\n"
}

# =============================================================================
# VALIDATION HELPERS
# =============================================================================

# validate_cidr STRING
#   Accept /1 through /30.  /31 and /32 are unusable LAN subnets.
#   Octets must each be 0-255.
validate_cidr() {
    _vc_net=$(printf "%s" "$1" | cut -d/ -f1)
    _vc_pfx=$(printf "%s" "$1" | cut -d/ -f2)
    case "$1" in */*) : ;; *) return 1 ;; esac
    printf "%s" "$_vc_net" \
        | grep -qE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' \
        || return 1
    printf "%s" "$_vc_pfx" \
        | grep -qE '^([1-9]|[12][0-9]|30)$' \
        || return 1
    for _o in $(printf "%s" "$_vc_net" | tr '.' ' '); do
        [ "$_o" -ge 0 ] && [ "$_o" -le 255 ] || return 1
    done
    return 0
}

# validate_name STRING  -- letters, digits, - _ .  non-empty
validate_name() {
    [ -n "$1" ] || return 1
    printf "%s" "$1" | grep -qE '^[a-zA-Z0-9._-]+$'
}

# validate_dir STRING  -- non-empty, no whitespace
validate_dir() {
    [ -n "$1" ] || return 1
    case "$1" in *' '* | *'	'*) return 1 ;; esac
    return 0
}

# =============================================================================
# SUBNET ARITHMETIC  (pure POSIX sh, 64-bit GNU/Linux safe)
# =============================================================================

# prefix_to_mask PREFIX -> dotted-decimal netmask
prefix_to_mask() {
    _ptm_m=$(((0xFFFFFFFF << (32 - $1)) & 0xFFFFFFFF))
    printf "%d.%d.%d.%d" \
        "$(((_ptm_m >> 24) & 255))" \
        "$(((_ptm_m >> 16) & 255))" \
        "$(((_ptm_m >> 8) & 255))" \
        "$((_ptm_m & 255))"
}

# int_to_ip INT -> dotted-decimal
int_to_ip() {
    printf "%d.%d.%d.%d" \
        "$((($1 >> 24) & 255))" \
        "$((($1 >> 16) & 255))" \
        "$((($1 >> 8) & 255))" \
        "$(($1 & 255))"
}

# yn_prompt VAR_NAME PROMPT DEFAULT
#   Reads y/n, sets VAR_NAME to 1 (yes) or 0 (no).
#   DEFAULT is 'y' or 'n' (used when user hits Enter).
yn_prompt() {
    _yn_var="$1"
    _yn_prompt="$2"
    _yn_def="$3"
    while true; do
        printf "  ${MAGENTA}%s${NC}" "$_yn_prompt"
        read -r _yn_ans || true
        _yn_ans="${_yn_ans:-${_yn_def}}"
        case "$_yn_ans" in
            [Yy]*)
                eval "${_yn_var}=1"
                return 0
                ;;
            [Nn]*)
                eval "${_yn_var}=0"
                return 0
                ;;
            *) err "Please answer y or n." ;;
        esac
    done
}

# =============================================================================
# BANNER
# =============================================================================
printf "\n${BOLD}=== %s v%s ===${NC}\n" "$SCRIPT_NAME" "$VERSION"
printf "    Tangent Networks -- virsh / Linux subnet tool\n\n"

# =============================================================================
# STAGE 1: MODE SELECTION
# =============================================================================
print_header "Stage 1: Mode Selection"

yn_prompt WANT_VIRSH "Generate a virsh XML network definition? [y/N]: " "n"
if [ "$WANT_VIRSH" -eq 1 ]; then
    info "Mode: subnet analysis + virsh XML definition"
else
    info "Mode: subnet analysis only (no virsh XML)"
fi

# =============================================================================
# STAGE 2: IPv4 SUBNET INPUT
# =============================================================================
print_header "Stage 2: IPv4 Subnet Input"

CIDR4=""
while true; do
    printf "  Enter IPv4 Subnet (e.g., 10.10.10.0/24 or 192.168.4.0/22): "
    read -r CIDR4 || {
        err "Failed to read input."
        exit 1
    }
    if validate_cidr "$CIDR4"; then
        break
    fi
    err "Invalid CIDR.  Dotted-decimal/prefix, prefix /1-/30 only."
done

O1=$(printf "%s" "$CIDR4" | cut -d. -f1)
O2=$(printf "%s" "$CIDR4" | cut -d. -f2)
O3=$(printf "%s" "$CIDR4" | cut -d. -f3)
O4=$(printf "%s" "$CIDR4" | cut -d/ -f1 | cut -d. -f4)
PREFIX=$(printf "%s" "$CIDR4" | cut -d/ -f2)

MASK_INT=$(((0xFFFFFFFF << (32 - PREFIX)) & 0xFFFFFFFF))
IP_INT=$(((O1 << 24) | (O2 << 16) | (O3 << 8) | O4))
NET_INT=$((IP_INT & MASK_INT))
BCAST_INT=$((NET_INT | (~MASK_INT & 0xFFFFFFFF)))

NETWORK_ADDR=$(int_to_ip "$NET_INT")
BCAST_ADDR=$(int_to_ip "$BCAST_INT")
NETMASK=$(prefix_to_mask "$PREFIX")
GW_ADDR=$(int_to_ip "$((NET_INT + 1))")
USABLE_START="$GW_ADDR"
USABLE_END=$(int_to_ip "$((BCAST_INT - 1))")
DHCP4_START=$(int_to_ip "$((NET_INT + 10))")
DHCP4_END=$(int_to_ip "$((BCAST_INT - 1))")

# =============================================================================
# STAGE 3: IPv6 ULA DERIVATION + DISPLAY
# =============================================================================
ULA_G1=$(printf "%02x" "$O1")
ULA_G2=$(printf "%02x%02x" "$O2" "$O3")
ULA_BASE="fd${ULA_G1}:${ULA_G2}"
ULA_NET="${ULA_BASE}::/64"
ULA_GW="${ULA_BASE}::1"
ULA_DHCP_START="${ULA_BASE}::a"
ULA_DHCP_END="${ULA_BASE}::fe"

printf "\n--- IPv4 Subnet Analysis ---\n"
printf "%-20s %s\n" "CIDR Block:" "${NETWORK_ADDR}/${PREFIX}"
printf "%-20s %s\n" "Network Address:" "$NETWORK_ADDR"
printf "%-20s %s\n" "Subnet Mask:" "$NETMASK"
printf "%-20s %s\n" "Broadcast Address:" "$BCAST_ADDR"
printf "%-20s %s to %s\n" "Usable IPv4 Range:" "$USABLE_START" "$USABLE_END"

printf "\n--- Corresponding ULA IPv6 Range ---\n"
printf "%-20s %s\n" "Derived ULA Net:" "$ULA_NET"
printf "%-20s %s\n" "IPv6 Start:" "$ULA_GW"
printf "%-20s %s\n" "IPv6 End:" "$ULA_DHCP_END"
printf "\n"

if [ "$WANT_VIRSH" -eq 0 ]; then
    ok "Subnet analysis complete.  No virsh definition requested."
    exit 0
fi

# =============================================================================
# STAGE 4: TOPOLOGY PROFILING
# =============================================================================
print_header "Stage 4: Network Topology"

printf "  Select virsh network topology:\n\n"
printf "    ${BOLD}1  NAT${NC}       -- Host is gateway; libvirt runs dnsmasq;\n"
printf "                  VMs share host internet via NAT.\n\n"
printf "    ${BOLD}2  Route${NC}     -- VM acts as egress router; VM owns DHCP + RA;\n"
printf "                  libvirt creates bridge only, no dnsmasq.\n\n"
printf "    ${BOLD}3  Isolated${NC}  -- Air-gapped segment; no external routing.\n"
printf "                  DHCP by: libvirt | VM on segment | none.\n\n"

TOPO=""
while true; do
    printf "  ${MAGENTA}Topology [1/2/3]: ${NC}"
    read -r _topo_ans || {
        err "Failed to read input."
        exit 1
    }
    case "${_topo_ans}" in
        1)
            TOPO="nat"
            info "Topology: NAT -- libvirt gateway + dnsmasq"
            break
            ;;
        2)
            TOPO="route"
            info "Topology: Route -- VM as egress router"
            break
            ;;
        3)
            TOPO="isolated"
            info "Topology: Isolated -- air-gapped segment"
            break
            ;;
        *) err "Enter 1, 2, or 3." ;;
    esac
done

# --- Topology-specific follow-up ---

ROUTE_VM_SEG_IF="<segment-if>"
ROUTE_VM_WAN_IF="<wan-if>"
ROUTE_DHCP4=1
ROUTE_DHCP6=1
ROUTE_RA=1
ROUTE_HOST_DHCP6=0
ISO_DHCP="libvirt"
ISO_HOST_DHCP6=0

if [ "$TOPO" = "route" ]; then
    print_header "Stage 4a: Route Topology -- VM Router Profile"

    printf "  ${CYAN}Interface names are used only in comments and activation hints.${NC}\n\n"

    printf "  VM segment-side interface (e.g., eth0, enp1s0) [Enter to skip]: "
    read -r _seg_if || true
    [ -n "$_seg_if" ] && ROUTE_VM_SEG_IF="$_seg_if"

    printf "  VM WAN/egress interface   (e.g., eth1, enp2s0) [Enter to skip]: "
    read -r _wan_if || true
    [ -n "$_wan_if" ] && ROUTE_VM_WAN_IF="$_wan_if"

    printf "\n  ${CYAN}Services the VM will provide on this segment:${NC}\n\n"
    yn_prompt ROUTE_DHCP4 "  VM will run DHCPv4?              [Y/n]: " "y"
    yn_prompt ROUTE_DHCP6 "  VM will run DHCPv6?              [Y/n]: " "y"
    yn_prompt ROUTE_RA "  VM will run IPv6 RA (radvd/radv)? [Y/n]: " "y"

    printf "\n"
    yn_prompt ROUTE_HOST_DHCP6 \
        "  Host bridge acquires IPv6 via DHCPv6 from the VM? [y/N]: " "n"

elif [ "$TOPO" = "isolated" ]; then
    print_header "Stage 4a: Isolated Topology -- DHCP Profile"

    printf "  Who manages DHCP on this air-gapped segment?\n\n"
    printf "    ${BOLD}1  libvirt${NC}  -- libvirt starts dnsmasq (DHCPv4 + DHCPv6)\n"
    printf "    ${BOLD}2  vm${NC}       -- a VM on this segment runs DHCP\n"
    printf "    ${BOLD}3  none${NC}     -- static addressing only\n\n"

    while true; do
        printf "  ${MAGENTA}DHCP provider [1/2/3]: ${NC}"
        read -r _iso_dhcp || {
            err "Failed to read input."
            exit 1
        }
        case "${_iso_dhcp}" in
            1)
                ISO_DHCP="libvirt"
                info "DHCP: libvirt dnsmasq"
                break
                ;;
            2)
                ISO_DHCP="vm"
                info "DHCP: VM on segment"
                break
                ;;
            3)
                ISO_DHCP="none"
                info "DHCP: none (static)"
                break
                ;;
            *) err "Enter 1, 2, or 3." ;;
        esac
    done

    if [ "$ISO_DHCP" = "vm" ]; then
        printf "\n"
        yn_prompt ISO_HOST_DHCP6 \
            "  Host bridge acquires IPv6 via DHCPv6 from the VM? [y/N]: " "n"
    fi
fi

# =============================================================================
# STAGE 5: VIRSH NETWORK NAME
# =============================================================================
print_header "Stage 5: virsh Network Name"

VIRSH_NAME=""
while true; do
    printf "  Enter virsh network name (e.g., tn-lan0, tn-dmz, tn-router0): "
    read -r VIRSH_NAME || {
        err "Failed to read input."
        exit 1
    }
    if validate_name "$VIRSH_NAME"; then
        break
    fi
    err "Name must be non-empty; letters, digits, - _ . only."
done

# =============================================================================
# STAGE 6: OUTPUT DIRECTORY + BRIDGE NAME
# =============================================================================
print_header "Stage 6: Output Directory"

OUT_DIR=""
while true; do
    printf "  Enter output directory [Enter for current dir]: "
    read -r OUT_DIR || true
    OUT_DIR="${OUT_DIR:-.}"
    if validate_dir "$OUT_DIR"; then
        break
    fi
    err "Directory path may not contain whitespace."
done

if [ ! -d "$OUT_DIR" ]; then
    printf "  ${YELLOW}Directory '%s' does not exist.${NC}\n" "$OUT_DIR"
    printf "  ${MAGENTA}Create it? [Y/n]: ${NC}"
    read -r _mkd || true
    case "${_mkd:-Y}" in
        [Nn]*)
            err "Output directory not created.  Aborting."
            exit 1
            ;;
        *) mkdir -p "$OUT_DIR" && ok "Created: $OUT_DIR" ;;
    esac
fi

OUT_FILE="${OUT_DIR}/net_${VIRSH_NAME}.xml"

# Linux IFNAMSIZ = 16 (15 usable + NUL).  "virbr-" = 6 chars -> 9 available.
BR_NAME="virbr-$(printf "%s" "$VIRSH_NAME" | cut -c1-9)"

# =============================================================================
# STAGE 7: XML GENERATION
# =============================================================================
print_header "Stage 7: Writing virsh XML Definition"

if [ -f "$OUT_FILE" ]; then
    printf "  ${YELLOW}File already exists: %s${NC}\n" "$OUT_FILE"
    printf "  ${MAGENTA}Overwrite? [y/N]: ${NC}"
    read -r _ow || true
    case "${_ow:-N}" in
        [Yy]*) : ;;
        *)
            warn "Not overwriting.  Aborting."
            exit 0
            ;;
    esac
fi

case "$TOPO" in

    # -------------------------------------------------------------------------
    nat)
        cat > "$OUT_FILE" << XMLEOF
<network>
  <!-- Generated by ${SCRIPT_NAME} v${VERSION} -->
  <!-- Topology : NAT -- libvirt dnsmasq gateway -->
  <!-- IPv4     : ${NETWORK_ADDR}/${PREFIX}   IPv6: ${ULA_NET} -->
  <name>${VIRSH_NAME}</name>
  <forward mode='nat'>
    <nat>
      <port start='1024' end='65535'/>
    </nat>
  </forward>
  <bridge name='${BR_NAME}' stp='on' delay='0'/>

  <!-- IPv4: host bridge = ${GW_ADDR}  DHCP ${DHCP4_START}-${DHCP4_END} -->
  <ip address='${GW_ADDR}' netmask='${NETMASK}'>
    <dhcp>
      <range start='${DHCP4_START}' end='${DHCP4_END}'/>
    </dhcp>
  </ip>

  <!-- IPv6: host bridge = ${ULA_GW}/64  DHCP ${ULA_DHCP_START}-${ULA_DHCP_END} -->
  <ip family='ipv6' address='${ULA_GW}' prefix='64'>
    <dhcp>
      <range start='${ULA_DHCP_START}' end='${ULA_DHCP_END}'/>
    </dhcp>
  </ip>

</network>
XMLEOF
        ;;

    # -------------------------------------------------------------------------
    route)
        cat > "$OUT_FILE" << XMLEOF
<network>
  <!-- Generated by ${SCRIPT_NAME} v${VERSION} -->
  <!-- Topology : Route -- VM egress router; libvirt bridge only, no dnsmasq -->
  <!-- IPv4     : ${NETWORK_ADDR}/${PREFIX}   IPv6: ${ULA_NET} -->
  <!--
    VM segment-side IF : ${ROUTE_VM_SEG_IF}
      assign static    : ${GW_ADDR}/${PREFIX}  (IPv4)
                         ${ULA_GW}/64          (IPv6)
    VM WAN/egress IF   : ${ROUTE_VM_WAN_IF}
  -->
  <name>${VIRSH_NAME}</name>
  <forward mode='route'/>
  <bridge name='${BR_NAME}' stp='on' delay='0'/>

  <!--
    No <ip> elements: VM owns all addressing on this segment.
    Host bridge (${BR_NAME}) has no libvirt-assigned address.
    See activation hints for host-side configuration.
  -->

</network>
XMLEOF
        ;;

    # -------------------------------------------------------------------------
    isolated)
        case "$ISO_DHCP" in

            libvirt)
                cat > "$OUT_FILE" << XMLEOF
<network>
  <!-- Generated by ${SCRIPT_NAME} v${VERSION} -->
  <!-- Topology : Isolated -- air-gapped; libvirt dnsmasq manages DHCP -->
  <!-- IPv4     : ${NETWORK_ADDR}/${PREFIX}   IPv6: ${ULA_NET} -->
  <name>${VIRSH_NAME}</name>
  <!-- No <forward>: isolated segment, no external routing -->
  <bridge name='${BR_NAME}' stp='on' delay='0'/>

  <!-- IPv4: host bridge = ${GW_ADDR}  DHCP ${DHCP4_START}-${DHCP4_END} -->
  <ip address='${GW_ADDR}' netmask='${NETMASK}'>
    <dhcp>
      <range start='${DHCP4_START}' end='${DHCP4_END}'/>
    </dhcp>
  </ip>

  <!-- IPv6: host bridge = ${ULA_GW}/64  DHCP ${ULA_DHCP_START}-${ULA_DHCP_END} -->
  <ip family='ipv6' address='${ULA_GW}' prefix='64'>
    <dhcp>
      <range start='${ULA_DHCP_START}' end='${ULA_DHCP_END}'/>
    </dhcp>
  </ip>

</network>
XMLEOF
                ;;

            vm)
                cat > "$OUT_FILE" << XMLEOF
<network>
  <!-- Generated by ${SCRIPT_NAME} v${VERSION} -->
  <!-- Topology : Isolated -- air-gapped; VM on segment manages DHCP -->
  <!-- IPv4     : ${NETWORK_ADDR}/${PREFIX}   IPv6: ${ULA_NET} -->
  <name>${VIRSH_NAME}</name>
  <!-- No <forward>: isolated segment, no external routing -->
  <bridge name='${BR_NAME}' stp='on' delay='0'/>

  <!--
    No <ip> elements: VM owns all addressing on this segment.
    Host bridge (${BR_NAME}) has no libvirt-assigned address.
    See activation hints for host-side configuration.
  -->

</network>
XMLEOF
                ;;

            none)
                cat > "$OUT_FILE" << XMLEOF
<network>
  <!-- Generated by ${SCRIPT_NAME} v${VERSION} -->
  <!-- Topology : Isolated -- air-gapped; static addressing, no DHCP -->
  <!-- IPv4     : ${NETWORK_ADDR}/${PREFIX}   IPv6: ${ULA_NET} -->
  <name>${VIRSH_NAME}</name>
  <!-- No <forward>: isolated segment, no external routing -->
  <bridge name='${BR_NAME}' stp='on' delay='0'/>

  <!-- IPv4: host bridge = ${GW_ADDR} -- no DHCP range -->
  <ip address='${GW_ADDR}' netmask='${NETMASK}'/>

  <!-- IPv6: host bridge = ${ULA_GW}/64 -- no DHCP range -->
  <ip family='ipv6' address='${ULA_GW}' prefix='64'/>

</network>
XMLEOF
                ;;
        esac
        ;;
esac

ok "Written: $OUT_FILE"

# =============================================================================
# STAGE 8: SUMMARY AND ACTIVATION HINTS
# =============================================================================
printf "\n"
printf "  ${CYAN}--- Network Summary ---${NC}\n"
printf "  %-24s %s\n" "virsh name:" "$VIRSH_NAME"
printf "  %-24s %s\n" "Topology:" "$TOPO"
printf "  %-24s %s\n" "Bridge:" "$BR_NAME"
printf "  %-24s %s\n" "IPv4 segment:" "${NETWORK_ADDR}/${PREFIX}  (mask ${NETMASK})"
printf "  %-24s %s\n" "IPv6 segment:" "${ULA_NET}"
printf "  %-24s %s\n" "Definition file:" "$OUT_FILE"

case "$TOPO" in
    nat)
        printf "  %-24s %s\n" "IPv4 gateway:" "$GW_ADDR  (host bridge)"
        printf "  %-24s %s to %s\n" "IPv4 DHCP range:" "$DHCP4_START" "$DHCP4_END"
        printf "  %-24s %s\n" "IPv6 gateway:" "$ULA_GW  /64  (host bridge)"
        printf "  %-24s %s to %s\n" "IPv6 DHCP range:" "$ULA_DHCP_START" "$ULA_DHCP_END"
        ;;
    route)
        printf "  %-24s %s\n" "VM segment-side IF:" "$ROUTE_VM_SEG_IF"
        printf "  %-24s %s\n" "VM WAN/egress IF:" "$ROUTE_VM_WAN_IF"
        _svc=""
        [ "$ROUTE_DHCP4" -eq 1 ] && _svc="${_svc}DHCPv4 "
        [ "$ROUTE_DHCP6" -eq 1 ] && _svc="${_svc}DHCPv6 "
        [ "$ROUTE_RA" -eq 1 ] && _svc="${_svc}RA(radvd)"
        printf "  %-24s %s\n" "VM services:" "${_svc:-none declared}"
        _hb6="static (manual)"
        [ "$ROUTE_HOST_DHCP6" -eq 1 ] && _hb6="DHCPv6 client"
        printf "  %-24s %s\n" "Host bridge IPv6:" "$_hb6"
        ;;
    isolated)
        _iso_label=""
        case "$ISO_DHCP" in
            libvirt) _iso_label="libvirt dnsmasq (DHCPv4 + DHCPv6)" ;;
            vm) _iso_label="VM on segment" ;;
            none) _iso_label="none -- static addressing" ;;
        esac
        printf "  %-24s %s\n" "DHCP provider:" "$_iso_label"
        if [ "$ISO_DHCP" = "libvirt" ]; then
            printf "  %-24s %s to %s\n" "IPv4 DHCP range:" "$DHCP4_START" "$DHCP4_END"
            printf "  %-24s %s to %s\n" "IPv6 DHCP range:" "$ULA_DHCP_START" "$ULA_DHCP_END"
        fi
        ;;
esac

printf "\n"
info "Activate:"
printf "    virsh net-define    %s\n" "$OUT_FILE"
printf "    virsh net-start     %s\n" "$VIRSH_NAME"
printf "    virsh net-autostart %s\n" "$VIRSH_NAME"

# Topology-specific post-activation instructions
case "$TOPO" in
    nat)
        printf "\n"
        info "Verify:"
        printf "    virsh net-list --all\n"
        printf "    virsh net-dumpxml %s\n" "$VIRSH_NAME"
        ;;

    route)
        printf "\n"
        info "VM segment-side interface (${ROUTE_VM_SEG_IF}) -- configure in VM:"
        printf "    ip addr add %s/%s dev %s\n" \
            "$GW_ADDR" "$PREFIX" "$ROUTE_VM_SEG_IF"
        printf "    ip addr add %s/64  dev %s\n" \
            "$ULA_GW" "$ROUTE_VM_SEG_IF"
        printf "    ip link set %s up\n" "$ROUTE_VM_SEG_IF"
        if [ "$ROUTE_DHCP4" -eq 1 ]; then
            printf "\n"
            info "VM DHCPv4 (dnsmasq example -- run in VM):"
            printf "    dnsmasq --interface=%s \\\\\n" "$ROUTE_VM_SEG_IF"
            printf "            --dhcp-range=%s,%s,12h\n" "$DHCP4_START" "$DHCP4_END"
        fi
        if [ "$ROUTE_RA" -eq 1 ] || [ "$ROUTE_DHCP6" -eq 1 ]; then
            printf "\n"
            info "VM IPv6 RA + DHCPv6 (dnsmasq example -- run in VM):"
            printf "    dnsmasq --interface=%s \\\\\n" "$ROUTE_VM_SEG_IF"
            printf "            --dhcp-range=%s,%s,ra-stateless\n" \
                "$ULA_DHCP_START" "$ULA_DHCP_END"
        fi
        printf "\n"
        if [ "$ROUTE_HOST_DHCP6" -eq 1 ]; then
            info "Host bridge -- acquire IPv6 from VM via DHCPv6 client:"
            printf "    dhclient -6 %s\n" "$BR_NAME"
            printf "    # or NetworkManager:\n"
            printf "    #   nmcli con modify %s ipv6.method auto\n" "$BR_NAME"
            printf "    # or systemd-networkd:\n"
            printf "    #   /etc/systemd/network/%s.network  [DHCP] IPv6=yes\n" "$BR_NAME"
        else
            info "Host bridge -- assign static address after net-start (example):"
            printf "    ip addr add %s/%s dev %s\n" \
                "$USABLE_END" "$PREFIX" "$BR_NAME"
            printf "    ip addr add %s/64  dev %s\n" \
                "$ULA_DHCP_END" "$BR_NAME"
        fi
        printf "\n"
        info "Verify:"
        printf "    virsh net-list --all\n"
        printf "    ip addr show %s\n" "$BR_NAME"
        ;;

    isolated)
        if [ "$ISO_DHCP" = "vm" ]; then
            printf "\n"
            info "Configure the router VM's segment interface with:"
            printf "    ip addr add %s/%s dev <vm-if>\n" "$GW_ADDR" "$PREFIX"
            printf "    ip addr add %s/64  dev <vm-if>\n" "$ULA_GW"
            if [ "$ISO_HOST_DHCP6" -eq 1 ]; then
                printf "\n"
                info "Host bridge -- acquire IPv6 from VM via DHCPv6 client:"
                printf "    dhclient -6 %s\n" "$BR_NAME"
            fi
        fi
        if [ "$ISO_DHCP" = "none" ]; then
            printf "\n"
            info "Assign static addresses to all VMs on this segment manually."
            printf "    Segment: %s/%s  IPv6: %s\n" \
                "$NETWORK_ADDR" "$PREFIX" "$ULA_NET"
        fi
        printf "\n"
        info "Verify:"
        printf "    virsh net-list --all\n"
        printf "    virsh net-dumpxml %s\n" "$VIRSH_NAME"
        ;;
esac
