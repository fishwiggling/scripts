#!/bin/bash
## License: BSD 3
## It can reinstall  to current stable version !.
## Written By https://github.com/ehebe

function __log() { local _date=$(date +"%Y-%m-%d %H:%M:%S"); echo -e "\e[0;32m[${_date}]\e[0m $@" >&2; }
function __fatal() { __log "$@"; __log "\tExiting."; exit 1; }
function __command_exists() { command -v "$1" >/dev/null 2>&1; }

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH

[[ "$(uname -a)" =~ "inux" && "$(uname -a)" =~ "entos" ]] && __fatal "requires debian or ubuntu"
[[ "$(id -u)" -ne 0 ]] && __fatal "Error:This script must be run as root!"

need_commands=(wget gzip openssl awk blockdev)
for cmd in "${need_commands[@]}"; do
  if ! __command_exists "$cmd"; then
    __fatal "\tError: Missing command '$cmd'.You need to install it first.\n\t\t\tapt install -y wget gzip openssl";
  fi
done

function lowmen_check(){
  mem=$(grep "^MemTotal:" /proc/meminfo 2>/dev/null |grep -o "[0-9]*")
  [ -n "$mem" ] || return 0
  [ "$mem" -le "524288" ] && return 1 || return 0
}

function prefix_to_ipv4_netmask() {
    local prefix=$1
    local netmask=$((0xffffffff << (32 - prefix)))
    printf "%d.%d.%d.%d\n" \
        $(( (netmask >> 24) & 0xff )) \
        $(( (netmask >> 16) & 0xff )) \
        $(( (netmask >> 8) & 0xff )) \
        $(( netmask & 0xff ))
}

function prefix_to_ipv6_netmask() {
    local prefix=$1
    local netmask=(0 0 0 0 0 0 0 0)
    for (( i=0; i<$prefix; i++ )); do
        local segment=$(( i / 16 ))
        local bit=$(( 15 - (i % 16) ))
        netmask[$segment]=$(( netmask[$segment] | (1 << bit) ))
    done
    printf "%04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n" "${netmask[@]}"
}

machine=$(uname -m)
case ${machine} in
  aarch64|arm64) machine_warp="arm64";;
  x86|i386|i686) machine_warp="i386";;
  x86_64|amd64) machine_warp="amd64";;
  *) __fatal "Can not detect your server arch!";;
esac

pwd='Ideb123'
suite='stable'
interface='auto'
dns='8.8.8.8 1.1.1.1'
dns6='2001:4860:4860::8888 2001:4860:4860::8844'
_confirm='n'
kernel_params=''
filesystem='ext4'
opt_cmd='IyEvYmluL2Jhc2gKCmNhdCA+IC9ldGMvc3NoL3NzaGRfY29uZmlnIDw8RU9GCiNJbmNsdWRlIC9ldGMvc3NoL3NzaGRfY29uZmlnLmQvKi5jb25mClBvcnQgIDIyClBlcm1pdFJvb3RMb2dpbiB5ZXMKUGFzc3dvcmRBdXRoZW50aWNhdGlvbiB5ZXMKUHVia2V5QXV0aGVudGljYXRpb24geWVzCkNoYWxsZW5nZVJlc3BvbnNlQXV0aGVudGljYXRpb24gbm8KS2JkSW50ZXJhY3RpdmVBdXRoZW50aWNhdGlvbiBubwpBdXRob3JpemVkS2V5c0ZpbGUgIC9yb290Ly5zc2gvYXV0aG9yaXplZF9rZXlzClgxMUZvcndhcmRpbmcgeWVzCkFsbG93VXNlcnMgcm9vdApQcmludE1vdGQgbm8KQWNjZXB0RW52IExBTkcgTENfKgpFT0YKCl9mdHA9JChmaW5kIC91c3IgLW5hbWUgInNmdHAtc2VydmVyIiAyPi9kZXYvbnVsbCB8IGhlYWQgLW4gMSkKWyAtbiAiJHtfZnRwfSIgXSAmJiBlY2hvICJTdWJzeXN0ZW0gc2Z0cCAke19mdHB9IiA+PiAvZXRjL3NzaC9zc2hkX2NvbmZpZwoKY2F0ID4+IC9ldGMvYmFzaC5iYXNocmMgPDxFT0YKZXhwb3J0IFBTMT0nXFtcZVswOzMybVxdXHVAXGggXFtcZVswOzM0bVxdXHdcW1xlWzA7MzZtXF1cblwkIFxbXGVbMG1cXScKYWxpYXMgZ2V0aXA9J2N1cmwgLS1jb25uZWN0LXRpbWVvdXQgMyAtTHMgaHR0cHM6Ly9pcHY0LWFwaS5zcGVlZHRlc3QubmV0L2dldGlwJwphbGlhcyBnZXRpcDY9J2N1cmwgLS1jb25uZWN0LXRpbWVvdXQgMyAtTHMgaHR0cHM6Ly9pcHY2LWFwaS5zcGVlZHRlc3QubmV0L2dldGlwJwphbGlhcyBuZXRjaGVjaz0ncGluZyAtYzIgOC44LjguOCcKYWxpYXMgbHM9J2xzIC0tY29sb3I9YXV0bycKYWxpYXMgZ3JlcD0nZ3JlcCAtLWNvbG9yPWF1dG8nIAphbGlhcyBmZ3JlcD0nZmdyZXAgLS1jb2xvcj1hdXRvJwphbGlhcyBlZ3JlcD0nZWdyZXAgLS1jb2xvcj1hdXRvJwphbGlhcyBybT0ncm0gLWknCmFsaWFzIGNwPSdjcCAtaScKYWxpYXMgbXY9J212IC1pJwphbGlhcyBsbD0nbHMgLWxoJwphbGlhcyBsYT0nbHMgLWxBaCcKYWxpYXMgLi49J2NkIC4uLycKYWxpYXMgLi4uPSdjZCAuLi8uLi8nCmFsaWFzIHBnPSdwcyBhdXggfGdyZXAgLWknCmFsaWFzIGhnPSdoaXN0b3J5IHxncmVwIC1pJwphbGlhcyBsZz0nbHMgLUEgfGdyZXAgLWknCmFsaWFzIGRmPSdkZiAtVGgnCmFsaWFzIGZyZWU9J2ZyZWUgLWgnCmV4cG9ydCBISVNUVElNRUZPUk1BVD0iJUYgJVQgXGB3aG9hbWlcYCAiCmV4cG9ydCBMQU5HPWVuX1VTLlVURi04CmV4cG9ydCBQQVRIPVwkUEFUSDouCkVPRgoKY2F0ID4+IC9ldGMvc2VjdXJpdHkvbGltaXRzLmNvbmYgPDxFT0YKKglzb2Z0CW5vZmlsZQk2NTUzNQoqCWhhcmQJbm9maWxlCTY1NTM1CioJc29mdAlub3Byb2MJNjU1MzUKKgloYXJkIG5vcHJvYwk2NTUzNQpyb290CXNvZnQJbm9maWxlCTY1NTM1CnJvb3QJaGFyZAlub2ZpbGUJNjU1MzUKcm9vdAlzb2Z0CW5vcHJvYwk2NTUzNQpyb290CWhhcmQJbm9wcm9jCTY1NTM1CkVPRgoKY2F0ID4+IC9ldGMvc2VjdXJpdHkvbGltaXRzLmQvOTAtbnByb2MuY29uZiA8PEVPRgoqCXNvZnQJbnByb2MJNjU1MzUKcm9vdAlzb2Z0CW5wcm9jCTY1NTM1CkVPRgoKWyAtZiAvZXRjL3N5c3RlbWQvc3lzdGVtLmNvbmYgXSAmJiBzZWQgLWkgJ3MvI1w/RGVmYXVsdExpbWl0Tk9GSUxFPS4qL0RlZmF1bHRMaW1pdE5PRklMRT02NTUzNS8nIC9ldGMvc3lzdGVtZC9zeXN0ZW0uY29uZjsKCmNhdCA+IC9ldGMvc3lzdGVtZC9qb3VybmFsZC5jb25mICA8PEVPRgpbSm91cm5hbF0KU3RvcmFnZT1hdXRvCkNvbXByZXNzPXllcwpGb3J3YXJkVG9TeXNsb2c9bm8KU3lzdGVtTWF4VXNlPThNClJ1bnRpbWVNYXhVc2U9OE0KUmF0ZUxpbWl0SW50ZXJ2YWxTZWM9MzBzClJhdGVMaW1pdEJ1cnN0PTEwMApFT0YKCmNhdCA+IC9ldGMvc3lzY3RsLmQvOTktc3lzY3RsLmNvbmYgIDw8RU9GCm5ldC5pcHY0LnRjcF9zYWNrID0gMQpuZXQuaXB2NC50Y3BfZmFzdG9wZW4gPSAxCm5ldC5pcHY0LnRjcF90d19yZXVzZSA9IDEKbmV0LmlwdjQudGNwX3dpbmRvd19zY2FsaW5nID0gMQpuZXQuaXB2NC5pcF9mb3J3YXJkID0gMQpuZXQuaXB2Ni5jb25mLmFsbC5mb3J3YXJkaW5nID0gMQpuZXQuaXB2Ni5jb25mLmRlZmF1bHQuZm9yd2FyZGluZyA9IDEKbmV0LmNvcmUucm1lbV9tYXggPSA4Mzg4NjA4Cm5ldC5jb3JlLndtZW1fbWF4ID0gODM4ODYwOApuZXQuaXB2NC50Y3Bfcm1lbSA9IDgxOTIgMjYyMTQ0IDgzODg2MDgKbmV0LmlwdjQudGNwX3dtZW0gPSA0MDk2IDE2Mzg0IDgzODg2MDgKbmV0LmNvcmUuZGVmYXVsdF9xZGlzYyA9IGZxCm5ldC5pcHY0LnRjcF9jb25nZXN0aW9uX2NvbnRyb2wgPSBiYnIKRU9GCg=='
firmware='0'
upgrade='none' #'none','safe-upgrade','full-upgrade'
lowmem_mode='0'
force_lowmem='2'  # 0, 1, 2
force_gpt='0'
ethx_mode='0'
grub_timeout='5'
interface='auto'
apt_services='security,updates,backports'
# pkg dbus fix error :Failed to create bus connection: No such file or directory
# tasksel tasksel/first multiselect minimal will not install dbus
install_softs='dbus libpam-systemd ca-certificates sudo'
hostname=$(cat /proc/sys/kernel/hostname)
mapper=$(mount | awk '$3=="/boot" {print $1}' | grep . || mount | awk '$3=="/" {print $1}')
disk="/dev/$(lsblk -rn --inverse $mapper | grep -w disk | awk '{print $1}' | sort -u)"
[ -d /sys/firmware/efi ] && is_uefi=true 
[ -d /sys/firmware/efi ] && force_gpt='1'

ipv4_address='' 
ipv4_netmask='' 
ipv4_prefix='' 
ipv4_gateway='' 
ipv6_address='' 
ipv6_netmask='' 
ipv6_prefix='' 
ipv6_gateway='' 

# get public v4 and v6
real_ipv4=$(timeout 2 wget --timeout=2 -qO- https://ipv4-api.speedtest.net/getip) 
real_ipv6=$(timeout 2 wget --timeout=2 -qO- https://ipv6-api.speedtest.net/getip) 

# network interface
ipv4_interface=$(ip route get 8.8.8.8 2>/dev/null | awk '{print $5}') 
ipv6_interface=$(ip -6 route | grep default | awk '{print $5}') 

# v4
if [ -n "$ipv4_interface" ]; then  
    ipv4_info=$(ip addr show dev $ipv4_interface | grep 'inet ' | grep -v '127\.' )  
    if [ -n "$ipv4_info" ]; then  
        ipv4_address=$(echo $ipv4_info | awk '{print $2}' | cut -d'/' -f1)  
        ipv4_prefix=$(echo $ipv4_info | awk '{print $2}' | cut -d'/' -f2)  
        ipv4_netmask=$(prefix_to_ipv4_netmask $ipv4_prefix)  
        ipv4_gateway=$(ip route | grep default | grep -v 'via ::' | awk '{print $3}')  
    fi  
fi

# v6
if [ -n "$ipv6_interface" ]; then 
    ipv6_info=$(ip addr show dev $ipv6_interface | grep 'inet6 ' | grep -v 'scope link') 
    if [ -n "$ipv6_info" ]; then 
        ipv6_address=$(echo $ipv6_info | awk '{print $2}' | cut -d'/' -f1) 
        ipv6_prefix=$(echo $ipv6_info | awk '{print $2}' | cut -d'/' -f2) 
        ipv6_netmask=$(prefix_to_ipv6_netmask $ipv6_prefix) 
        ipv6_gateway=$(ip -6 route | grep default | awk '{print $3}') 
    fi 
fi

# parse cmdline
while [[ $# -ge 1 ]]; do
  case $1 in
    -p|--password)
      shift
      pwd="$1"
      shift
      ;;
    -dns)
      shift
      dns="$1"
      shift
      ;;
    -dns6)
      shift
      dns6="$1"
      shift
      ;;
    -hostname)
      shift
      hostname="$1"
      shift
      ;;
    -interface)
      shift
      interface="$1"
      shift
      ;;
    -disk)
      shift
      disk="$1"
      shift
      ;;
    -install)
      shift
      install_softs="$install_softs $1"
      shift
      ;;
    -suite)
      shift
      suite="$1"
      shift
      ;;
    -filesystem)
      shift
      filesystem="$1"
      shift
      ;;
    --firmware)
      shift
      firmware='1'
      ;;
    --confirm)
      shift
      _confirm='y'
      ;;
    --lowmem)
      shift
      lowmem_mode="1"
      ;;
    --force_gpt)
      shift
      force_gpt="1"
      ;;
    --safe-upgrade)
      shift
      upgrade='safe-upgrade'
      ;;
    --full-upgrade)
      shift
      upgrade='full-upgrade'
      ;;
    --ethx)
      shift
      ethx_mode='1'
      kernel_params="$kernel_params net.ifnames=0 biosdevname=0"
      ;;
    *)
     if [[ "$1" != 'error' ]]; then echo -ne "\nInvaild option: '$1'\n\n"; fi
      echo "eg: sudo bash ideb.sh -p '$pwd' , will auto reinstall to current stable debian version !";
      echo "  -p '$pwd' | --password ''$pwd' (set your login password)"
      echo "  -dns '8.8.8.8' (set your dns v4)"
      echo "  -dns6 '2001:4860:4860::8888' (set your dns v6)"
      echo "  -suite 'bookworm' (recommend:stable, bookworm, bullseye)"
      echo "  -interface 'eth0' (be careful with current options and the --ethx option)"
      echo "  -hostname 'localhost' (set your hostname)"
      echo "  -disk (install disk)"
      echo "  -filesystem ext4 (set your filesystem)"
      echo "  -install 'git htop' (install more softs)"
      echo "  --ethx (Use old ethx naming)"
      echo "  --lowmem (lowmem mode)"
      echo "  --force_gpt (use gpt)"
      echo "  --firmware (install firmware,make sure boot part free size >= 200MB)"
      echo "  --confirm (Ignore installation confirmation)"
      echo ''
      __fatal
      ;;
    esac
done

[[ -z "$disk" ]] && __fatal "Not set install disk !";
find_by_size=$(blockdev --getsize64 $disk);
[[ -z "$find_by_size" ]] && __fatal "Not get disk [ $disk ] size !";

# fix low memory server.
lowmen_check || lowmem_mode="1"

# Encrypted password
enc_pwd=$(openssl passwd -1 "$pwd");

# choose network info.
if [ -n "$real_ipv4" ]; then
    selected_ip="$ipv4_address"
    selected_netmask="$ipv4_netmask"
    selected_gw="$ipv4_gateway"
    selected_dns="$dns"
elif [ -n "$real_ipv6" ]; then
    selected_ip="$ipv6_address"
    selected_netmask="$ipv6_netmask"
    selected_gw="$ipv6_gateway"
    selected_dns="$dns6"
else 
  __fatal "Can not detect your IPv4 or IPv6 info !"
fi

_inject=$(cat <<EOF
#!/bin/bash

# be careful ,  no more testing!!!
real_ndev=\$(grep -E '^iface[[:space:]]+(ens|enp|eth)[a-zA-Z0-9]+' /etc/network/interfaces | awk '{print \$2}' | head -n 1)
if [ -z "\$real_ndev" ]; then
    echo 'Failed to determine the real network device (only ensx or enpx or ethx).'
    exit -1
fi

cat > /etc/network/interfaces <<EOFIN
source /etc/network/interfaces.d/*

auto lo
iface lo inet loopback

EOFIN

if [ -n "$ipv4_address" ] && [ -n "$ipv4_prefix" ] && [ -n "$ipv4_gateway" ]; then
    cat >> /etc/network/interfaces <<EOFIN
allow-hotplug \$real_ndev
iface \$real_ndev inet static
  address $ipv4_address/$ipv4_prefix
  gateway $ipv4_gateway
  dns-nameservers $dns

EOFIN
fi

if [ -n "$ipv6_address" ] && [ -n "$ipv6_prefix" ] && [ -n "$ipv6_gateway" ]; then
    cat >> /etc/network/interfaces <<EOFIN
iface \$real_ndev inet6 static
  address $ipv6_address/$ipv6_prefix
  gateway $ipv6_gateway
  dns-nameservers $dns6
  
EOFIN
fi
EOF
)

__log 'Encoding ipinfo ...'
base64_ipdata=$(echo -n "$_inject" | base64 -w 0)

mirror='https://cdn-aws.deb.debian.org/debian'
vmlinuz_url="${mirror}/dists/${suite}/main/installer-${machine_warp}/current/images/netboot/debian-installer/${machine_warp}/linux"
initrd_url="${mirror}/dists/${suite}/main/installer-${machine_warp}/current/images/netboot/debian-installer/${machine_warp}/initrd.gz"
firmware_url="https://cdimage.debian.org/cdimage/unofficial/non-free/firmware/${suite}/current/firmware.cpio.gz"

__log 'downloading initrd.gz and vmlinuz ...'
wget --no-check-certificate -O '/tmp/initrd.gz' "${initrd_url}" --tries=3 || __fatal 'Download initrd.gz error !'
wget --no-check-certificate -O '/tmp/vmlinuz' "${vmlinuz_url}" --tries=3 || __fatal 'Download vmlinuz error !'

if [[ "$firmware" == '1' ]]; then
  __log 'downloading firmware ...'
  wget --no-check-certificate -O '/tmp/firmware.cpio.gz' "${firmware_url}" --tries=3 || __fatal 'Download firmware error !'
fi

__log 'generating grub.cfg ...'
mkdir -p /etc/default/grub.d
cat << EOF > /etc/default/grub.d/ideb.cfg
GRUB_DEFAULT=debi
GRUB_TIMEOUT=$grub_timeout
GRUB_TIMEOUT_STYLE=menu
EOF

if __command_exists update-grub; then
        grub_cfg=/boot/grub/grub.cfg
        update-grub
elif __command_exists grub2-mkconfig; then
        tmp=$(mktemp)
        grep -vF ideb.cfg /etc/default/grub > "$tmp"
        cat "$tmp" > /etc/default/grub
        rm "$tmp"
        echo 'ideb=/etc/default/grub.d/ideb.cfg; if [ -f "$ideb" ]; then . "$ideb"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub2/grub.cfg
        [ -d /sys/firmware/efi ] && grub_cfg=/boot/efi/EFI/*/grub.cfg
        grub2-mkconfig -o "$grub_cfg"
elif __command_exists grub-mkconfig; then
        tmp=$(mktemp)
        grep -vF ideb /etc/default/grub > "$tmp"
        cat "$tmp" > /etc/default/grub
        rm "$tmp"
        echo 'ideb=/etc/default/grub.d/ideb.cfg; if [ -f "$ideb" ]; then . "$ideb"; fi' >> /etc/default/grub
        grub_cfg=/boot/grub/grub.cfg
        grub-mkconfig -o "$grub_cfg"
else
        err 'Could not find "update-grub" or "grub2-mkconfig" or "grub-mkconfig" command'
fi

grub_temp_file=$(mktemp)
grub_dir=$(dirname "$grub_cfg")

__log 'Checking grub.cfg ...'
[[ ! -f "${grub_cfg}" ]] && __fatal "Error! Not Found ${grub_cfg} ..."

__log 'Backing up and restoring GRUB configuration files ...'
[[ ! -f "${grub_cfg}.old" && -f "${grub_cfg}.bak" ]] && mv -f "${grub_cfg}.bak" "${grub_cfg}.old"
mv -f "${grub_cfg}" "${grub_cfg}.bak"
cat "${grub_cfg}.old" >"${grub_cfg}" 2>/dev/null || cat "${grub_cfg}.bak" >"${grub_cfg}"

__log 'looking grub.cfg  menuentry ...'
# Get the first menuentry block
sed -n '/^menuentry /{:a;N;/\}$/!ba;p;q;}' "$grub_cfg" | sed '/^\s*$/d' > "$grub_temp_file"
sed -i "s/menuentry.*/menuentry 'Install OS [$suite]' --class debian --class gnu-linux --class gnu --class os \{/" "$grub_temp_file"

# Delete Miscellaneous 
sed -i "/echo.*Loading/d" "$grub_temp_file";

# Get the insertion row number
insert_row_num=$(awk '/^menuentry /{print NR; exit}' "${grub_cfg}");
boot_check=$([[ -n "$(grep 'linux.*/\|kernel.*/' $grub_temp_file |awk '{print $2}' |tail -n 1 |grep '^/boot/')" ]] && echo "inboot" || echo "noboot");

linux_kernel="$(grep 'linux.*/\|kernel.*/' $grub_temp_file |awk '{print $1}' |head -n 1)";
[[ -z "$linux_kernel" ]] && __fatal "Error! read grub config! ";
linux_image="$(grep 'initrd.*/' $grub_temp_file |awk '{print $1}' |tail -n 1)";
[ -z "$linux_image" ] && sed -i "/$linux_kernel.*\//a\\\tinitrd\ \/" "$grub_temp_file" && linux_image='initrd';

# generating boot options
add_option=$([[ "$ethx_mode" == '1' ]] && echo "net.ifnames=0 biosdevname=0")$([[ "$lowmem_mode" == '1' ]] && echo " lowmem=+2")
boot_option="auto=true $add_option hostname=$hostname domain=$hostname quiet"

[[ "$boot_check" == 'inboot' ]] && {
  sed -i "/$linux_kernel.*\//c\\\t$linux_kernel\\t\/boot\/vmlinuz $boot_option" "$grub_temp_file";
  sed -i "/$linux_image.*\//c\\\t$linux_image\\t\/boot\/initrd.gz" "$grub_temp_file";
}

[[ "$boot_check" == 'noboot' ]] && {
  sed -i "/$linux_kernel.*\//c\\\t$linux_kernel\\t\/vmlinuz $boot_option" "$grub_temp_file";
  sed -i "/$linux_image.*\//c\\\t$linux_image\\t\/initrd.gz" "$grub_temp_file";
}

sed -i '$a\\n' "$grub_temp_file";
sed -i ''${insert_row_num}'i\\n' $grub_cfg;
sed -i ''${insert_row_num}'r '${grub_temp_file}'' $grub_cfg;
[[ -f  $grub_dir/grubenv ]] && sed -i 's/saved_entry/#saved_entry/g' $grub_dir/grubenv;
rm -rf "$grub_temp_file";

[[ -d /tmp/boot ]] && rm -rf /tmp/boot;
mkdir -p /tmp/boot;
cd /tmp/boot;

gzip -d < /tmp/initrd.gz | cpio --extract --verbose --make-directories --no-absolute-filenames >>/dev/null 2>&1

initrd_kernel_version=$(ls -1 ./lib/modules 2>/dev/null |head -n1)
[ -n "$initrd_kernel_version" ] && lowmem_pkgs="di-utils-exit-installer,driver-injection-disk-detect,fdisk-udeb,netcfg-static,parted-udeb,partman-auto,partman-ext3,ata-modules-${initrd_kernel_version}-di,efi-modules-${initrd_kernel_version}-di,sata-modules-${initrd_kernel_version}-di,scsi-modules-${initrd_kernel_version}-di,scsi-nic-modules-${initrd_kernel_version}-di" || lowmem_pkgs=""


# fix some vps
function is_grub_dir_linked() {
    [ "$(readlink -f /boot/grub/grub.cfg)" = /boot/grub2/grub.cfg ] ||
    [ "$(readlink -f /boot/grub2/grub.cfg)" = /boot/grub/grub.cfg ] ||
    { [ -f /boot/grub2/grub.cfg ] && [ "$(cat /boot/grub2/grub.cfg)" = 'chainloader (hd0)+1' ]; }
}

if is_grub_dir_linked; then
    __hack_grub='mkdir /target/boot/grub2; echo "chainloader (hd0)+1" >/target/boot/grub2/grub.cfg;ln -s grub /target/boot/grub2;'
fi

__log 'generating preseed.cfg ...'
cat >/tmp/boot/preseed.cfg<<EOF
d-i debian-installer/language string en
d-i debian-installer/country string US
d-i debian-installer/locale string en_US.UTF-8
d-i keyboard-configuration/xkb-keymap select us

d-i lowmem/low note
d-i anna/choose_modules_lowmem multiselect $lowmem_pkgs

d-i netcfg/choose_interface select $interface

d-i netcfg/disable_autoconfig boolean true
d-i netcfg/dhcp_failed note
d-i netcfg/dhcp_options select Configure network manually
d-i netcfg/get_ipaddress string $selected_ip
d-i netcfg/get_netmask string $selected_netmask
d-i netcfg/get_gateway string $selected_gw
d-i netcfg/get_nameservers string $selected_dns
d-i netcfg/no_default_route boolean true
d-i netcfg/confirm_static boolean true

d-i netcfg/get_hostname string $hostname
d-i netcfg/get_domain string 

d-i hw-detect/load_firmware boolean true

d-i mirror/country string manual
d-i mirror/protocol string https
d-i mirror/https/hostname string deb.debian.org
d-i mirror/https/directory string /debian
d-i mirror/https/proxy string 
d-i mirror/suite string $suite

d-i passwd/root-login boolean ture
d-i passwd/make-user boolean false
d-i passwd/root-password-crypted password $enc_pwd
#d-i user-setup/allow-password-weak boolean true
d-i user-setup/encrypt-home boolean false

d-i anna/choose_modules string network-console
d-i preseed/early_command string anna-install network-console
d-i network-console/password password $pwd
d-i network-console/password-again password $pwd
d-i network-console/start select Continue

d-i clock-setup/utc boolean true
d-i time/zone string US/Eastern
d-i clock-setup/ntp boolean true

#d-i partman-auto/disk string $disk
d-i partman/early_command string echo 'init disk';\
find_disk() { \
    for device in \$(list-devices disk); do \
       local d_size=\$(blockdev --getsize64 \$device); \
        if [ \$d_size -eq \$1 ]; then find=\$device;fi; \
    done; \
    if [ -z "\$find" ]; then echo \$(list-devices disk | head -n 1); else echo \$find;fi; \
}; \
ins_disk=\$(find_disk $find_by_size); \
debconf-set partman-auto/disk \$ins_disk; \
debconf-set grub-installer/bootdev \$ins_disk; 

d-i partman-partitioning/choose_label string gpt
d-i partman-partitioning/default_label string gpt
d-i partman-efi/non_efi_system boolean true

d-i partman-partitioning/confirm_write_new_label boolean true
d-i partman/mount_style select uuid
d-i partman/choose_partition select finish
d-i partman-auto/method string regular
d-i partman-auto/init_automatically_partition select Guided - use entire disk
d-i partman-auto/choose_recipe select All files in one partition (recommended for new users)
d-i partman-md/device_remove_md boolean true
d-i partman-lvm/device_remove_lvm boolean true
d-i partman-lvm/confirm boolean true
d-i partman-lvm/confirm_nooverwrite boolean true
d-i partman/confirm boolean true
d-i partman/confirm_nooverwrite boolean true
d-i partman/default_filesystem string $filesystem

d-i debian-installer/allow_unauthenticated boolean true

d-i apt-setup/services-select multiselect $apt_services
# tasksel tasksel/first multiselect minimal, ssh-server
tasksel tasksel/first multiselect ssh-server
d-i pkgsel/update-policy select none
d-i pkgsel/include string $install_softs
d-i pkgsel/upgrade select $upgrade

popularity-contest popularity-contest/participate boolean false

d-i grub-installer/only_debian boolean true
#d-i grub-installer/bootdev string $disk
d-i grub-installer/force-efi-extra-removable boolean true
d-i debian-installer/add-kernel-opts string $kernel_params
d-i finish-install/reboot_in_progress note
d-i debian-installer/exit/reboot boolean true
d-i preseed/late_command string	\
$__hack_grub \
echo '@reboot root cat /etc/run.sh 2>/dev/null |base64 -d >/tmp/run.sh; cat /etc/ip.sh 2>/dev/null |base64 -d >/tmp/ip.sh; rm -rf /etc/run.sh; rm -rf /etc/ip.sh; sed -i /^@reboot/d /etc/crontab; bash /tmp/run.sh; bash /tmp/ip.sh; reboot;' >>/target/etc/crontab; \
echo '' >>/target/etc/crontab; \
echo '${opt_cmd}' >/target/etc/run.sh; \
echo '${base64_ipdata}' >/target/etc/ip.sh;
EOF

__log 'Setting custom options ...'
if [[ "$is_uefi" != 'true' ]]; then
  sed -i '/d-i partman-efi\/non_efi_system boolean true/d' /tmp/boot/preseed.cfg
fi
if [[ "$force_gpt" != '1' ]]; then
  sed -i '/d-i partman-partitioning\/choose_label string gpt/d' /tmp/boot/preseed.cfg
  sed -i '/d-i partman-partitioning\/default_label string gpt/d' /tmp/boot/preseed.cfg
fi
sed -i '/pkgsel\/update-policy/d' /tmp/boot/preseed.cfg

[[ -f '/tmp/firmware.cpio.gz' ]] && gzip -d < /tmp/firmware.cpio.gz | cpio --extract --verbose --make-directories --no-absolute-filenames >>/dev/null 2>&1
find . | cpio -H newc --create --verbose | gzip -6 > /tmp/initrd.gz;

cp -f /tmp/initrd.gz /boot/initrd.gz || sudo cp -f /tmp/initrd.gz /boot/initrd.gz
cp -f /tmp/vmlinuz /boot/vmlinuz || sudo cp -f /tmp/vmlinuz /boot/vmlinuz
chown root:root ${grub_cfg}
chmod 444 ${grub_cfg}

__log 'Confirmation Information: '
if [ -n "$ipv4_address" ] && [ -n "$ipv4_prefix" ] && [ -n "$ipv4_gateway" ]; then
  __log "IPv4 Address: $ipv4_address"
  __log "IPv4 Netmask: $ipv4_netmask"
  __log "IPv4 Prefix: $ipv4_prefix"
  __log "IPv4 Gateway: $ipv4_gateway"
  __log "IPv4 DNS: $dns"
  __log
fi
if [ -n "$ipv6_address" ] && [ -n "$ipv6_prefix" ] && [ -n "$ipv6_gateway" ]; then
  __log "IPv6 Address: $ipv6_address"
  __log "IPv6 Netmask: $ipv6_netmask"
  __log "IPv6 Prefix: $ipv6_prefix"
  __log "IPv6 Gateway: $ipv6_gateway"
  __log "IPv6 DNS: $dns6"
  __log
fi
__log "Interface: $interface"
__log "Hostname: $hostname"
__log "Install version: $suite"
__log "Install DISK: $disk,$find_by_size"
__log
__log "login_password: $pwd"
__log "Installation Stage SSH Information [installer,$pwd]"
__log 'Use [ CTRL+A ] to check your installation progress.'
__log 'Or [ tail -f /var/log/syslog | grep -v sshd ] to check your installation progress.'
__log
  
[ "$_confirm" = 'n' ] && read -r -p "${1:-[!] This operation will clear all data. Are you sure you want to continue? 😂[y/N]}" _confirm;
case "$_confirm" in
  [yY][eE][sS]|[yY])
    __log 'Server will reboot, waiting 5s. 😂'
    sleep 5 && reboot || sudo reboot >/dev/null 2>&1
    ;;
  *)
    __log 'Oh! Did you mean "goodbye"? Don’t worry, installations can be tricky! 😂'
    exit 0
    ;;
esac
