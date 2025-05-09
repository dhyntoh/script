## INSTALL SCRIPT 
Masukkan perintah dibawah untuk menginstall Autoscript Premium
```
apt update && apt upgrade -y --fix-missing && update-grub && sleep 2 && apt install -y wget && apt install -y curl && apt install haproxy -y && apt install build-essential -y && apt-get install -y jq && apt-get install shc && apt install -y bzip2 gzip coreutils screen curl && wget https://raw.githubusercontent.com/dhyntoh/script/main/setup.sh && chmod +x setup.sh && ./setup.sh
```
#
#
## JIKA GAGAL PAKAI YANG INI
```
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt upgrade -y --fix-missing && update-grub && sleep 2 && apt install -y wget && apt install -y curl && apt install haproxy -y && apt install build-essential -y && apt-get install -y jq && apt-get install shc && apt install -y bzip2 gzip coreutils screen curl && wget https://raw.githubusercontent.com/dhyntoh/script/main/setup.sh && chmod +x setup.sh && ./setup.sh
```

## UPDATE
```
wget https://raw.githubusercontent.com/dhyntoh/script/main/update.sh && chmod +x update.sh && ./update.sh
```

## RESINTALL/REBUILD VPS DO Ubuntu 20 
```
curl -O https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh && bash reinstall.sh ubuntu 20.04 && reboot
```


# pilih salah satu repo utk mempercepat proses instalasi 
#id 1
```
[[ -e $(which curl) ]] && if [[ -z $(cat /etc/resolv.conf | grep "8.8.8.8") ]]; then cat <(echo "nameserver 8.8.8.8") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi && curl -LksS -4 "https://raw.githubusercontent.com/izulx1/repo/master/repoindo.sh" -o repoindo && chmod +x repoindo && ./repoindo id1
```
#id 2
```
[[ -e $(which curl) ]] && if [[ -z $(cat /etc/resolv.conf | grep "8.8.8.8") ]]; then cat <(echo "nameserver 8.8.8.8") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi && curl -LksS -4 "https://raw.githubusercontent.com/izulx1/repo/master/repoindo.sh" -o repoindo && chmod +x repoindo && ./repoindo id2
```
#id 3
```
[[ -e $(which curl) ]] && if [[ -z $(cat /etc/resolv.conf | grep "8.8.8.8") ]]; then cat <(echo "nameserver 8.8.8.8") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi && curl -LksS -4 "https://raw.githubusercontent.com/izulx1/repo/master/repoindo.sh" -o repoindo && chmod +x repoindo && ./repoindo id3
```
# sg
```
[[ -e $(which curl) ]] && if [[ -z $(cat /etc/resolv.conf | grep "8.8.8.8") ]]; then cat <(echo "nameserver 8.8.8.8") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi && curl -LksS -4 "https://raw.githubusercontent.com/izulx1/repo/master/repoindo.sh" -o repoindo && chmod +x repoindo && ./repoindo sg
```
#ori
```
[[ -e $(which curl) ]] && if [[ -z $(cat /etc/resolv.conf | grep "8.8.8.8") ]]; then cat <(echo "nameserver 8.8.8.8") /etc/resolv.conf > /etc/resolv.conf.tmp && mv /etc/resolv.conf.tmp /etc/resolv.conf; fi && curl -LksS -4 "https://raw.githubusercontent.com/izulx1/repo/master/repoindo.sh" -o repoindo && chmod +x repoindo && ./repoindo ori
```