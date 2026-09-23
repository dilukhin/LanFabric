#!/bin/sh
set -eu
test -r /state/wg0.conf
amneziawg-go -f wg0 &
awg_pid=$!
echo "$awg_pid" > /run/awg-probe.pid
trap 'kill "$awg_pid" 2>/dev/null || true; wait "$awg_pid" 2>/dev/null || true' TERM INT
i=0
while [ ! -S /var/run/amneziawg/wg0.sock ]; do
    kill -0 "$awg_pid"
    i=$((i+1))
    test "$i" -lt 50
    sleep 0.2
done
awg setconf wg0 /state/wg0.conf
ip address add "$VPN_ADDRESS" dev wg0
ip link set wg0 up
if [ "${ROLE:-}" = gateway ]; then
    iptables -P FORWARD DROP
    iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT
    iptables -A FORWARD -i wg0 -s 10.77.0.2/32 -d 172.29.77.2/32 -j ACCEPT
    iptables -A FORWARD -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables -t nat -A POSTROUTING -s 10.77.0.2/32 -d 172.29.77.2/32 -j MASQUERADE
else
    ip route add 10.77.0.0/24 dev wg0
    ip route add 172.29.77.2/32 dev wg0
fi
wait "$awg_pid"
