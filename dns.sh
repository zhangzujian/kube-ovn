
ip netns add ns1
ip link add veth1 type veth peer name veth2
ip link set veth2 netns ns1
ip link set veth1 up
nsenter --net=/var/run/netns/ns1 ip link set veth2 up
nsenter --net=/var/run/netns/ns1 ip address add 1.1.1.2/24 dev veth2
nsenter --net=/var/run/netns/ns1 ip neigh replace 1.1.1.1 lladdr 00:11:22:33:44:55 dev veth2

ovs-vsctl add-br br0
ip link set br0 up
ip address add 1.1.1.1/24 dev br0

ovs-vsctl add-port br0 veth1
ip neigh replace 1.1.1.2 lladdr ff:ff:ff:ff:00:01 dev br0
nsenter --net=/var/run/netns/ns1 ping -n -c1 -w1 1.1.1.1

# ovs-ofctl add-flow br0 'table=0,priority=110,icmp,in_port=LOCAL,NXM_OF_ETH_DST[16..47]=0xffffffff,actions=move:NXM_OF_ETH_DST[0..15]->NXM_OF_IN_PORT[],output=in_port'
# ovs-ofctl add-flow br0 'table=0,priority=90,dl_dst=ff:ff:ff:ff:00:00/ff:ff:ff:ff:00:00,icmp,actions=load:0xffffffff->NXM_OF_ETH_DST[16..47],move:NXM_OF_IN_PORT[]->NXM_OF_ETH_DST[0..15],LOCAL'

ovs-ofctl add-flow br0 'table=0,priority=110,udp,in_port=LOCAL,dl_src=ff:ff:ff:ff:00:00/ff:ff:ff:ff:00:00,actions=move:NXM_OF_ETH_SRC[0..15]->NXM_NX_REG1[16..31],output:NXM_NX_REG1[16..31]'

ovs-ofctl add-flow br0 'table=0,priority=110,udp,in_port=LOCAL,dl_src=ff:ff:ff:ff:00:01,actions=1'
ovs-ofctl add-flow br0 'table=0,priority=110,udp6,in_port=LOCAL,dl_src=ff:ff:ff:ff:00:01,actions=1'
ovs-ofctl add-flow br0 'table=0,priority=100,in_port=LOCAL,actions=drop'
ovs-ofctl add-flow br0 'table=0,priority=90,udp,actions=load:0xffffffff->NXM_OF_ETH_DST[16..47],move:NXM_OF_IN_PORT[]->NXM_OF_ETH_DST[0..15],LOCAL'
ovs-ofctl add-flow br0 'table=0,priority=90,udp6,actions=load:0xffffffff->NXM_OF_ETH_DST[16..47],move:NXM_OF_IN_PORT[]->NXM_OF_ETH_DST[0..15],LOCAL'


nsenter --net=/var/run/netns/ns1 ping -n -c1 -w1 1.1.1.1



nsenter --net=/var/run/netns/ns1 nslookup foo.bar. 1.1.1.1

# read/write internal port tap device?

