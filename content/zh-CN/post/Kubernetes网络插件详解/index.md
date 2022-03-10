# Kubernetes网络插件详解

## VxLan

### [解读VXLAN](http://www.h3c.com/cn/d_201811/1131076_30005_0.htm)

#### 起源-Origin

传统的交换网络解决了二层的互通及隔离问题，这个架构发展了几十年已经相当成熟。而随着云时代的到来，却渐渐暴露出了一些主要的缺点。

- 多租户环境和虚拟机迁移

  为了满足在云网络中海量虚拟机迁移前后业务不中断的需要，要求虚拟机迁移前后的IP不能变化，继而要求网络必须是大二层结构。传统的二层网络技术，在链路使用率、收敛时间等方面都不能满足需要。

- VLAN的局限

  随着云业务的运营，租户数量剧增。传统交换网络用VLAN来隔离用户和虚拟机，但理论上只支持最多4K个标签的VLAN，已无法满足需求。

#### 竞争-Competition

为了解决上述局限性，不论是网络设备厂商，还是虚拟化软件厂商，都提出了一些新的Overlay解决方案。

- 网络设备厂商，基于硬件设备开发出了EVI（Ethernet Virtualization Interconnect）、TRILL（Transparent Interconnection of Lots of Links)、SPB（Shortest Path Bridging）等大二层技术。这些技术通过网络边缘设备对流量进行封装/解封装，构造一个逻辑的二层拓扑，同时对链路充分利用、表项资源分担、多租户等问题采取各自的解决方法。此类技术一般要求网络边缘设备必须支持相应的协议，优点是硬件设备表项容量大、转发速度快。

- 虚拟化软件厂商，从自身出发，提出了VXLAN（Virtual eXtensible LAN）、NVGRE（Network Virtualization Using Generic Routing Encapsulation）、STT（A Stateless Transport Tunneling Protocol for Network Virtualization）等一系列技术。这部分技术利用主机上的虚拟交换机（vSwitch）作为网络边缘设备，对流量进行封装/解封装。优点是对网络硬件设备没有过多要求。

通过下表我们可以看到这几种Overlay技术对比。 其中，虚拟化软件厂商提出的Overlay技术由于天然支持vSwitch，在云计算网络中更有优势。

![img](各种Overlay技术比较.jpg)

通过下表可以看到VXLAN、NVGRE、STT这三种技术的区别。 与NVGRE相比，VXLAN不需要改变报文结构即可支持L2~L4的链路负载均衡；与STT相比，VXLAN不需要修改传输层结构，与传统网络设备完美兼容。由此，VXLAN脱颖而出，成为了SDN环境下的主流Overlay技术。

![img](VXLAN和NVGRE及STT对比.jpg)

VXLAN是由IETF定义的NVO3（Network Virtualization over Layer 3）标准技术之一，采用MAC-in-UDP的报文封装模式，可实现二层网络在三层范围内进行扩展，满足数据中心大二层虚拟机迁移的需求。在VXLAN网络中，属于相同VXLAN的虚拟机处于同一个逻辑二层网络，彼此之间二层互通；属于不同VXLAN的虚拟机之间二层隔离。

VXLAN最初只在虚拟交换机实现，但虚拟交换机天然具有转发性能低下的缺点，并不适合大流量的网络环境。于是，各硬件厂商也纷纷推出支持VXLAN的硬件产品，与虚拟交换机一起，共同成为网络边缘设备，最终使VXLAN技术能够适应各种网络。

#### 数据平面-Data Plane

##### VXLAN基本概念

![img](VXLAN网络基本模型.jpg)



- **VNI（VXLAN Network Identifier，VXLAN网络标识符）**

  VXLAN通过VXLAN ID来标识，其长度为24比特。VXLAN 16M个标签数解决了VLAN标签不足的缺点。

- **VTEP（VXLAN Tunnel End Point，VXLAN隧道端点）**

  VXLAN的边缘设备。VXLAN的相关处理都在VTEP上进行，例如识别以太网数据帧所属的VXLAN、基于VXLAN对数据帧进行二层转发、封装/解封装报文等。VTEP可以是一台独立的物理设备，也可以是虚拟机所在服务器的虚拟交换机。

- **VXLAN Tunnel**

  两个VTEP之间点到点的逻辑隧道。VTEP为数据帧封装VXLAN头、UDP头、IP头后，通过VXLAN隧道将封装后的报文转发给远端VTEP，远端VTEP对其进行解封装。

- **VSI（irtual Switching Instance，虚拟交换实例）**

  VTEP上为一个VXLAN提供二层交换服务的虚拟交换实例。VSI可以看作是VTEP上的一台基于VXLAN进行二层转发的虚拟交换机，它具有传统以太网交换机的所有功能，包括源MAC地址学习、MAC地址老化、泛洪等。VSI与VXLAN一一对应。

- **VSI-Interface（VSI的虚拟三层接口）**

  类似于Vlan-Interface，用来处理跨VNI即跨VXLAN的流量。VSI-Interface与VSI一一对应，在没有跨VNI流量时可以没有VSI-Interface。

![img](VTEP中的对应关系.jpg)

现有VTEP设备中，一般用“接口+VLAN”的方式来区分流量与VSI的对应关系，而VSI与VXLAN Tunnel之间既可以建立全连接，也可以根据需求进行关联。

##### VXLAN帧格式

###### RFC7348封装

RFC7348规定了VXLAN报文的格式：

![img](VXLAN报文一般封装.jpg)

- **Outer MAC Header**

  封装外层以太头，14字节，如果有VLAN TAG则为18字节。其中，源MAC地址（Outer Source MAC Address）为源VM所属VTEP的MAC地址，目的MAC地址（Outer Destination MAC Address）为到达目的VTEP的路径上下一跳设备的MAC地址。类型字段为0x0800，指示内层封装的是IP报文。

- **Outer IP Header**

  封装外层IP头，20字节。其中，源IP地址（Outer Source IP Address）为源VM所属VTEP的IP地址，目的IP地址（Outer Destination IP Address）为目的VM所属VTEP的IP地址。协议字段为0x11，指示内层封装的是UDP报文。

- **UDP Header**

  UDP报文头，8字节。其中，UDP目的端口号（UDP Destination Port）固定为4789，指示内层封装报文为VXLAN报文。UDP源端口号（UDP Source Port）为随机任意值，可以用于VTEP之间多路径负载分担的计算。

- **VXLAN Header**

  VXLAN协议新定义的VXLAN头，8字节。

- **Flags**

  8 bit，RRRRIRRR。“I”位为1时，表示VXLAN头中的VXLAN ID有效；为0，表示VXLAN ID无效。“R”位保留未用，设置为0。

- **VXLAN ID(VNI)**

  24 bit，用于标识一个单独的VXLAN网络。

- **Reserved**

  分别为24 bit和8 bit。保留位。

- **Original L2 Frame**

  原始以太网报文。

从报文的封装可以看出，VXLAN头和原始二层报文是作为UDP报文的载荷存在的。在VTEP之间的网络设备，只需要根据Outer MAC Header和Outer IP Header进行转发，利用UDP Source Port进行负载分担，这一过程，与转发普通的IP报文完全相同。这样，除了VTEP设备，现网的大量设备无需更换或升级即可支持VXLAN网络。

不过，新增加的VXLAN报文封装也引入了一个问题，即MTU值的设置。

一般来说，虚拟机的默认MTU为1500 Bytes，也就是说原始以太网报文最大为1500字节。这个报文在经过VTEP时，会封装上50字节的新报文头（VXLAN头8字节+UDP头8字节+外部IP头20字节+外部MAC头14字节），这样一来，整个报文长度达到了1550字节。而现有的VTEP设备，一般在解封装VXLAN报文时，要求VXLAN报文不能被分片，否则无法正确解封装。这就要求VTEP之间的所有网络设备的MTU最小为 1550字节。

如果中间设备的MTU值不方便进行更改，那么设置虚拟机的MTU值为1450，也可以暂时解决这个问题。

###### VXLAN GPE封装

RFC7348中规定的VXLAN内部的载荷报文必须是以太网报文，这就限制了VXLAN协议的使用范围。为了让VXLAN能够更广泛的支持其他协议报文的Overlay传输，RFC草案正在探索VXLAN Generic Protocol Encapsulation （GPE）即VXLAN通用协议封装。

![img](VXLAN报文GPE封装.jpg)

GPE封装使用了原FRC7348中规定的一些保留位。

- **Version(Ver)**：指示VXLAN GPE协议版本。初始值为0。

- **Next Protocol Bit (P bit)**：如果P位为1，则Next Protocol域有效。

- **BUM Traffic Bit (B bit)**： 如果B位为1，则表示VXLAN内部的封装报文为BUM报文。

- **OAM Flag Bit (O bit)**：如果O位为1，则表示VXLAN内部的封装报文为OAM报文。

- **Next Protocol**：8位。表示VXLAN内部的封装报文的协议格式。

VXLAN的GPE封装还处于草案阶段，读者只需要了解VXLAN协议还在不断的发展中，暂时不必深究GPE封装的格式和应用。

##### BUM报文转发

BUM（Broadcast, Unknown-unicast, Multicast）即广播、未知单播、组播流量。根据对泛洪流量的复制方式不同可分为单播路由方式（头端复制）和组播路由方式（核心复制）两种。

###### 单播路由方式泛洪（头端复制）

![img](单播路由方式泛洪.jpg)

在头端复制方式下，VTEP负责复制报文，采用单播方式将复制后的报文通过本地接口发送给本地站点，并通过VXLAN隧道发送给VXLAN内的所有远端VTEP。

如图5所示，当VTEP 1上的VM 1发出BUM报文后，VTEP 1判断数据所属的VXLAN，通过该VXLAN内所有本地接口和VXLAN Tunnel转发报文。通过VXLAN Tunnel转发报文时，封装VXLAN头、UDP头和IP头，将泛洪报文封装于单播报文中，发送到VXLAN内的所有远端VTEP。

远端VTEP收到VXLAN报文后，解封装报文，将原始数据在本地站点的VXLAN内泛洪。为避免环路，远端VTEP从VXLAN隧道上接收到报文后，不会再将其泛洪到其他的VXLAN隧道。

###### 组播路由方式泛洪（核心复制）

![img](组播路由方式泛洪.jpg)

组播路由方式的组网中同一个VXLAN内的所有VTEP都加入同一个组播组，利用组播路由协议（如PIM）在IP网络上为该组播建立组播转发表项，VTEP上相应生成一个组播隧道。

如图所示，当VTEP 1上的VM 1发出BUM报文后，VTEP 1不仅在本地站点内泛洪，还会为其封装组播目的IP地址，封装后的报文根据已建立的组播转发表项转发到IP网络。

在组播报文到达IP网络中的中间设备时，该设备根据已建立的组播表项对报文进行复制并转发。

远端VTEP（VTEP 2和VTEP 3）接收到报文后，解封装报文，将原始的数据帧在本地站点的指定VXLAN泛洪。为了避免环路，远端VTEP从VXLAN隧道上接收到报文后，不会再将其泛洪到其他的VXLAN隧道。

由于泛洪流量使用了组播技术，所以整个组网中的网络设备需要支持组播路由协议（如PIM等）来建立组播路径以便组播报文转发。

##### 单播报文转发流程

下面，我们用实际的例子帮助大家理解VXLAN是如何完成报文转发的，其中，BUM报文采用头端复制的方法进行泛洪。

###### 同VNI单播报文转发流程

![img](ARP请求报文转发流程.jpg)

**ARP请求报文转发流程**

1. VM 1与VM3的IP地址在同一网段。VM 1想要与VM 3进行通信，但发现没有VM 3的MAC地址，于是发起VM 3的ARP请求报文。ARP请求报文的源IP是VM 1的IP，目的IP是VM 3的IP，源MAC是VM 1的MAC，目的MAC则是全0字段，表示希望获得VM 3的MAC信息。外层封装以太网头，其中目的MAC为全F，表示这是一个广播报文。

2. Leaf A收到了VM 1发来的ARP请求报文，根据其入端口和VLAN信息，判断出这个报文应该匹配VXLAN 10。将VXLAN、MAC、入端口和VLAN信息写入相应的VSI MAC表中。

3. Leaf A发现ARP请求报文是一个广播报文，于是将这个报文在本地和远端所有VXLAN 10的端口进行广播。由于本流程广播采用头端复制的方法，Leaf A将给Leaf B和Spine C各发送一份VXLAN报文。Leaf A发送给Leaf B的报文，最外层是以太网头，接着是IP头，其中源IP是Leaf A的IP，目的IP是Leaf B的IP。再往内是UDP头和VXLAN头，其中VNI为10。最内层是VM 1的ARP请求报文。Leaf A发给Spine C的报文封装相同，不同之处在于外层目的IP是Spine C的IP，外层目的MAC根据下一跳不同而不同。

4. Spine C收到Leaf A发来的报文，发现外层目的IP是自己，于是将其解封装。发现UDP的目的端口是4789，于是将UDP的上层报文进行VXLAN解封装处理。根据VXLAN报文的信息，将VXLAN、内部MAC、入端口等信息写入相应的VSI MAC表中。再发现内部原始二层报文是一个广播报文，根据水平分割的要求，不再往其他VTEP设备转发，只在本地的VXLAN 10端口内进行广播。由于Spine C上没有连接服务器，所以Spine C对这个报文不再进行后续处理，予以丢弃。

5. 同样的，Leaf B也收到Leaf A发来的报文，解封装后，将VXLAN、内部MAC、入端口等信息写入相应的VSI MAC表中。由于报文是从Tunnel 1中收到的，所以端口信息为Tunnel 1。根据VXLAN 10的映射关系表，将原始二层报文在本地所有VXLAN 10端口进行广播.

6. 最终VM 3收到了VM 1的ARP请求报文，将VM 1的IP和MAC对应关系写入自己的ARP表项，准备进行ARP应答。

![img](ARP应答报文转发流程.jpg)

**ARP应答报文转发流程**

1. VM 3给VM 1发送ARP应答报文。ARP应答报文的源IP是VM 3的IP，目的IP是VM 1的IP，源MAC是VM 3的MAC，目的MAC是VM 1的MAC。外层封装以太网头，源MAC是VM 3的MAC，目的MAC是VM 1的MAC，表示这是一个单播报文。

2. Leaf B收到VM3发来的ARP应答报文，根据其入端口和VLAN信息，判断出这个报文应该匹配VXLAN 10。将VXLAN、MAC、入端口和VLAN信息写入相应的VSI MAC表中。

3. Leaf B发现ARP应答报文是一个单播报文，其目的MAC是MAC 1，于是在VXLAN 10中查找。发现MAC 1的条目存在，其对应的端口为VXLAN Tunnel 1，于是把原始报文进行VXLAN封装。最外层是以太网头，接着是IP头，其中源IP是Leaf B的IP，目的IP是Leaf A的IP。再往内是UDP头和VXLAN头，其中VNI为10。最内层是VM 3的ARP应答报文。

4. Leaf A收到Leaf B发来的报文，发现外层目的IP是自己，于是将其解封装。发现UDP的目的IP是4789，于是将UDP的上层报文进行VXLAN解封装处理。根据VXLAN报文的信息，将VXLAN、内部MAC、入端口等信息写入相应的VSI MAC表中。发现原始二层报文的目的MAC为MAC 1，于是在VXLAN 10中查找，找到MAC 1的对应表项，将报文从对应端口发送出去。

5. VM 1收到了VM 3的ARP应答报文，将VM 3的IP和MAC写入ARP表项中，完成了此次ARP的学习。

![img](同VNI单播报文转发流程.jpg)

**同VNI单播报文转发流程**

1. 在进行ARP报文的交互后，VM 1上已经存在VM 3的ARP表项，VM 3上也有VM 1的ARP表项。之后，VM 1和VM 3的通信就走单播报文转发流程了。

2. VM 1将发给VM 3的单播报文发送出去。Leaf A收到VM 1发来的报文，发现其目的MAC为MAC 3，在VXLAN 10中查找到MAC 3后，进行VXLAN封装后通过Tunnel 1发送出去。

3. Leaf B收到Leaf A发来的报文，解封装后在VXLAN 10中找到MAC 3表项，将其在对应的本地端口和VLAN中发出去。

4. VM 3收到报文后，往VM 1发送单播报文的流程相同，在此不再赘述。

###### 跨VNI单播报文转发

![img](跨VNI单播报文转发.jpg)

跨VNI的流量需要经过VXLAN L3 Gateway（VXLAN L3 Gateway用于转发跨VXLAN的流量，后文有详细介绍）来转发，这里采用集中式网关的模式进行说明。有关集中式网关和分布式网关的内容，在后文中会说明。

由于是首次进行通信，且VM 1和VM 4处于不同网段。VM 1的网关VSI-Interface 10的IP为IP G10，MAC为MAC G10；VM4的网关VSI-Interface 20的IP为IP G20，MAC为MAC　　G20；VSI-interface 10 和VSI-interface 20均在Spine C上。VM 1需要先发送ARP广播报文请求网关（VSI-Interface 10）的MAC，获得网关的MAC后，VM 1先将数据报文发送给网关；之后网关也将发送ARP广播报文请求VM 4的MAC，获得VM 4的MAC后，网关再将数据报文发送给VM 4。以上MAC地址学习的过程与同子网互通中MAC地址学习的流程一致，不再赘述。现在假设VM 1和VM 4均已学到网关的MAC、网关也已经学到VM 1和VM 4的MAC，下面就让我们来看下数据报文是如何从VM 1发送到VM 4的。

1. VM 1先将报文发送给网关。报文的源MAC是VM 1的MAC，目的MAC是网关VSI-Interface 10的MAC，源IP是VM 1的IP，目的IP是VM 4的IP。

2. Leaf A收到VM 1发来的报文，识别此报文属于VXLAN 10，查找目的MAC G10的表项，就报文进行VXLAN封装后从Tunnel 2发送出去。其中，VXLAN头中的VNI为10；外层源IP地址为Leaf A的IP，外层目的IP地址为Spine C的IP；外层源MAC地址为Leaf A的MAC，而外层目的MAC地址为去往目的IP的网络中下一跳设备的MAC地址。封装后的报文，根据外层MAC和IP信息，在IP网络中进行传输，直至到达对端VTEP。

3. Spine C收到Leaf A发来的报文，发现外层目的IP是自己，于是对报文进行解封装。解完封装后，Spine C发现原始二层报文的目的MAC为本机VSI-interface 10的MAC，目的IP是IP4，于是根据路由表查找IP 4的下一跳。发现一下跳为Leaf B，出接口为VSI-Interface 20。再查询ARP表项，并将原始二层报文的源MAC修改为VSI-interface 20的MAC，将目的MAC修改为VM 4的MAC。报文到达VSI-interface 20接口时，识别到需要进入VXLAN 20隧道，所以根据MAC表对报文进行封装。这里封装的VXLAN头中的VNI为20，外层源IP地址为Spine C的IP地址，外层目的IP地址为Leaf B的IP地址；外层源MAC地址为Spine C的MAC地址，而外层目的MAC地址为去往目的IP的网络中下一跳设备的MAC地址。封装后的报文，根据外层MAC和IP信息，在IP网络中进行传输，直至到达对端VTEP。

4. Leaf B收到Spine C发来的报文后，解封装，得到原始二层报文。在VXLAN 20内找到目的MAC为MAC 4的表项，并将报文从对应的接口和VLAN中发送出去。最终VM 4收到了来自VM 1的报文。

5. VM 4发送给VM 1的过程与此类似，在此不再赘述。

#### VXLAN三层网关-L3 Gateway

VXLAN三层网关提供了VXLAN的三层转发功能，通过将VXLAN关联VSI虚接口（VXLAN虚接口）的方式实现，在VSI虚接口指定IP地址作为VXLAN内所有虚拟机的网关。

VXLAN三层网关的主要功能：

- 实现VXLAN内虚拟机与非VXLAN网络的互访

- 完成跨VXLAN的虚拟机互访

VXLAN三层网关根据其部署方式不同，有集中式和分布式两种。

##### 集中式三层网关

![img](集中式三层网关.jpg)

集中式网关，即网关都集中在Spine设备。如图10所示，VSI-interface 10和VSI-interface 20都在Spine C设备上。所有跨VXLAN的流量，VXLAN与非VXLAN的互访流量都需要经过Spine。如图10中VM 1访问VM 4时，需要通过Spine设备，并经过两段VXLAN Tunnel，即VXLAN Tunnel 2和VXLAN Tunnel 3。而VM 1访问VM 2，也需要绕行Spine设备，同样需要历经从A到C和从C到A两次VXLAN封装。

集中式网关的优点是流量均会经过Spine设备，能比较容易实现流量控制、自动引流等功能。缺点是Spine设备压力过大，不利于大规模部署。

##### 分布式三层网关

在分布式VXLAN 三层网关方案中，每台VTEP设备都可以作为VXLAN IP网关，对本地站点的流量进行三层转发。分布式三层网关可以很好地解决流量集中而导致Spine设备压力过大的问题，在组网上也可以做到灵活扩展。

![img](分布式三层网关.jpg)

在分布式网关组网中，Spine设备一般不是VTEP，仅为Underlay网络的一部分，承担普通IP报文的转发功能。

VXLAN的三层网关分布在所有的Leaf设备上。如图12，Leaf A和Leaf B上均有相同的VSI-Interface。VM 1访问VM 4为跨网段通信，VXLAN流量只需要在Leaf A和Leaf B之间直接交互，而不用Spine设备参与。VM 1访问VM 2也是跨网段通信，由于VM 1和VM 2都直连在Leaf A下，VXLAN流量甚至不用出Leaf A就能完成互访。由此，我们能看出，分布式网关的部署方式大大减少了Spine设备的压力。

##### 4.3 ARP抑制

ARP流量是数据网络中最常见的BUM报文。为了尽量减少ARP广播对带宽的影响，一般会在VXLAN网络中开启ARP抑制功能。

ARP抑制方法有两种，我们称之为ARP代理和ARP代答。

###### ARP代理

在ARP代理模式中，VTEP设备会用网关自身的MAC地址进行回应ARP请求。

![img](ARP代理模式.jpg)

1. VM 1想要和同网段的VM 3进行通信，于是VM 1发起了ARP请求寻找VM 3的MAC。

2. Leaf A开启了ARP代理模式，于是将VSI-Interface 10的MAC回应给VM 1，VM 1上生成了IP 3和MAC G10对应的ARP表项。

3. Leaf A若是没有VM 3的ARP表项，则会在VXLAN中的所有本地和远端端口广播。Leaf A将ARP请求报文的源MAC地址修改成本地地址MAC A，再封装成VXLAN报文发送出去。

4. Leaf B收到Leaf A发来的报文，解封装后，将IP 1与MAC A的对应关系写进表项。发现请求的是本地直连网段的ARP，于是将ARP请求报文中的源MAC地址修改成本地VSI-Interface 10的MAC，发送出去。

5. VM 3收到Leaf B发来的ARP请求报文，将IP 1和MAC G10的对应关系写进自己的ARP表。然后开始回送ARP应答报文，一路回送，最终Leaf A学到了IP 3与MAC B的对应表项。

6. VM 1发送数据报文给VM 3，目的MAC地址为Leaf A上的网关MAC。Leaf A收到报文后，发现目的MAC地址是VSI-interface 10的MAC，于是进行三层查表转发。找到IP 3对应的表项，将目的MAC改为Leaf B的MAC后，再把报文进行VXLAN封装发送给Leaf B。

7. Leaf B解封装VXLAN报文后，发现目的MAC是自己，于是进行三层查表转发。找到IP 3对应的表项，将目的MAC改为VM 3的MAC后，发送给VM 3。VM 3收到VM 1发来的数据报文，回送过程不再赘述。

在ARP代理模式下，网关设备在回应ARP时，只会以自己的网关MAC进行回应，这就将所有下挂的服务器MAC进行了屏蔽，实现了ARP抑制的作用。而在数据转发时，由于报文的目的MAC是自己，所以每一跳都会进行三层查表转发。

###### ARP代答

在ARP代答模式中，VTEP设备会将用请求虚拟机的实际MAC回应ARP请求。

![img](ARP代答模式.jpg)

ARP代答模式下的首次ARP请求和前文“同VNI单播报文转发流程”章节中的过程相同。在VM 1和VM 3已经在经过flood-learn的过程后，VM 1和VM 3已经可以正常通信，且沿途的设备均已建立正确的表项。

此时，处于同一网段的VM2，同样想要和VM 3通信时，就需要发送ARP请求报文来寻找VM 3的MAC信息。Leaf A已经开启了ARP代答功能，且此时Leaf A上已经有了VM 3的IP和MAC对应表项，那么Leaf A会直接将表项中的MAC 3回应给VM 2，而不需要再经过一次泛洪。这样，ARP代答就可以大大减少ARP泛洪流量。而ARP代答若是配合可以在全网VTEP同步IP和MAC信息的VXLAN控制平面，那么ARP泛洪流量对带宽的影响可以降至最低。

#### 控制平面-Control Plane

RFC7348只规定了VXLAN协议的数据平面，对控制平面未做任何要求。这样做的好处是，可以使各类设备无须做较大改动就能互相兼容。如前文所述，和传统VLAN网络数据平面一样，数据经过未知单播泛洪->MAC表项及ARP表项建立->单播转发的过程，我们称之为自学习模式。但自学习方式过于简单，其大量的泛洪报文以及无法智能调整的缺点，使得这样的控制平面构建方式不适合SDN网络。

于是，各厂商纷纷探索更为先进的控制平面实现方法。

##### 控制平面的功能

VXLAN控制平面必须实现的功能：

- **VTEP邻居发现**

  VXLAN网络中的VTEP数量众多，类型不同，纯手工配置VTEP非常困难也不利于大规模部署。VXLAN的控制平面应该具有自动发现VTEP邻居、自动建立VXLAN Tunnel、自动进行关联等功能。

- **虚拟机信息同步**

  虚拟机信息同步主要是指MAC及ARP的同步。上线的虚拟机信息需要在各VTEP上同步，下线的虚拟机信息要能够在各VTEP上删除或老化，迁移的虚拟机信息要能够从旧VTEP转移到新VTEP。

除了以上两点之外，不同的控制平面协议还能实现自动部署、灵活调整、策略下发等功能。

##### 基于Controller的控制平面

SDN最大的特点就是转控分离，集中控制。按照这个指导思想，将控制功能单独剥离出来成为一个单独的设备便是很自然的事了。这个设备就是 Controller。

Controller可以是一个或者一组硬件设备，也可以是一套软件。Controller与网络中所有设备建立连接，整个VXLAN网络的数据转发都由Controller来管理。Controller与设备连接的接口称为南向接口，可以使用OpenFlow、Netconf等协议；对用户提供服务的接口称为北向接口，也可以提供API以便与其他管理平台对接或进行深度开发。

基于Controller的控制平面，其SDN网络的功能几乎都依赖于Controller本身的特性，根据Controller的不同，会有不同的实现方式和功能。

![img](基于Controller的控制平面.jpg)

##### 基于VXLAN-ISIS的控制平面

基于VXLAN-ISIS的控制平面利用ENDP（Enhanced Neighbor Discovery Protocol，增强邻居发现协议）和VXLAN-ISIS两个协议共同完成VXLAN所需的自动建立隧道和信息同步功能。这种控制平面利用ISIS协议的可扩展特性来同步VXLAN建立和流量转发所需要的信息，是早期VXLAN控制平面探索时期的成果之一。

##### 基于EVPN的控制平面

RFC7432（BGP MPLS-Based Ethernet VPN）定义了EVPN。EVPN架构是在现有的BGP VPLS（RFC4761）方案上，参考了BGP/MPLS L3 VPN（RFC4364）的架构提出的。

EVPN构建在MP-BGP之上，依靠MP-BGP来传递EVPN信息。EVPN规定了控制平面需要完成的功能，数据平面可以选择MPLS、PBB和VXLAN中的任意一种。

用VXLAN构建数据平面，用EVPN配合来构建控制平面，是当下较为流行的一种方式。

![img](EVPN-VXLAN共同构建SDN网络.jpg)

EVPN利用MP-BGP实现邻居发现，自动发现VXLAN网络中的VTEP，并在有相同VXLAN ID的VTEP之间自动创建VXLAN隧道，自动关联VXLAN隧道和VXLAN。

EVPN利用MP-BGP扩展路由类型报文完成MAC地址同步、主机路由同步。

有关EVPN技术的更详细的内容，后续文章会有相应介绍。

##### 各控制平面特点

最后，我们来比较一下各控制平面的特点。

![img](各控制平面特点.jpg)

#### 未来-Future

VXLAN由于其简单的数据平面，良好的兼容性，已经成为了当下SDN Overlay技术的最好选择，但VXLAN未来还有很长的路要走。比如探索VXLAN GPE封装是一个方向，解决VXLAN隧道的QoS也是一个方向。而控制平面要做的更多，如何更好的实现按需定制，如何实现智能流量调整，如何更好的兼容异构设备等等。相信未来会给我们一个更好的答案。

### [VXLAN 协议原理](https://segmentfault.com/a/1190000022365692)

VXLAN（`Virtual eXtensible Local Area Network`，虚拟可扩展局域网），是一种虚拟化隧道通信技术。它是一种 Overlay（覆盖网络）技术，通过三层的网络来搭建虚拟的二层网络。

简单来讲，`VXLAN` 是在底层物理网络（underlay）之上使用隧道技术，借助 `UDP` 层构建的 Overlay 的逻辑网络，使逻辑网络与物理网络解耦，实现灵活的组网需求。它对原有的网络架构几乎没有影响，不需要对原网络做任何改动，即可架设一层新的网络。也正是因为这个特性，很多 CNI 插件（Kubernetes 集群中的容器网络接口，这个大家应该都知道了吧，如果你不知道，现在你知道了）才会选择 `VXLAN` 作为通信网络。

`VXLAN` 不仅支持一对一，也支持一对多，一个 `VXLAN` 设备能通过像网桥一样的学习方式学习到其他对端的 IP 地址，还可以直接配置静态转发表。

一个典型的数据中心 VXLAN 网络拓扑图如图所示：

![img](VXLAN网络拓扑.png)

其中 VM 指的是虚拟机，`Hypervisor` 指的是虚拟化管理器。

#### 为什么需要 VXLAN？

与 VLAN 相比，`VXLAN` 很明显要复杂很多，再加上 VLAN 的先发优势，已经得到了广泛的支持，那还要 `VXLAN` 干啥？

##### VLAN ID 数量限制

VLAN tag 总共有 4 个字节，其中有 `12 bit` 用来标识不同的二层网络（即 `LAN ID`），故而最多只能支持 $2^{12}$，即 `4096` 个子网的划分。而虚拟化（虚拟机和容器）的兴起使得一个数据中心会有成千上万的机器需要通信，这时候 VLAN 就无法满足需求了。而 VXLAN 的报文 Header 预留了 `24 bit` 来标识不同的二层网络（即 `VNI`，VXLAN Network Identifier），即 3 个字节，可以支持 $2^{24}$ 个子网。

##### 交换机 MAC 地址表限制

对于同网段主机的通信而言，报文到底交换机后都会查询 `MAC` 地址表进行二层转发。数据中心虚拟化之后，VM 的数量与原有的物理机相比呈数量级增长，而应用容器化之后，容器与 VM 相比也是呈数量级增长。。。而交换机的内存是有限的，因而 MAC 地址表也是有限的，随着虚拟机（或容器）网卡 MAC 地址数量的空前增加，交换机表示压力山大啊！

而 VXLAN 就厉害了，它用 `VTEP`（后面会解释）将二层以太网帧封装在 `UDP` 中，一个 `VTEP` 可以被一个物理机上的所有 VM（或容器）共用，一个物理机对应一个 `VTEP`。从交换机的角度来看，只是不同的 `VTEP` 之间在传递 `UDP` 数据，只需要记录与物理机数量相当的 MAC 地址表条目就可以了，一切又回到了和从前一样。

##### 虚机或容器迁移范围受限

VLAN 与物理网络融合在一起，不存在 Overlay 网络，带来的问题就是虚拟网络不能打破物理网络的限制。举个例子，**如果要在 `VLAN 100` 部署虚拟机（或容器），那只能在支持 `VLAN 100` 的物理设备上部署**。

VLAN 其实也有解决办法，就是将所有的交换机 `Trunk` 连接起来，产生一个大的二层，这样带来的问题就是广播域过分扩大，也包括更多未知的单播和多播，即 `BUM`（Broadcast，Unknown Unicast，Multicast），同时交换机 MAC 地址表也会有承受不住的问题。

而 VXLAN 将二层以太网帧封装在 `UDP` 中（上面说过了），相当于在三层网络上构建了二层网络。这样不管你物理网络是二层还是三层，都不影响虚拟机（或容器）的网络通信，也就无所谓部署在哪台物理设备上了，可以随意迁移。

总的来说，传统二层和三层的网络在应对这些需求时变得力不从心，虽然很多改进型的技术比如堆叠、SVF、TRILL 等能够增加二层的范围，努力改进经典网络，但是要做到对网络改动尽可能小的同时保证灵活性却非常困难。为了解决这些问题，有很多方案被提出来，`Overlay` 就是其中之一，而 `VXLAN` 是 `Overlay` 的一种典型的技术方案。下面就对 `Overlay` 做一个简要的介绍。

#### Overlay 是个啥？

`Overlay` 在网络技术领域，指的是一种网络架构上叠加的虚拟化技术模式，其大体框架是对基础网络不进行大规模修改的条件下，实现应用在网络上的承载，并能与其它网络业务分离，并且以基于 IP 的基础网络技术为主。

IETF 在 `Overlay` 技术领域提出 `VXLAN`、`NVGRE`、`STT` 三大技术方案。大体思路均是将以太网报文承载到某种隧道层面，差异性在于选择和构造隧道的不同，而底层均是 IP 转发。`VXLAN` 和 `STT` 对于现网设备而言对流量均衡要求较低，即负载链路负载分担适应性好，一般的网络设备都能对 `L2-L4` 的数据内容参数进行链路聚合或等价路由的流量均衡，而 `NVGRE` 则需要网络设备对 `GRE` 扩展头感知并对 `flow ID` 进行 HASH，**需要硬件升级**；`STT` 对于 `TCP` 有较大修改，隧道模式接近 UDP 性质，隧道构造技术属于革新性，且复杂度较高，而 `VXLAN` 利用了现有通用的 UDP 传输，成熟性极高。

总体比较，`VLXAN` 技术具有更大优势，而且当前 `VLXAN` 也得到了更多厂家和客户的支持，已经成为 `Overlay` 技术的主流标准。

#### VXLAN 协议原理

VXLAN 有几个常见的术语：

- VTEP（VXLAN Tunnel Endpoints，VXLAN 隧道端点）

  VXLAN 网络的边缘设备，用来进行 VXLAN 报文的处理（封包和解包）。VTEP 可以是网络设备（比如交换机），也可以是一台机器（比如虚拟化集群中的宿主机）。

- VNI（VXLAN Network Identifier，VXLAN 网络标识符）

  `VNI` 是每个 VXLAN 段的标识，是个 24 位整数，一共有 $2^{24} = 16777216$（一千多万），一般每个 `VNI` 对应一个租户，也就是说使用 `VXLAN` 搭建的公有云可以理论上可以支撑千万级别的租户。

- Tunnel（VXLAN 隧道）

  隧道是一个逻辑上的概念，在 VXLAN 模型中并没有具体的物理实体向对应。隧道可以看做是一种虚拟通道，VXLAN 通信双方认为自己是在直接通信，并不知道底层网络的存在。从整体来说，每个 VXLAN 网络像是为通信的虚拟机搭建了一个单独的通信通道，也就是隧道。

![img](VXLAN工作模型.png)

上图所示为 `VXLAN` 的工作模型，它创建在原来的 IP 网络（三层）上，只要是三层可达（能够通过 IP 相互通信）的网络就能部署 `VXLAN`。在 VXLAN 网络的每个端点都有一个 `VTEP` 设备，负责 VXLAN 协议报文的解包和封包，也就是在虚拟报文上封装 `VTEP` 通信的报文头部。

物理网络上可以创建多个 `VXLAN` 网络，可以将这些 `VXLAN` 网络看成一个隧道，不同节点上的虚拟机/容器能够通过隧道直连。通过 `VNI` 标识不同的 VXLAN 网络，使得不同的 VXLAN 可以相互隔离。

VXLAN 的报文结构如下图所示：

![img](VXLAN报文结构.png)

- **VXLAN Header** : 在原始二层帧的前面增加 `8` 字节的 VXLAN 的头部，其中最主要的是 `VNID`，占用 `3` 个字节（即 24 bit），类似 VLAN ID，可以具有 $2^{24}$ 个网段。

- **UDP Header** : 在 VXLAN 和原始二层帧的前面使用 `8` 字节 `UDP` 头部进行封装（MAC IN UDP），目的端口号缺省使用 4789，源端口按流随机分配（通过 MAC，IP，四层端口号进行 hash 操作）， 这样可以更好的做 `ECMP`。

  > `IANA`（Internet As-signed Numbers Autority）分配了 `4789` 作为 VXLAN 的默认目的端口号。

在上面添加的二层封装之后，再添加底层网络的 IP 头部（`20` 字节）和 MAC 头部（`14` 字节），**这里的 IP 和 MAC 是宿主机的 IP 地址和 MAC 地址**。

同时，这里需要注意 `MTU` 的问题，传统网络 MTU 一般为 `1500`，这里加上 VXLAN 的封装多出的（36+14/18，对于 `14` 的情况为 `access` 口，省去了 `4` 字节的 VLAN Tag）`50` 或 `54` 字节，需要调整 MTU 为 `1550` 或 `1554`，防止频繁分包。

![img](VXLAN字段解释.png)

#### VXLAN 的 Flood 与 Learn

总的来说，VXLAN 报文的转发过程就是：原始报文经过 `VTEP`，被 Linux 内核添加上 `VXLAN` 头部以及外层的 `UDP` 头部，再发送出去，对端 `VTEP` 接收到 VXLAN 报文后拆除外层 `UDP` 头部，并根据 VXLAN 头部的 `VNI` 把原始报文发送到目的服务器。但这里有一个问题，第一次通信前双方如何知道所有的通信信息？这些信息包括：

- 哪些 `VTEP` 需要加到一个相同的 VNI 组？
- 发送方如何知道对方的 `MAC` 地址？
- 如何知道目的服务器在哪个节点上（即目的 VTEP 的地址）？

第一个问题简单，VTEP 通常由网络管理员来配置。要回答后面两个问题，还得回到 VXLAN 协议的报文上，看看一个完整的 VXLAN 报文需要哪些信息：

- **内层报文** : 通信双方的 IP 地址已经明确，只需要 VXLAN 填充对方的 `MAC` 地址，因此需要一个机制来实现 `ARP` 功能。

- **VXLAN 头部** : 只需要知道 `VNI`。一般直接配置在 VTEP 上，要么提前规划，要么根据内层报文自动生成。

- **UDP 头部** : 需要知道源端口和目的端口，源端口由系统自动生成，目的端口默认是 `4789`。

- **IP 头部** : 需要知道对端 `VTEP` 的 IP 地址，**这个是最关键的部分**。

  实际上，`VTEP` 也会有自己的转发表，转发表通过泛洪和学习机制来维护，对于目标 MAC 地址在转发表中不存在的未知单播，广播流量，都会被泛洪给除源 VTEP 外所有的 VTEP，目标 VTEP 响应数据包后，源 VTEP 会从数据包中学习到 `MAC`，`VNI` 和 `VTEP` 的映射关系，并添加到转发表中，后续当再有数据包转发到这个 MAC 地址时，VTEP 会从转发表中直接获取到目标 VTEP 地址，从而发送单播数据到目标 VTEP。

  ![img](VXLAN转发学习.png)

  VTEP 转发表的学习可以通过以下两种方式：

  - 多播
  - 外部控制中心（如 Flannel、Cilium 等 CNI 插件）

- **MAC 头部** : 确定了 `VTEP` 的 IP 地址，后面就好办了，MAC 地址可以通过经典的 `ARP` 方式获取。

#### Linux 的 VXLAN

`Linux` 对 VXLAN 协议的支持时间并不久，`2012` 年 Stephen Hemminger 才把相关的工作合并到 kernel 中，并最终出现在 `kernel 3.7.0` 版本。为了稳定性和很多的功能，可能会看到某些软件推荐在 `3.9.0` 或者 `3.10.0` 以后版本的 kernel 上使用 VXLAN。

到了 `kernel 3.12` 版本，Linux 对 VXLAN 的支持已经完备，支持单播和组播，IPv4 和 IPv6。利用 `man` 查看 ip 的 `link` 子命令，可以查看是否有 VXLAN type：

```bash
$ man ip-link
```

搜索 VXLAN，可以看到如下描述：

![img](Linux上的VXLAN.png)

##### 管理 VXLAN 接口

Linux VXLAN 接口的基本管理如下：

1. 创建点对点的 VXLAN 接口：

   ```bash
   $ ip link add vxlan0 type vxlan id 4100 remote 192.168.1.101 local 192.168.1.100 dstport 4789 dev eth0
   ```

   其中 `id` 为 VNI，`remote` 为远端主机的 IP，`local` 为你本地主机的 IP，`dev` 代表 VXLAN 数据从哪个接口传输。

   在 VXLAN 中，**一般将 VXLAN 接口（本例中即 vxlan0）叫做 VTEP**。

2. 创建多播模式的 VXLAN 接口：

   ```bash
   $ ip link add vxlan0 type vxlan id 4100 group 224.1.1.1 dstport 4789 dev eth0
   ```

   多播组主要通过 `ARP` 泛洪来学习 `MAC` 地址，即在 VXLAN 子网内广播 `ARP` 请求，然后对应节点进行响应。`group` 指定多播组的地址。

3. 查看 VXLAN 接口详细信息：

   ```bash
   $ ip -d link show vxlan0
   ```

##### FDB 表

`FDB`（Forwarding Database entry，即转发表）是 Linux 网桥维护的一个二层转发表，用于保存远端虚拟机/容器的 MAC地址，远端 VTEP IP，以及 VNI 的映射关系，可以通过 `bridge fdb` 命令来对 `FDB` 表进行操作：

- 条目添加：

  ```bash
  $ bridge fdb add <remote_host_mac> dev <vxlan_interface> dst <remote_host_ip>
  ```

- 条目删除：

  ```bash
  $ bridge fdb del <remote_host_mac> dev <vxlan_interface>
  ```

- 条目更新：

  ```bash
  $ bridge fdb replace <remote_host_mac> dev <vxlan_interface> dst <remote_host_ip>
  ```

- 条目查询：

  ```bash
  $ bridge fdb show
  ```

#### 总结

本文通过介绍 VXLAN 出现的时代背景、VXLAN 的概念和网络模型、VXLAN 报文结构，让你对 VXLAN 有了初步的认识；通过介绍 VXLAN 转发表的泛洪和学习，让你知道了通信双方如何感知对方；最后介绍了 Linux 中 VXLAN 的基本配置，让你进一步了解如何在 Linux 中玩转 VXLAN。下一篇文章将会通过实战来说明如何搭建基于 VXLAN 的 `Overlay` 网络，顺便展开解读上文提到的多播和外部控制中心的工作原理。

#### 参考资料

- [vxlan 协议原理简介](https://link.segmentfault.com/?enc=W5CQkQSoq1lARWoda7YZ7Q%3D%3D.d50EMqj5EKOLxKQOtBY4DjUzflVgrzel2ISgwvMkzqZVuk%2BMOT1SO1LxODcBL3%2F37YbU%2B8pNHzuCtXq%2F06G5RQ%3D%3D)
- [VXLAN vs VLAN](https://link.segmentfault.com/?enc=hCVcYSOsqOMTqwVPJBQc8g%3D%3D.RgGobMGk2sJBGwwrm0rcXTPn58uADfjQlsPvBeOxYcvmcUxbPI6bTVucFpetMxDZ)

## Flannel

### [Kubernetes Flannel网络分析](http://just4coding.com/2021/11/03/flannel/)

[`flannel`](https://github.com/flannel-io/flannel)是`coreos`开源的`Kubernetes CNI`实现。它使用`etcd`或者`Kubernetes API`存储整个集群的网络配置。每个`kubernetes`节点上运行`flanneld`组件，它从`etcd`或者`Kubernetes API`获取集群的网络地址空间，并在空间内获取一个`subnet`,该节点上的容器`IP`都从这个`subnet`中分配，从而保证不同节点上的`IP`不会冲突。`flannel`通过不同的`backend`来实现跨主机的容器网络通信，目前支持`udp`,`vxlan`,`host-gw`等一系列`backend`实现。本文介绍`vxlan backend`下的容器通信过程。

`flannel`在`v0.9.0`版本上对`vxlan`的实现作了改动。[源码](https://github.com/flannel-io/flannel/blob/v0.9.0/backend/vxlan/vxlan.go`)中有一段非常详细的注释介绍了不同版本的设计与实现:

```
// Some design notes and history:
// VXLAN encapsulates L2 packets (though flannel is L3 only so don't expect to be able to send L2 packets across hosts)
// The first versions of vxlan for flannel registered the flannel daemon as a handler for both "L2" and "L3" misses
// - When a container sends a packet to a new IP address on the flannel network (but on a different host) this generates
//   an L2 miss (i.e. an ARP lookup)
// - The flannel daemon knows which flannel host the packet is destined for so it can supply the VTEP MAC to use.
//   This is stored in the ARP table (with a timeout) to avoid constantly looking it up.
// - The packet can then be encapsulated but the host needs to know where to send it. This creates another callout from
//   the kernal vxlan code to the flannel daemon to get the public IP that should be used for that VTEP (this gets called
//   an L3 miss). The L2/L3 miss hooks are registered when the vxlan device is created. At the same time a device route
//   is created to the whole flannel network so that non-local traffic is sent over the vxlan device.
//
// In this scheme the scaling of table entries (per host) is:
//  - 1 route (for the configured network out the vxlan device)
//  - One arp entry for each remote container that this host has recently contacted
//  - One FDB entry for each remote host
//
// The second version of flannel vxlan removed the need for the L3MISS callout. When a new remote host is found (either
// during startup or when it's created), flannel simply adds the required entries so that no further lookup/callout is required.
//
//
// The latest version of the vxlan backend  removes the need for the L2MISS too, which means that the flannel deamon is not
// listening for any netlink messages anymore. This improves reliability (no problems with timeouts if
// flannel crashes or restarts) and simplifies upgrades.
//
// How it works:
// Create the vxlan device but don't register for any L2MISS or L3MISS messages
// Then, as each remote host is discovered (either on startup or when they are added), do the following
// 1) create routing table entry for the remote subnet. It goes via the vxlan device but also specifies a next hop (of the remote flannel host).
// 2) Create a static ARP entry for the remote flannel host IP address (and the VTEP MAC)
// 3) Create an FDB entry with the VTEP MAC and the public IP of the remote flannel daemon.
//
// In this scheme the scaling of table entries is linear to the number of remote hosts - 1 route, 1 arp entry and 1 FDB entry per host
//
// In this newest scheme, there is also the option of skipping the use of vxlan for hosts that are on the same subnet,
// this is called "directRouting"
```

`v0.9.0`之前版本的实现主要依赖`vxlan`内核模块的`L2MISS`和`L3MISS`消息机制。`L2MISS`是指`vxlan`设备在`ARP`表中找不到内层`IP`对应的`MAC`地址时会给用户态程序发送`netlink`消息。`L3MISS`是指`vxlan`设备在`FDB`表中找不到`VXLAN`协议内层`MAC`地址所属的`VTEP`的`IP`地址时会给用户态程序发送`netlink`消息。之前的文章[<<动态维护FDB表项实现VXLAN通信>>](http://just4coding.com/2020/04/20/vxlan-fdb/)介绍过相关概念和操作。本文主要分析`v0.9.0`版本上的实现方式。



之前的方式实现是，`flanneld`作为`L2MISS`和`L3MISS`消息的处理器,当收到相应消息时从`etcd`或者`kubernetes API`获取到相应的`ARP`或者`FDB`信息来填充相应条目。如果`flanneld`异常退出，那么整个容器网络集群的网络就中断了。这是一个很大的隐患。`v0.9.0`实现不再需要处理`L2MISS`和`L3MISS`消息，而是由`flanneld`通过`watch` `etcd`或者`kubernetes API`的相关节点信息来动态地维护各节点通信所需的`ARP`、`FDB`以及路由条目。即使`flanneld`崩溃，整个集群网络数据转发依然可以运行。这个实现很优雅，每个节点只需要一条路由，一个`ARP`缓存条目和一个`FDB`条目。

下面在实验环境中分析`flannel vxlan`的网络通信过程。整个网络架构如图:

![img](Flannel网络架构.png)

`CNI`配置文件`/etc/cni/net.d/09-flannel.conf`内容如下:

```
{
    "name": "cbr0",
    "cniVersion": "0.3.1",
    "type": "flannel",

    "delegate": {
        "isDefaultGateway": true
    }
}
```

节点上每个`pod`会有一对`veth pair`设备，其中一端放在`pod`的`network namespace`中，另一端在宿主机上接在`cni0`网桥上。`flanneld`启动时创建了`vxlan`设备:`flannel.1`。

`node1`上的`flannel`网络信息如下,分配的`subnet`为`10.230.41.1/24`:

```
[root@node1 ~]# cat /run/flannel/subnet.env
FLANNEL_NETWORK=10.230.0.0/16
FLANNEL_SUBNET=10.230.41.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=false
```

`node2`上的`flannel`网络信息如下, 分配的`subnet`为`10.230.93.1/24`:

```
[root@node2 ~]# cat /run/flannel/subnet.env
FLANNEL_NETWORK=10.230.0.0/16
FLANNEL_SUBNET=10.230.93.1/24
FLANNEL_MTU=1450
FLANNEL_IPMASQ=false
```

我们来看`10.230.41.17`向`10.230.93.2`发送数据包的过程。

`10.230.93.2`与`10.230.41.17`不在同一二层网络，因而需要查找路由来决定由哪个设备发送到哪里。`10.230.41.17`的路由如下:

```
[root@master1 ~]# kubectl exec -it busybox2-6f8fdb784d-r6ln2 -- ip route
default via 10.230.41.1 dev eth0
10.230.0.0/16 via 10.230.41.1 dev eth0
10.230.41.0/24 dev eth0 scope link  src 10.230.41.17
```

匹配到默认路由，因而需要发送到网关`10.230.41.1`。`10.230.41.1`配置在网桥`cni0`上。内核通过`ARP`请求获得`10.230.41.1`的`MAC`地址, 将数据包转发到`cni0`上。

```
[root@node1 ~]# ip addr show dev cni0
5: cni0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UP group default qlen 1000
    link/ether 86:99:b6:37:95:b2 brd ff:ff:ff:ff:ff:ff
    inet 10.230.41.1/24 brd 10.230.41.255 scope global cni0
       valid_lft forever preferred_lft forever
    inet6 fe80::8499:b6ff:fe37:95b2/64 scope link
       valid_lft forever preferred_lft forever
```

`flanneld`在加入集群时会为每个其他节点生成一条`on-link`路由，`on-link`路由表示是直连路由，匹配该条路由的数据包将触发`ARP`请求获取目的IP的`MAC`地址。在`node1`上查看路由信息:

```
[root@node1 ~]# ip route show dev flannel.1
10.230.93.0/24 via 10.230.93.0 onlink
```

`cni0`设备根据这条路由将数据包转给`vxlan`设备`flannel.1`，并且接收端的`IP`地址为`10.230.93.0`, 需要通过`ARP`获取`MAC`地址。

`flannel.1`的信息如下, 可以看到没有开启`l2miss`和`l3miss`:

```
[root@node1 ~]# ip -d link show flannel.1
4: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN mode DEFAULT group default
    link/ether a6:f7:8b:a4:60:b0 brd ff:ff:ff:ff:ff:ff promiscuity 0
    vxlan id 1 local 10.240.0.101 dev eth1 srcport 0 0 dstport 8472 nolearning ageing 300 noudpcsum noudp6zerocsumtx noudp6zerocsumrx addrgenmode eui64 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
```

`vxlan`设备需要对接收到的数据包进行`VXLAN`协议封装。它需要知道对端`10.230.93.0`的`MAC`地址。而`flanneld`在启动时已经根据从`etcd`或`kubernetes API`获取到的信息写入到`ARP`表中:

```
[root@node1 ~]# ip neigh show dev flannel.1
10.230.93.0 lladdr 2a:02:24:58:e9:07 PERMANENT
```

这样获取到`10.230.93.0`的`MAC`地址后，就可以完成内层数据的封装。数据包封装完成后，它需要获得对应这个`MAC`地址的`VTEP`的`IP`地址。`flanneld`已经在启动时写入`FDB`条目:

```
[root@node1 ~]# bridge fdb show dev flannel.1
2a:02:24:58:e9:07 dst 10.240.0.102 self permanent
```

可以看到`2a:02:24:58:e9:07`对应的`VTEP IP`为`10.240.0.102`。这时`flannel.1`这个`vxlan`设备知道数据包要发送的目的`IP`，根据主机的路由策略从`eth1`设备发出。主机路由信息如下:

```
[root@node1 ~]# ip route
default via 10.0.2.2 dev eth0
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15
10.230.41.0/24 dev cni0 proto kernel scope link src 10.230.41.1
10.230.93.0/24 via 10.230.93.0 dev flannel.1 onlink
10.240.0.0/24 dev eth1 proto kernel scope link src 10.240.0.101
169.254.0.0/16 dev eth0 scope link metric 1002
169.254.0.0/16 dev eth1 scope link metric 1003
```

数据包到达`node2`的`eth1`后，`eth1`将收到`VXLAN`数据包, 数据包中的`MAC`地址为:`2a:02:24:58:e9:07`, 正是`node2`节点上`flannel.1`的地址, 将它转给`flannel.1`设备:

```
[root@node2 ~]# ip addr show flannel.1
4: flannel.1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1450 qdisc noqueue state UNKNOWN group default
    link/ether 2a:02:24:58:e9:07 brd ff:ff:ff:ff:ff:ff
    inet 10.230.93.0/32 scope global flannel.1
       valid_lft forever preferred_lft forever
    inet6 fe80::2802:24ff:fe58:e907/64 scope link
       valid_lft forever preferred_lft forever
```

`flannel.1`解包之后，根据内层目的地址:`10.240.93.2`查找路由转发到`cni0`:

```
[root@node2 ~]# ip route
default via 10.0.2.2 dev eth0 proto dhcp metric 100
10.0.2.0/24 dev eth0 proto kernel scope link src 10.0.2.15 metric 100
10.230.41.0/24 via 10.230.41.0 dev flannel.1 onlink
10.230.93.0/24 dev cni0 proto kernel scope link src 10.230.93.1
10.240.0.0/24 dev eth1 proto kernel scope link src 10.240.0.102 metric 101
```

`cni0`再通过`ARP`请求获得`10.230.93.2`的`MAC`地址，从而将数据包转发到相应的POD中的`veth pair`设备，从而到达容器中。

回包的路径是一样的，不再详述。

下面简要分析一下`flanneld`的源码实现。

`main`函数中首先调用`newSubnetManager`创建`SubnetManager`。

```
sm, err := newSubnetManager()
if err != nil {
    log.Error("Failed to create SubnetManager: ", err)
    os.Exit(1)
}
log.Infof("Created subnet manager: %s", sm.Name())
```

`SubnetManager`用于向网络配置存储租用或续组`subnet`。每个节点都会有自己的一个`subnet`,保证了节点之间的`IP`不会冲突。

```
func newSubnetManager() (subnet.Manager, error) {
    if opts.kubeSubnetMgr {
        return kube.NewSubnetManager(opts.kubeApiUrl, opts.kubeConfigFile)
    }

    cfg := &etcdv2.EtcdConfig{
        Endpoints: strings.Split(opts.etcdEndpoints, ","),
        Keyfile:   opts.etcdKeyfile,
        Certfile:  opts.etcdCertfile,
        CAFile:    opts.etcdCAFile,
        Prefix:    opts.etcdPrefix,
        Username:  opts.etcdUsername,
        Password:  opts.etcdPassword,
    }

    // Attempt to renew the lease for the subnet specified in the subnetFile
    prevSubnet := ReadSubnetFromSubnetFile(opts.subnetFile)

    return etcdv2.NewLocalManager(cfg, prevSubnet)
}
```

如果命令行参数中指定了`kube-subnet-mgr`, 则使用`kubernetes API`作为全局网络配置存储，否则使用`etcd`。

接着调用`getConfig`从全局配置存储获取网络配置, 包括容器集群的网络信息，`backend`的配置等等:

```
// Fetch the network config (i.e. what backend to use etc..).
config, err := getConfig(ctx, sm)
if err == errCanceled {
    wg.Wait()
    os.Exit(0)
}
```

比如，我的实验环境写到`etcd`的配置内容为:

```
{"Network":"10.230.0.0/16","SubnetLen":24, "Backend":{"Type": "vxlan"}}
```

接下来，`main`函数会调用`backend.NewManager`。

```
// Create a backend manager then use it to create the backend and register the network with it.
bm := backend.NewManager(ctx, sm, extIface)
be, err := bm.GetBackend(config.BackendType)
if err != nil {
    log.Errorf("Error fetching backend: %s", err)
    cancel()
    wg.Wait()
    os.Exit(1)
}

bn, err := be.RegisterNetwork(ctx, config)
if err != nil {
    log.Errorf("Error registering network: %s", err)
    cancel()
    wg.Wait()
    os.Exit(1)
}
```

开头时也介绍过，`flannel`通过`backend`机制来支持各种不同的跨主机通信方式。不同的实现方式会在`init`函数中向`backend`注册自己的构造函数。比如，`package vxlan`的`init`函数:

```
func init() {
    backend.Register("vxlan", New)
}

const (
    defaultVNI = 1
)

type VXLANBackend struct {
    subnetMgr subnet.Manager
    extIface  *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
    backend := &VXLANBackend{
        subnetMgr: sm,
        extIface:  extIface,
    }

    return backend, nil
}
```

`be.RegisterNetwork`会调用到`package vxlan`的`RegisterNetwork`:

```
func (be *VXLANBackend) RegisterNetwork(ctx context.Context, config *subnet.Config) (backend.Network, error) {
    // Parse our configuration
    cfg := struct {
        VNI           int
        Port          int
        GBP           bool
        DirectRouting bool
    }{
        VNI: defaultVNI,
    }

    if len(config.Backend) > 0 {
        if err := json.Unmarshal(config.Backend, &cfg); err != nil {
            return nil, fmt.Errorf("error decoding VXLAN backend config: %v", err)
        }
    }
    log.Infof("VXLAN config: VNI=%d Port=%d GBP=%v DirectRouting=%v", cfg.VNI, cfg.Port, cfg.GBP, cfg.DirectRouting)

    devAttrs := vxlanDeviceAttrs{
        vni:       uint32(cfg.VNI),
        name:      fmt.Sprintf("flannel.%v", cfg.VNI),
        vtepIndex: be.extIface.Iface.Index,
        vtepAddr:  be.extIface.IfaceAddr,
        vtepPort:  cfg.Port,
        gbp:       cfg.GBP,
    }

    dev, err := newVXLANDevice(&devAttrs)
    if err != nil {
        return nil, err
    }
    dev.directRouting = cfg.DirectRouting

    subnetAttrs, err := newSubnetAttrs(be.extIface.ExtAddr, dev.MACAddr())
    if err != nil {
        return nil, err
    }

    lease, err := be.subnetMgr.AcquireLease(ctx, subnetAttrs)
    switch err {
    case nil:
    case context.Canceled, context.DeadlineExceeded:
        return nil, err
    default:
        return nil, fmt.Errorf("failed to acquire lease: %v", err)
    }

    // Ensure that the device has a /32 address so that no broadcast routes are created.
    // This IP is just used as a source address for host to workload traffic (so
    // the return path for the traffic has an address on the flannel network to use as the destination)
    if err := dev.Configure(ip.IP4Net{IP: lease.Subnet.IP, PrefixLen: 32}); err != nil {
        return nil, fmt.Errorf("failed to configure interface %s: %s", dev.link.Attrs().Name, err)
    }

    return newNetwork(be.subnetMgr, be.extIface, dev, ip.IP4Net{}, lease)
}
```

`RegisterNetwork`函数会调用`newVXLANDevice`创建一个`vxlan`设备，就对应我们实验环境中的`flannel.1`。从代码也可以看到`flannel.1`设备名中的`1`指的是`VNI`, 我们可以通过在全局配置存储中设置为其他值。然后获取本地`VTEP`的`IP`地址以及`vxlan`设备的`MAC`地址填充到`subnetAttrs`结构调用`be.subnetMgr.AcquireLease`。这最终会调用到`package etcdv2`的`tryAcquireLease`。`tryAcquireLease`则会调用`m.registry.createSubnet`或者`m.registry.updateSubnet`去向`etcd`中写入相应的`Subnet`信息，完成相应`Subnet`的租用。这时，如果已经有其他节点的`flanneld`在`watch` `etcd`上的`subnets`的key，则会触发添加路由、`ARP`及`FDB`条目的逻辑。这个下面我们再详细描述具体实现。之后，调用`dev.Configure`给`vxlan`设备配置一个掩码为`32`的地址防止广播路由创建。

`RegisterNetwork`返回后，`main`函数会调用`WriteSubnetFile`将获取到的网络信息写入`subnetFile`中，默认是`/run/flannel/subnet.env`，后续`flanneld`再启动时就会优先尝试使用这个文件中记录的信息去续组`subnet`:

```
if err := WriteSubnetFile(opts.subnetFile, config.Network, opts.ipMasq, bn); err != nil {
    // Continue, even though it failed.
    log.Warningf("Failed to write subnet file: %s", err)
} else {
    log.Infof("Wrote subnet file to %s", opts.subnetFile)
}
```

接着，`main`函数中启动一个`goroutine`去运行`bn.Run`:

```
// Start "Running" the backend network. This will block until the context is done so run in another goroutine.
log.Info("Running backend.")
wg.Add(1)
go func() {
    bn.Run(ctx)
    wg.Done()
}()
```

这会调用到`package vxlan`的`Run`实现，它会调用`subnet.WatchLeases`去获取全局范围的`subnet`情况:

```
func (nw *network) Run(ctx context.Context) {
    wg := sync.WaitGroup{}

    log.V(0).Info("watching for new subnet leases")
    events := make(chan []subnet.Event)
    wg.Add(1)
    go func() {
        subnet.WatchLeases(ctx, nw.subnetMgr, nw.SubnetLease, events)
        log.V(1).Info("WatchLeases exited")
        wg.Done()
    }()

    defer wg.Wait()

    for {
        select {
        case evtBatch := <-events:
            nw.handleSubnetEvents(evtBatch)

        case <-ctx.Done():
            return
        }
    }
}
```

`package subnet`的`WatchLeases`函数中会一直循环调用`sm.WatchLeases`。`sm.WatchLeases`首次运行时会获取到当前`etcd`中已有的`subnet`信息，之后则开始`watch` `etcd`中`subnets` `key`获得变更的`subnet`信息。这些`subnet`信息传送给`channel`:`receiver`:

```
func WatchLeases(ctx context.Context, sm Manager, ownLease *Lease, receiver chan []Event) {
    lw := &leaseWatcher{
        ownLease: ownLease,
    }
    var cursor interface{}

    for {
        res, err := sm.WatchLeases(ctx, cursor)
        if err != nil {
            if err == context.Canceled || err == context.DeadlineExceeded {
                return
            }

            log.Errorf("Watch subnets: %v", err)
            time.Sleep(time.Second)
            continue
        }

        cursor = res.Cursor

        var batch []Event

        if len(res.Events) > 0 {
            batch = lw.update(res.Events)
        } else {
            batch = lw.reset(res.Snapshot)
        }

        if len(batch) > 0 {
            receiver <- batch
        }
    }
}
```

`receiver`的接收端协程则调用`nw.handleSubnetEvents(evtBatch)`来处理这些消息:

```
func (nw *network) handleSubnetEvents(batch []subnet.Event) {
    for _, event := range batch {
        sn := event.Lease.Subnet
        attrs := event.Lease.Attrs
        if attrs.BackendType != "vxlan" {
            log.Warningf("ignoring non-vxlan subnet(%s): type=%v", sn, attrs.BackendType)
            continue
        }

        var vxlanAttrs vxlanLeaseAttrs
        if err := json.Unmarshal(attrs.BackendData, &vxlanAttrs); err != nil {
            log.Error("error decoding subnet lease JSON: ", err)
            continue
        }

        // This route is used when traffic should be vxlan encapsulated
        vxlanRoute := netlink.Route{
            LinkIndex: nw.dev.link.Attrs().Index,
            Scope:     netlink.SCOPE_UNIVERSE,
            Dst:       sn.ToIPNet(),
            Gw:        sn.IP.ToIP(),
        }
        vxlanRoute.SetFlag(syscall.RTNH_F_ONLINK)

        // directRouting is where the remote host is on the same subnet so vxlan isn't required.
        directRoute := netlink.Route{
            Dst: sn.ToIPNet(),
            Gw:  attrs.PublicIP.ToIP(),
        }
        var directRoutingOK = false
        if nw.dev.directRouting {
            routes, err := netlink.RouteGet(attrs.PublicIP.ToIP())
            if err != nil {
                log.Errorf("Couldn't lookup route to %v: %v", attrs.PublicIP, err)
                continue
            }
            if len(routes) == 1 && routes[0].Gw == nil {
                // There is only a single route and there's no gateway (i.e. it's directly connected)
                directRoutingOK = true
            }
        }

        switch event.Type {
        case subnet.EventAdded:
            if directRoutingOK {
                log.V(2).Infof("Adding direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)

                if err := netlink.RouteReplace(&directRoute); err != nil {
                    log.Errorf("Error adding route to %v via %v: %v", sn, attrs.PublicIP, err)
                    continue
                }
            } else {
                log.V(2).Infof("adding subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))
                if err := nw.dev.AddARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                    log.Error("AddARP failed: ", err)
                    continue
                }

                if err := nw.dev.AddFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                    log.Error("AddFDB failed: ", err)

                    // Try to clean up the ARP entry then continue
                    if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                        log.Error("DelARP failed: ", err)
                    }

                    continue
                }

                // Set the route - the kernel would ARP for the Gw IP address if it hadn't already been set above so make sure
                // this is done last.
                if err := netlink.RouteReplace(&vxlanRoute); err != nil {
                    log.Errorf("failed to add vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)

                    // Try to clean up both the ARP and FDB entries then continue
                    if err := nw.dev.DelARP(neighbor{IP: event.Lease.Subnet.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                        log.Error("DelARP failed: ", err)
                    }

                    if err := nw.dev.DelFDB(neighbor{IP: event.Lease.Attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                        log.Error("DelFDB failed: ", err)
                    }

                    continue
                }
            }
        case subnet.EventRemoved:
            if directRoutingOK {
                log.V(2).Infof("Removing direct route to subnet: %s PublicIP: %s", sn, attrs.PublicIP)
                if err := netlink.RouteDel(&directRoute); err != nil {
                    log.Errorf("Error deleting route to %v via %v: %v", sn, attrs.PublicIP, err)
                }
            } else {
                log.V(2).Infof("removing subnet: %s PublicIP: %s VtepMAC: %s", sn, attrs.PublicIP, net.HardwareAddr(vxlanAttrs.VtepMAC))

                // Try to remove all entries - don't bail out if one of them fails.
                if err := nw.dev.DelARP(neighbor{IP: sn.IP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                    log.Error("DelARP failed: ", err)
                }

                if err := nw.dev.DelFDB(neighbor{IP: attrs.PublicIP, MAC: net.HardwareAddr(vxlanAttrs.VtepMAC)}); err != nil {
                    log.Error("DelFDB failed: ", err)
                }

                if err := netlink.RouteDel(&vxlanRoute); err != nil {
                    log.Errorf("failed to delete vxlanRoute (%s -> %s): %v", vxlanRoute.Dst, vxlanRoute.Gw, err)
                }
            }
        default:
            log.Error("internal error: unknown event type: ", int(event.Type))
        }
    }
}
```

这里我们忽略`directRouting`相关内容。`EventAdded`表示有新的节点上线，首先调用`nw.dev.AddARP`给`vxlan`设备添加`ARP`条目，`MAC`和`IP`分别为新上线节点上`vxlan`设备的`MAC`地址以及上面所配置的`32`位掩码的`IP`地址。接着调用`nw.dev.AddFDB`在`vxlan`设备上添加`FDB`条目，`MAC`和`IP`分别为新上线节点上的`vxlan`设备的`MAC`地址以及新节点上的`VTEP`的IP地址。最后，再调用`netlink.RouteReplace(&vxlanRoute)`去添加经由`32`位掩码地址到达新上线`subnet`的路由。代码注释里也说明了，最后再添加路由是为了防止在`ARP`缓存没有填加的情况下发起`ARP`请求。

`EventRemoved`表示有节点下线，这里分别调用`nw.dev.DelARP`,`nw.dev.DelFDB`,`netlink.RouteDel`删除相应的`ARP`,`FDB`和路由条目。

在`main`函数的逻辑里接下来还会调用`MonitorLease`去定期续租`subnet`，这里不再详述。

参考:

- https://www.cnblogs.com/robinunix/articles/13275530.html
- https://programmer.ink/think/5da939768e5cb.html

## Calico

### [Kubernetes Calico](https://www.jesse.top/2021/02/06/kubernetes/network/kubernetes%20Calico/)

#### 简介

 Calico是一个非常流行的Kubernetes网络插件和解决方案.Calico是一个开源虚拟化网络方案，用于为云原生应用实现互联及策略控制。与Flannel相比，Calico的一个显著优势是对网络策略（network policy）的支持，它允许用户动态定义ACL规则控制进出容器的数据报文，实现为Pod间的通信按需施加安全策略。事实上，Calico可以整合进大多数主流的编排系统，如Kubernetes、Apache Mesos、Docker和OpenStack等。

 Calico本身是一个三层的虚拟网络方案，它将每个节点都当作路由器（router），将每个节点的容器都当作是“节点路由器”的一个终端并为其分配一个IP地址，各节点路由器通过BGP（Border Gateway Protocol）学习生成路由规则，从而将不同节点上的容器连接起来。因此，Calico方案其实是一个纯三层的解决方案，通过每个节点协议栈的三层（网络层）确保容器之间的连通性，这摆脱了flannel host-gw类型的所有节点必须位于同一二层网络的限制，从而极大地扩展了网络规模和网络边界。

 Calico利用Linux内核在每一个计算节点上实现了一个高效的vRouter（虚拟路由器）进行报文转发，而每个vRouter都通过BGP负责把自身所属的节点上运行的Pod资源的IP地址信息基于节点的agent程序（Felix）直接由vRouter生成路由规则向整个Calico网络内进行传播.

 Calico承载的各Pod资源直接通过vRouter经由基础网络进行互联，它非叠加、无隧道、不使用VRF表，也不依赖于NAT，因此每个工作负载都可以直接配置使用公网IP接入互联网，当然，也可以按需使用网络策略控制它的网络连通性。

 Calico官网介绍: projectcaclico.org

#### 重要特性

##### 经IP路由直连

Calico中，Pod收发的IP报文由所在节点的Linux内核路由表负责转发，并通过iptables规则实现其安全功能。某Pod对象发送报文时，Calico应确保节点总是作为下一跳MAC地址返回，不管工作负载本身可能配置什么路由，而发往某Pod对象的报文，其最后一个IP跃点就是Pod所在的节点，也就是说，报文的最后一程即由节点送往目标Pod对象，如下图所示。

![Calico直连路由.png)](https://img2.jesse.top/image-20210206163936241.png)

需为某Pod对象提供连接时，系统上的专用插件（如Kubernetes的CNI）负责将需求通知给Calico Agent。收到消息后，Calico Agent会为每个工作负载添加直接路径信息到工作负载的TAP设备（如veth）。而运行于当前节点的BGP客户端监控到此类消息后会调用路由reflector向工作于其他节点的BGP客户端进行通告。

##### 简单、高效、易扩展

Calico未使用额外的报文封装和解封装，从而简化了网络拓扑，这也是Calico高性能、易扩展的关键因素。毕竟，小的报文减少了报文分片的可能性，而且较少的封装和解封装操作也降低了对CPU的占用。此外，较少的封装也易于实现报文分析，易于进行故障排查。

创建、移动或删除Pod对象时，相关路由信息的通告速度也是影响其扩展性的一个重要因素。Calico出色的扩展性缘于与互联网架构设计原则别无二致的方式，它们都使用了BGP作为控制平面。BGP以高效管理百万级的路由设备而闻名于世，Calico自然可以游刃有余地适配大型IDC网络规模。另外，由于Calico各工作负载使用基IP直接进行互联，因此它还支持多个跨地域的IDC之间进行协同。

#### Calico系统架构

![img](Calico系统架构.png)

各组件介绍如下:

- **Felix**

  Calico Agent，运行于每个节点。主要负责网络接口管理和监听、路由、ARP 管理、ACL 管理和同步、状态上报等。

- **ETCD**

  分布式键值存储，主要负责网络元数据一致性，确保Calico网络状态的准确性，可以与kubernetes共用；

- **BGP Client（BIRD）**

  Calico 为每一台 Host 部署一个 BGP Client，使用 BIRD 实现，BIRD 是一个单独的持续发展的项目，实现了众多动态路由协议比如 BGP、OSPF、RIP 等。在 Calico 的角色是监听 Host 上由 Felix 注入的路由信息，然后通过 BGP 协议广播告诉剩余 Host 节点，从而实现网络互通。

- **BGP Route Reflector**

  在大型网络规模中，如果仅仅使用 BGP client 形成 mesh 全网互联的方案就会导致规模限制，因为所有节点之间俩俩互联，需要 N^2 个连接，为了解决这个规模问题，可以采用 BGP 的 Router Reflector 的方法，使所有 BGP Client 仅与特定 RR 节点互联并做路由同步，从而大大减少连接数。

##### Felix

 Felix运行于各节点的用于支持端点（VM或Container）构建的守护进程，它负责生成路由和ACL，以及其他任何由节点用到的信息，从而为各端点构建连接机制。Felix在各编排系统中主要负责以下任务。

 首先是接口管理（Interface Management）功能，负责为接口生成必要的信息并送往内核，以确保内核能够正确处理各端点的流量，尤其是要确保各节点能够响应目标MAC为当前节点上各工作负载的MAC地址的ARP请求，以及为其管理的接口打开转发功能。另外，它还要监控各接口的变动以确保规则能够得到正确的应用。

 其次是路由规划（Route Programming）功能，其负责为当前节点运行的各端点在内核FIB（Forwarding Information Base）中生成路由信息，以保证到达当前节点的报文可正确转发给端点。

 再次是ACL规划（ACL Programming）功能，负责在Linux内核中生成ACL，用于实现仅放行端点间的合法流量，并确保流量不能绕过Calico的安全措施。

 最后是状态报告（State Reporting）功能，负责提供网络健康状态的相关数据，尤其是报告由其管理的节点上的错误和问题。这些报告数据会存储于etcd，供其他组件或网络管理员使用。

##### 编排系统插件

 编排系统插件（Orchestrator Plugin）依赖于编排系统自身的实现，故此并不存在一个固定的插件以代表此组件。编排系统插件的主要功能是将Calico整合进系统中，并让管理员和用户能够使用Calico的网络功能。它主要负责完成API的转换和反馈输出。

 编排系统通常有其自身的网络管理API，网络插件需要负责将对这些API的调用转为Calico的数据模型并存储于Calico的存储系统中。如果有必要，网络插件还要将Calico系统的信息反馈给编排系统，如Felix的存活状态，网络发生错误时设定相应的端点为故障等。

##### ETCD储系统

 Calico使用etcd完成组件间的通信，并以之作为一个持久数据存储系统。根据编排系统的不同，etcd所扮演角色的重要性也因之而异，但它贯穿了整个Calico部署全程，并被分为两类主机：核心集群和代理（proxy）。在每个运行着Felix或编排系统插件的主机上都应该运行一个etcd代理以降低etcd集群和集群边缘节点的压力。此模式中，每个运行着插件的节点都会运行着etcd集群的一个成员节点。

 etcd是一个分布式、强一致、具有容错功能的存储系统，这一点有助于将Calico网络实现为一个状态确切的系统：要么正常，要么发生故障。另外，分布式存储易于通过扩展应对访问压力的提升，而避免成为系统瓶颈。另外，etcd也是Calico各组件的通信总线，可用于确保让非etcd组件在键空间（keyspace）中监控某些特定的键，以确保它们能够看到所做的任何更改，从而使它们能够及时地响应这些更改。

##### BGP客户端(BIRD)

 Calico要求在每个运行着Felix的节点上同时还要运行一个BGP客户端，负责将Felix生成的路由信息载入内核并通告到整个IDC。在Calico语境中，此组件是通用的BIRD，因此任何BGP客户端（如GoBGP等）都可以从内核中提取路由并对其分发对于它们来说都适合的角色。

 BGP客户端的核心功能就是路由分发，在Felix插入路由信息至内核FIB中时，BGP客户端会捕获这些信息并将其分发至其他节点，从而确保了流量的高效路由。

##### BGP路由反射器(Route Reflector)

 在大规模的部署场景中，简易版的BGP客户端易于成为性能瓶颈，因为它要求每个BGP客户端都必须连接至其同一网络中的其他所有BGP客户端以传递路由信息，一个有着N个节点的部署环境中，其存在网络连接的数量为N的二次方，随着N值的逐渐增大，其连接复杂度会急剧上升。因而在较大规模的部署场景中，Calico应该选择部署一个BGP路由反射器，它是由BGP客户端连接的中心点，BGP的点到点通信也就因此转化为与中心点的单路通信模型，如图11-18所示。出于冗余之需，生产实践中应该部署多个BGP路由反射器。对于Calico来说，BGP客户端程序除了作为客户端使用之外，还可以配置成路由反射器。

#### Calico网络工作模式

##### BGP模式

边界网关协议（Border Gateway Protocol, BGP）是互联网上一个核心的去中心化自治路由协议，它通过维护IP路由表或“前缀”表来实现自治系统（AS）之间的可达性，属于矢量路由协议。不过，考虑到并非所有的网络都能支持BGP，以及Calico控制平面的设计要求物理网络必须是二层网络，以确保vRouter间均直接可达，路由不能够将物理设备当作下一跳等原因，为了支持三层网络。

![image](Calico-BGP.png)

在默认配置下每台宿主机的BGPClient需要和集群所有的BGPClient建立连接，进行路由信息交换，随着集群规模的扩大，集群的网络将会面临巨大的压力并且宿主机的路由表也会变的过大。所以在大规模的集群中，通常使用BGP Route Reflector充当BGP客户端连接的中心点，从而避免与互联网中的每个BGP客户端进行通信。Calico使用BGP Route Reflector是为了减少给定一个BGP客户端与集群其他BGP客户端的连接。用户也可以同时部署多个BGP Route Reflector服务实现高可用。Route Reflector仅仅是协助管理BGP网络，并没有工作负载的数据包经过它们。

![image](Calico-BGP路由反射.png)

##### IPIP模式

 BGP模式要求Kubernetes的所有物理节点网络必须是二层网络.为了支持三层网络，Calico还推出了IP-in-IP叠加的模型，它也使用Overlay的方式来传输数据。IPIP的包头非常小，而且也是内置在内核中，因此理论上它的速度要比VxLAN快一点，但安全性更差。Calico 3.x的默认配置使用的是IPIP类型的传输方案而非BGP。

 工作于IPIP模式的Calico会在每个节点上创建一个tunl0接口（TUN类型虚拟设备）用于封装三层隧道报文。节点上创建的每一个Pod资源，都会由Calico自动创建一对虚拟以太网接口（TAP类型的虚拟设备），其中一个附加于Pod的网络名称空间，另一个（名称以cali为前缀后跟随机字串）留置在节点的根网络名称空间，并经由tunl0封装或解封三层隧道报文。Calico IPIP模式如下图所示。

![image-20210206165304293](Calico-IPIP模式.png)

#### Calico 网络通信方式

##### Calico网络环境介绍

当前k8s集群使用的是v1.17.3的版本.有2个node节点.IP地址分别如下

```
[root@k8s-master ~]$kubectl get nodes -o wide | awk '{print $1,$6}' | sed 1,2d
k8s-node1 172.16.20.252
k8s-node2 172.16.20.253
```

每个node节点都启动一个`tunl0` 的虚拟路由器.和许多`calixxx` 开头的虚拟网卡设备

```
[root@k8s-node1 ~]# ifconfig
cali42b086c8543: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1440
        inet6 fe80::ecee:eeff:feee:eeee  prefixlen 64  scopeid 0x20<link>
        ether ee:ee:ee:ee:ee:ee  txqueuelen 0  (Ethernet)
        RX packets 13335563  bytes 928478769 (885.4 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 13335563  bytes 928478769 (885.4 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

tunl0: flags=193<UP,RUNNING,NOARP>  mtu 1440
        inet 10.100.36.64  netmask 255.255.255.255
        tunnel   txqueuelen 1000  (IPIP Tunnel)  #默认是IPIP模式
        RX packets 3978810  bytes 345003038 (329.0 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 3674392  bytes 613045453 (584.6 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions
```

Calico的CNI插件会为每个容器设置一个veth pair设备，然后把另一端接入到宿主机网络空间，由于没有网桥，CNI插件还需要在宿主机上为每个容器的veth pair设备配置一条路由规则，用于接收传入的IP包.

了这样的veth pair设备以后，容器发出的IP包就会通过veth pair设备到达宿主机，这些路由规则都是Felix维护配置的，而路由信息则是calico bird组件基于BGP分发而来。Calico实际上是将集群里所有的节点都当做边界路由器来处理，他们一起组成了一个全互联的网络，彼此之间通过BGP交换路由，这些节点我们叫做BGP Peer。

为了下面试验Calico的网络工作.当前集群使用daemonSet控制器运行了2个`busybox:1.28.4` 镜像的容器

```
[root@k8s-master ~]$kubectl get pods -o wide
NAME            READY   STATUS    RESTARTS   AGE    IP               NODE        NOMINATED NODE   READINESS GATES
busybox-g5rkr   1/1     Running   0          130m   10.100.36.103    k8s-node1   <none>           <none>
busybox-zdwsc   1/1     Running   0          130m   10.100.169.176   k8s-node2   <none>           <none>
```

在`k8s-node1`节点上可以看到两条相关路由

```
10.100.36.103   0.0.0.0         255.255.255.255 UH    0      0        0 cali96df9f67b52
10.100.169.128  172.16.20.253   255.255.255.192 UG    0      0        0 tunl0
```

第一条路由是访问该节点下的Busybox容器.它的下一跳是`calixxxx`开头的虚拟网卡.这种通信方式和docker的Bridge网桥模式其实并没有任何区别.

第二条路由的目的网络是10.100.169.128,子网掩码是255.255.255.192.它代表了IP范围为10.100.169.128-190的地址.而运行于另外一个节点下的`busybox-zdwsc`Pod的IP地址就位于这个范围之内.所以这条路由可以使node1节点借助于tunl0可以直接和node2节点下的pod进行通信.

> 在`k8s-node2` 服务器可以看到类似的这2条路由

##### Calico网络模型解密

登录`k8s-node1`节点下的Pod容器内部.查看Pod容器的IP地址,以及路由条目.

```
[root@k8s-master ~]$kubectl exec -it busybox-g5rkr -- sh
/ # ifconfig
eth0      Link encap:Ethernet  HWaddr 4A:7C:E7:FA:4B:CC
          inet addr:10.100.36.103  Bcast:0.0.0.0  Mask:255.255.255.255
          UP BROADCAST RUNNING MULTICAST  MTU:1440  Metric:1
          RX packets:14 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:1322 (1.2 KiB)  TX bytes:426 (426.0 B)


/ # route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         169.254.1.1     0.0.0.0         UG    0      0        0 eth0
169.254.1.1     0.0.0.0         255.255.255.255 UH    0      0        0 eth0
```

通过`k8s-node`节点上的下面的路由条目,我们可以知道节点主机和Pod容器的IP地址`10.100.36.103`通信使用的是`cali96df9f67b52`这个虚拟网卡

```
10.100.36.103   0.0.0.0         255.255.255.255 UH    0      0        0 cali96df9f67b52
```

路由条目显示`169.254.1.1` 是Pod容器的默认网关.但是有网络常识的我们都知道这个IP是个保留的IP地址,不存在于互联网或者任何设备中.那Pod如何和网关通信呢?

回顾一下网络课程,我们知道任何网络设备和网关设备都是在一个二层局域网中,而二层数据链路层使用MAC地址进行通信,不需要双方的IP地址信息.通信方(这里是Pod容器)会通过ARP协议获取网关的MAC地址,然后通过MAC地址将数据包发送给网关..也就是说网络设备不关心对方的IP是否可达,只要能找到对应的MAC地址就可以.

通过`ip neigh`命令查看Pod容器的ARP缓存

```
/ # ip neigh
169.254.1.1 dev eth0 lladdr ee:ee:ee:ee:ee:ee ref 1 used 0/0/0 probes 4 REACHABLE
```

> 如果是新的Pod容器可能无法获得ARP缓存,此时只需要随便发生一个网络交互(例如ping百度)即可

这个MAC地址(ee:ee:ee:ee:ee:ee)也是Calico的虚拟`cali96df9f67b52`网卡的虚拟MAC地址.下放是宿主机网卡信息:

```
cali96df9f67b52: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1440
        inet6 fe80::ecee:eeff:feee:eeee  prefixlen 64  scopeid 0x20<link>
        ether ee:ee:ee:ee:ee:ee  txqueuelen 0  (Ethernet)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

所有虚拟网卡默认开启了ARP代理协议

```
[root@k8s-node1 ~]# cat /proc/sys/net/ipv4/conf/cali96df9f67b52/proxy_arp
1
```

所以Calico 通过一个巧妙的方法将 Pod 的所有流量引导到一个特殊的网关 169.254.1.1，从而引流到主机的 calixxx 网络设备上，最终将二三层流量全部转换成三层流量来转发。

#### Calico IPIP网络模式

登录`busybox-g5rkr`Pod容器内部.ping位于另外一台`k8s-node2` 下的`busybox-zdwsc`Pod容器

```
[root@k8s-master ~]$kubectl get pods -o wide
NAME            READY   STATUS    RESTARTS   AGE    IP               NODE        NOMINATED NODE   READINESS GATES
busybox-g5rkr   1/1     Running   0          130m   10.100.36.103    k8s-node1   <none>           <none>
busybox-zdwsc   1/1     Running   0          130m   10.100.169.176   k8s-node2   <none>           <none>
```

两个Pod之前可以直接访问对方的IP地址.而不需要像Docker容器那样暴露端口,然后利用对方宿主机的IP进行通信

```
[root@k8s-master ~]$kubectl exec -it busybox-g5rkr -- sh
/ # ifconfig
eth0      Link encap:Ethernet  HWaddr 4A:7C:E7:FA:4B:CC
          inet addr:10.100.36.103  Bcast:0.0.0.0  Mask:255.255.255.255
          UP BROADCAST RUNNING MULTICAST  MTU:1440  Metric:1
          RX packets:14 errors:0 dropped:0 overruns:0 frame:0
          TX packets:6 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:1322 (1.2 KiB)  TX bytes:426 (426.0 B)

/ # ping 10.100.169.176
PING 10.100.169.176 (10.100.169.176): 56 data bytes
64 bytes from 10.100.169.176: seq=0 ttl=62 time=0.622 ms
64 bytes from 10.100.169.176: seq=1 ttl=62 time=0.552 ms
64 bytes from 10.100.169.176: seq=2 ttl=62 time=0.597 ms
```

在`k8s-node2` 节点抓包

```
[root@k8s-node2 ~]# tcpdump -i ens192 -nn  -w imcp.cap
```

用wireshark软件打开抓包文件.发现如下ICMP的报文

![image-20210206220720374](Calico-IPIP模式抓包.png)

可以看到每个数据报文共有两个IP网络层,内层是Pod容器之间的IP网络报文,外层是宿主机节点的网络报文(2个node节点).之所以要这样做是因为tunl0是一个隧道端点设备，在数据到达时要加上一层封装，便于发送到对端隧道设备中。

Pod间的通信经由IPIP的三层隧道转发,相比较VxLAN的二层隧道来说，IPIP隧道的开销较小，但其安全性也更差一些。

![img](Calico-IPIP报文封装.png)

IPIP的通信方式如下:

![img](Calico-IPIP通信方式.png)

##### Pod和Service网络通信

经过测试.在k8s集群内部物理节点和pod容器内部访问Service的http服务.仍然使用的是Ipip通信模式.

下面是在容器内部通过Service访问busybox pod容器的http服务的抓包报文

```
[root@k8s-master ~]$kubectl exec -it busybox-6hnvc -- sh
/ # curl http://10.96.166.242
sh: curl: not found
/ # wget -O - -q http://10.96.166.242
wget: server returned error: HTTP/1.0 404 Not Found
/ # wget -O - -q http://10.96.166.242
wget: server returned error: HTTP/1.0 404 Not Found
```

![image-20210206222911793](Calico-IPIP抓包.png)

#### BGP网络模式

Calico网络部署时,默认安装就是IPIP网络.通过修改calico.yaml部署文件中的`CALICO_IPV4POOL_IPIP` 值修改成`off` 就切换到BGP网络模式

```
# Enable IPIP
- name: CALICO_IPV4POOL_IPIP
  value: "Always"  #改成Off
```

重新部署calico

```
[root@k8s-master ~]$kubectl apply -f calico-3.10.2.yaml
```

然后关闭ipipMode.把ipipMode从Always修改成为Never

```
[root@k8s-master1 target]# kubectl edit ippool

  ipipMode: Never
```

##### bgp和Ipip的区别

BGP网络相比较IPIP网络，最大的不同之处就是没有了隧道设备 tunl0。 前面介绍过IPIP网络pod之间的流量发送tunl0，然后tunl0发送对端设备。BGP网络中，pod之间的流量直接从网卡发送目的地，减少了tunl0这个环节。

##### 通信方式

删除原来的pod.重新启动新的

```
[root@k8s-master ~]$kubectl create -f deployment-kubia-v1.yaml
daemonset.apps/busybox created
service/busybox created
[root@k8s-master ~]$kubectl get pods -o wide
NAME            READY   STATUS    RESTARTS   AGE   IP               NODE        NOMINATED NODE   READINESS GATES
busybox-bd566   1/1     Running   0          16s   10.100.36.97     k8s-node1   <none>           <none>
busybox-fntv9   1/1     Running   0          16s   10.100.169.129   k8s-node2   <none>           <none>
```

再次查看路由表.发现节点和pod容器通信直接通过宿主机的物理网卡,而不是tunl0设备了

```
[root@k8s-master ~]$route -n
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
0.0.0.0         172.16.20.254   0.0.0.0         UG    100    0        0 ens192
10.100.36.64    172.16.20.252   255.255.255.192 UG    0      0        0 ens192
10.100.169.128  172.16.20.253   255.255.255.192 UG    0      0        0 ens192
```

此时,再次2个Pod容器互ping抓包分析.发现两个Pod像物理机一样直接通信,而不需要进行任何数据包封装和解封装.并且数据报文的MAC地址也是node1和node2物理网卡的MAC地址

![image-20210206224938109](Calico-BGP抓包.png)

BGP的网络连接方式:

![img](Calico-BGP通信方式.png)

#### BGP和ipip网络模式对比

- **IPIP**:

  特点: tunl0封装数据.形成隧道.所有Pod和pod.pod和节点之间进行三层网络传输

  优点: 适用所有网络类型.能够解决跨网段的路由问题.

- **BGP**:

  特点: 适用BGP路由导向流量

  优点: Pod之间直接通信.省去了隧道,封装,解封装等任何中间环节,传输效率非常高.

  缺点: 需要确保所有物理节点在同一个二层网络,否则Pod无法跨节点网段通信

#### Calico网络优化

##### MTU

Calico 的IPIP网络模型下tunl0接口的MTU默认为1440，这种设置主要是为适配Google的GCE环境，在非GCE的物理环境中，其最佳值为1480。因此，对于非GCE环境的部署，建议将配置清单calico.yaml下载至本地修改后，再将其应用到集群中。要修改的内容是DaemonSet资源calico-node的Pod模板，将容器calico-node的环境变量“FELIX_INPUTMTU”的值修改为1480即可

> 因为IPIP多了一层IP报文封装,而IP报文头部一般是20个字节.所以MUT的值应该是最大1500-20.

##### Calico-typha

对于50个节点以上规模的集群来说，所有Calico节点均基于Kubernetes API存取数据会为API Server带来不小的通信压力，这就应该使用calico-typha进程将所有Calico的通信集中起来与API Server进行统一交互。calico-typha以Pod资源的形式托管运行于Kubernetes系统之上，启用的方法为下载前面步骤中用到的Calico的部署清单文件至本地，修改其calico-typha的Pod资源副本数量为所期望的值并重新应用配置清单即可：

```
apiVersion: apps/v1beta1
kind: Deployment
metadata:
  name: calico-typha
  ...
spec:
  ...
  replicas: <number of replicas>
```

每个calico-typha Pod资源可承载100到200个Calico节点的连接请求，最多不要超过200个。另外，整个集群中的calico-typha的Pod资源总数尽量不要超过20个。

##### BGP路由模型

默认情况下，Calico的BGP网络工作于点对点的网格（node-to-node mesh）模型，它仅适用于较小规模的集群环境。中级集群环境应该使用全局对等BGP模型（Global BGP peers），以在同一二层网络中使用一个或一组BGP反射器构建BGP网络环境。而大型集群环境需要使用每节点对等BGP模型（Per-node BGP peers），即分布式BGP反射器模型，一个典型的用法是将每个节点都配置为自带BGP反射器接入机架顶部交换机上的路由反射器。

##### 使用BGP而非IPIP

事实上，仅在那些不支持用户自定义BGP配置的网络中才需要使用IPIP的隧道通信类型。如果有一个自主可控的网络环境且部署规模较大时，可以考虑启用BGP的通信类型降低网络开销以提升传输性能，并且应该部署BGP反射器来提高路由学习效率。

#### 参考资料

Calico官网: [www.projectcalico.org](http://www.projectcalico.org/)

k8s网络之Calico网络: https://www.cnblogs.com/goldsunshine/p/10701242.html#mxAMjXzT

kubernetes容器网络: https://tech.ipalfish.com/blog/2020/03/06/kubernetes_container_network/ (伴鱼团队)

### [Calico IPIP网络模式](https://network.51cto.com/art/202105/660965.htm)

本文主要分析k8s中网络组件calico的 IPIP网络模式。旨在理解IPIP网络模式下产生的calixxxx，tunl0等设备以及跨节点网络通信方式。可能看着有点枯燥，但是请花几分钟时间坚持看完，如果看到后面忘了前面，请反复看两遍，这几分钟时间一定你会花的很值。

#### calico介绍

Calico是Kubernetes生态系统中另一种流行的网络选择。虽然Flannel被公认为是最简单的选择，但Calico以其性能、灵活性而闻名。Calico的功能更为全面，不仅提供主机和pod之间的网络连接，还涉及网络安全和管理。Calico CNI插件在CNI框架内封装了Calico的功能。

Calico是一个基于BGP的纯三层的网络方案，与OpenStack、Kubernetes、AWS、GCE等云平台都能够良好地集成。Calico在每个计算节点都利用Linux Kernel实现了一个高效的虚拟路由器vRouter来负责数据转发。每个vRouter都通过BGP1协议把在本节点上运行的容器的路由信息向整个Calico网络广播，并自动设置到达其他节点的路由转发规则。Calico保证所有容器之间的数据流量都是通过IP路由的方式完成互联互通的。Calico节点组网时可以直接利用数据中心的网络结构(L2或者L3)，不需要额外的NAT、隧道或者Overlay Network，没有额外的封包解包，能够节约CPU运算，提高网络效率。

此外，Calico基于iptables还提供了丰富的网络策略，实现了Kubernetes的Network Policy策略，提供容器间网络可达性限制的功能。

**calico官网：**https://www.projectcalico.org/

#### calico架构及核心组件

架构图如下：

![img](Calico架构.png)

calico核心组件：

- Felix：运行在每个需要运行workload的节点上的agent进程。主要负责配置路由及 ACLs(访问控制列表) 等信息来确保 endpoint 的连通状态，保证跨主机容器的网络互通;
- ETCD：强一致性、高可用的键值存储，持久存储calico数据的存储管理系统。主要负责网络元数据一致性，确保Calico网络状态的准确性;
- BGP Client(BIRD)：读取Felix设置的内核路由状态，在数据中心分发状态。
- BGP Route Reflector(BIRD)：BGP路由反射器，在较大规模部署时使用。如果仅使用BGP Client形成mesh全网互联就会导致规模限制，因为所有BGP client节点之间两两互联，需要建立N^2个连接，拓扑也会变得复杂。因此使用reflector来负责client之间的连接，防止节点两两相连。

#### calico工作原理

Calico把每个操作系统的协议栈认为是一个路由器，然后把所有的容器认为是连在这个路由器上的网络终端，在路由器之间跑标准的路由协议——BGP的协议，然后让它们自己去学习这个网络拓扑该如何转发。所以Calico方案其实是一个纯三层的方案，也就是说让每台机器的协议栈的三层去确保两个容器，跨主机容器之间的三层连通性。

#### calico的两种网络方式

- IPIP

  把 IP 层封装到 IP 层的一个 tunnel。它的作用其实基本上就相当于一个基于IP层的网桥!一般来说，普通的网桥是基于mac层的，根本不需 IP，而这个 ipip 则是通过两端的路由做一个 tunnel，把两个本来不通的网络通过点对点连接起来。ipip 的源代码在内核 net/ipv4/ipip.c 中可以找到。

- BGP

  边界网关协议(Border Gateway Protocol, BGP)是互联网上一个核心的去中心化自治路由协议。它通过维护IP路由表或‘前缀’表来实现自治系统(AS)之间的可达性，属于矢量路由协议。BGP不使用传统的内部网关协议(IGP)的指标，而使用基于路径、网络策略或规则集来决定路由。因此，它更适合被称为矢量性协议，而不是路由协议。

#### PIP网络模式分析

由于个人环境中使用的是IPIP模式，因此接下来这里分析一下这种模式。

```
# kubectl get po -o wide -n paas | grep hello
demo-hello-perf-d84bffcb8-7fxqj   1/1     Running   0          9d      10.20.105.215   node2.perf  <none>           <none> 
demo-hello-sit-6d5c9f44bc-ncpql   1/1     Running   0          9d      10.20.42.31     node1.sit   <none>           <none> 
```

进行ping测试

这里在demo-hello-perf这个pod中ping demo-hello-sit这个pod。

```
root@demo-hello-perf-d84bffcb8-7fxqj:/# ping 10.20.42.31 
PING 10.20.42.31 (10.20.42.31) 56(84) bytes of data. 
64 bytes from 10.20.42.31: icmp_seq=1 ttl=62 time=5.60 ms 
64 bytes from 10.20.42.31: icmp_seq=2 ttl=62 time=1.66 ms 
64 bytes from 10.20.42.31: icmp_seq=3 ttl=62 time=1.79 ms 
^C 
--- 10.20.42.31 ping statistics --- 
3 packets transmitted, 3 received, 0% packet loss, time 6ms 
rtt min/avg/max/mdev = 1.662/3.015/5.595/1.825 ms 
```

进入pod demo-hello-perf中查看这个pod中的路由信息

```
root@demo-hello-perf-d84bffcb8-7fxqj:/# route -n 
Kernel IP routing table 
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface 
0.0.0.0         169.254.1.1     0.0.0.0         UG    0      0        0 eth0 
169.254.1.1     0.0.0.0         255.255.255.255 UH    0      0        0 eth0 
```

根据路由信息，ping 10.20.42.31，会匹配到第一条。

**第一条路由的意思是：**去往任何网段的数据包都发往网关169.254.1.1，然后从eth0网卡发送出去。

demo-hello-perf所在的node node2.perf 宿主机上路由信息如下：

```
# route -n 
Kernel IP routing table 
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface 
0.0.0.0         172.16.36.1     0.0.0.0         UG    100    0        0 eth0 
10.20.42.0      172.16.35.4     255.255.255.192 UG    0      0        0 tunl0 
10.20.105.196   0.0.0.0         255.255.255.255 UH    0      0        0 cali4bb1efe70a2 
169.254.169.254 172.16.36.2     255.255.255.255 UGH   100    0        0 eth0 
172.16.36.0     0.0.0.0         255.255.255.0   U     100    0        0 eth0 
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0 
```

可以看到一条Destination为 10.20.42.0的路由。

意思是：当ping包来到master节点上，会匹配到路由tunl0。该路由的意思是：去往10.20.42.0/26的网段的数据包都发往网关172.16.35.4。因为demo-hello-perf的pod在172.16.36.5上，demo-hello-sit的pod在172.16.35.4上。所以数据包就通过设备tunl0发往到node节点上。

demo-hello-sit所在的node node1.sit 宿主机上路由信息如下：

```
# route -n 
Kernel IP routing table 
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface 
0.0.0.0         172.16.35.1     0.0.0.0         UG    100    0        0 eth0 
10.20.15.64     172.16.36.4     255.255.255.192 UG    0      0        0 tunl0 
10.20.42.31     0.0.0.0         255.255.255.255 UH    0      0        0 cali04736ec14ce 
10.20.105.192   172.16.36.5     255.255.255.192 UG    0      0        0 tunl0 
```

当node节点网卡收到数据包之后，发现发往的目的ip为10.20.42.31，于是匹配到Destination为10.20.42.31的路由。

该路由的意思是：10.20.42.31是本机直连设备，去往设备的数据包发往cali04736ec14ce

**为什么这么奇怪会有一个名为cali04736ec14ce的设备呢?这是个啥玩意儿呢?**

其实这个设备就是veth pair的一端。在创建demo-hello-sit 时calico会给demo-hello-sit创建一个veth pair设备。一端是demo-hello-sit 的网卡，另一端就是我们看到的cali04736ec14ce

接着验证一下。我们进入demo-hello-sit 的pod，查看到 4 号设备后面的编号是：122964

```
root@demo-hello-sit--6d5c9f44bc-ncpql:/# ip a 
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 
    inet 127.0.0.1/8 scope host lo 
       valid_lft forever preferred_lft forever 
2: tunl0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000 
    link/ipip 0.0.0.0 brd 0.0.0.0 
4: eth0@if122964: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1380 qdisc noqueue state UP group default  
    link/ether 9a:7d:b2:26:9b:17 brd ff:ff:ff:ff:ff:ff link-netnsid 0 
    inet 10.20.42.31/32 brd 10.20.42.31 scope global eth0 
       valid_lft forever preferred_lft forever 
```

然后我们登录到demo-hello-sit这个pod所在的宿主机查看

```
# ip a | grep -A 5 "cali04736ec14ce" 
122964: cali04736ec14ce@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1380 qdisc noqueue state UP group default  
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netnsid 16 
    inet6 fe80::ecee:eeff:feee:eeee/64 scope link  
       valid_lft forever preferred_lft forever 
120918: calidd1cafcd275@if4: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1380 qdisc noqueue state UP group default  
    link/ether ee:ee:ee:ee:ee:ee brd ff:ff:ff:ff:ff:ff link-netnsid 2 
```

发现pod demo-hello-sit中 的另一端设备编号和这里在node上看到的cali04736ec14ce编号122964是一样的

所以，node上的路由，发送cali04736ec14ce网卡设备的数据其实就是发送到了demo-hello-sit的这个pod中去了。到这里ping包就到了目的地。

注意看 demo-hello-sit这个pod所在的宿主机的路由，有一条 Destination为10.20.105.192的路由

```
# route -n 
Kernel IP routing table 
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface 
... 
0.0.0.0         172.16.35.1     0.0.0.0         UG    100    0        0 eth0 
10.20.105.192   172.16.36.5     255.255.255.192 UG    0      0        0 tunl0 
... 
```

再查看一下demo-hello-sit的pod中路由信息，和demo-hello-perf的pod中是一样的。

所以综合上述例子来看，IPIP的网络模式就是将IP网络封装了一层。特点就是所有pod的数据流量都从隧道tunl0发送，并且tunl0这里增加了一层传输层的封包操作。

#### 抓包分析

在demo-hello-perf这个pod中ping demo-hello-sit这个pod，接着在demo-hello-sit这个pod所在的宿主机进行tcpdump

```
# tcpdump  -i eth0 -nn -w icmp_ping.cap 
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes 
```

在demo-hello-perf这个pod中进行ping demo-hello-sit的操作

```
root@demo-hello-perf-d84bffcb8-7fxqj:/# ping 10.20.42.31 
PING 10.20.42.31 (10.20.42.31) 56(84) bytes of data. 
64 bytes from 10.20.42.31: icmp_seq=1 ttl=62 time=5.66 ms 
64 bytes from 10.20.42.31: icmp_seq=2 ttl=62 time=1.68 ms 
64 bytes from 10.20.42.31: icmp_seq=3 ttl=62 time=1.61 ms 
^C 
--- 10.20.42.31 ping statistics --- 
3 packets transmitted, 3 received, 0% packet loss, time 6ms 
rtt min/avg/max/mdev = 1.608/2.983/5.659/1.892 ms 
```

结束抓包后下载icmp_ping.cap到本地windows进行抓包分析

能看到该数据包一共5层，其中IP(Internet Protocol)所在的网络层有两个，分别是pod之间的网络和主机之间的网络封装。

![img](Calico-IPIP抓包1.png)

红色框选的是两个pod所在的宿主机，蓝色框选的是两个pod的ip，src表示发起ping操作的pod所在的宿主机ip以及发起ping操作的pod的ip，dst表示被ping的pod所在的宿主机ip及被ping的pod的ip

根据数据包的封装顺序，应该是在demo-hello-perf ping demo-hello-sit的ICMP包外面多封装了一层主机之间的数据包。

![img](Calico-IPIP报文结构.png)

可以看到每个数据报文共有两个IP网络层,内层是Pod容器之间的IP网络报文,外层是宿主机节点的网络报文(2个node节点)。之所以要这样做是因为tunl0是一个隧道端点设备，在数据到达时要加上一层封装，便于发送到对端隧道设备中。

两层封包的具体内容如下：

![img](Calico-IPIP抓包2.png)

Pod间的通信经由IPIP的三层隧道转发,相比较VxLAN的二层隧道来说，IPIP隧道的开销较小，但其安全性也更差一些。

#### pod到svc的访问

查看service

```
# kubectl get svc -o wide -n paas | grep hello 
demo-hello-perf              ClusterIP   10.10.255.18    <none>        8080/TCP              10d    appEnv=perf,appName=demo-hello 
demo-hello-sit               ClusterIP   10.10.48.254    <none>        8080/TCP              10d    appEnv=sit,appName=demo-hello 
```

在pod demo-hello-sit 的宿主机上抓包

```
# tcpdump -i eth0 -nn -w svc.cap 
tcpdump: listening on eth0, link-type EN10MB (Ethernet), capture size 262144 bytes 
```

测试访问，在demo-hello-sit中curl demo-hello-perf的svc的地址和端口

```
root@demo-hello-perf-d84bffcb8-7fxqj:/# curl -I http://10.10.48.254:8080/actuator/health 
HTTP/1.1 200 
Content-Type: application/vnd.spring-boot.actuator.v3+json 
Transfer-Encoding: chunked 
Date: Fri, 30 Apr 2021 01:42:56 GMT 
 
root@demo-hello-perf-d84bffcb8-7fxqj:/# curl -I http://10.10.48.254:8080/actuator/health 
HTTP/1.1 200 
Content-Type: application/vnd.spring-boot.actuator.v3+json 
Transfer-Encoding: chunked 
Date: Fri, 30 Apr 2021 01:42:58 GMT 
 
root@demo-hello-perf-d84bffcb8-7fxqj:/# curl -I http://10.10.48.254:8080/actuator/health 
HTTP/1.1 200 
Content-Type: application/vnd.spring-boot.actuator.v3+json 
Transfer-Encoding: chunked 
Date: Fri, 30 Apr 2021 01:42:58 GMT 
```

结束抓包，下载svc.cap文件放到wireshark中打开查看

![img](Calico-IPIP抓包3.png)

可以看到wireshark中Src和Dst的结果。任然是和上面pod中访问pod的ip地址一样。这里Src和Dst任然是两个pod的宿主机的内网ip和两个pod自己的ip地址。是用ipip的方式进行通信的。
