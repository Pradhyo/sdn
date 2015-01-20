from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, tcp, udp, icmp, ipv4
from ryu.ofproto import ether



class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_host = {'10.0.0.1': '00:00:00:00:00:01', '10.0.0.2': '00:00:00:00:00:02', '10.0.0.3': '00:00:00:00:00:03', '10.0.0.4': '00:00:00:00:00:04'}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        match = parser.OFPMatch(eth_dst='33:33:00:00:00:02')
        actions = {}
        self.add_flow(datapath, 10, match, actions)

          

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        port = in_port
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        actionport = 0
        dpid = datapath.id
        pkt_arp = pkt.get_protocol(arp.arp) 
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)

        
        if pkt_tcp or pkt_icmp:

            #print pkt_ipv4
            src_ip = pkt_ipv4.src
            dst_ip = pkt_ipv4.dst

            if dpid == 3:

                if dst == '00:00:00:00:00:02' or dst == '00:00:00:00:00:04':
                    action = [parser.OFPActionOutput(3)]
                    actionport = 3
                    match1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02',eth_type=0x0800,ip_proto=6)
                    match1a = parser.OFPMatch(eth_dst='00:00:00:00:00:04',eth_type=0x0800,ip_proto=6)
                    self.logger.info("This line gets executed")
                    self.add_flow(datapath, 1, match1, action)
                    self.add_flow(datapath, 1, match1a, action)
                    match1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02',eth_type=0x0800,ip_proto=1)
                    match1a = parser.OFPMatch(eth_dst='00:00:00:00:00:04',eth_type=0x0800,ip_proto=1)
                    self.logger.info("This line gets executed")
                    self.add_flow(datapath, 1, match1, action)
                    self.add_flow(datapath, 1, match1a, action)
                    

                elif (dst == '00:00:00:00:00:03' and src == '00:00:00:00:00:01' and pkt_tcp) or (dst == '00:00:00:00:00:01' and src == '00:00:00:00:00:03' and pkt_tcp):
                    
                    #self._handle_tcp_reset(self,datapath, dst, src, pkt_ethernet, pkt_ipv4, in_port, src_ip, dst_ip)
                    new_pkt = packet.Packet()
                            
                    new_pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                               dst=src,
                                               src=dst))
                    new_pkt.add_protocol(ipv4.ipv4(dst=src_ip,
                                       src=dst_ip,
                                       proto=pkt_ipv4.proto))
                    new_pkt.add_protocol(tcp.tcp(src_port=80,dst_port=1, seq=0, ack=0, offset=0, bits=20, window_size=0, csum=0, urgent=0, option=None))
                    self._send_packet(datapath, in_port, new_pkt) 
                    #self.send_set_config(self, datapath)
                    ofp = datapath.ofproto
                    ofp_parser = datapath.ofproto_parser

                    req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_DROP, 256)
                    datapath.send_msg(req)

                    return

                                        
                elif dst == '00:00:00:00:00:01':            
                    action = [parser.OFPActionOutput(1)]
                    actionport = 1
                    match2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01',eth_type=0x0800,ip_proto=6)
                    self.add_flow(datapath, 1, match2, action)
                    match2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01',eth_type=0x0800,ip_proto=1)
                    self.add_flow(datapath, 1, match2, action)

                elif dst == '00:00:00:00:00:03':
                    action = [parser.OFPActionOutput(2)]
                    actionport = 2
                    match3 = parser.OFPMatch(eth_dst='00:00:00:00:00:03',eth_type=0x0800,ip_proto=6)
                    self.add_flow(datapath, 1, match3, action)
                    match3 = parser.OFPMatch(eth_dst='00:00:00:00:00:03',eth_type=0x0800,ip_proto=1)
                    self.add_flow(datapath, 1, match3, action)
                else:
                    print ''
                

            elif dpid == 4:

                if dst == '00:00:00:00:00:02':
                    action = [parser.OFPActionOutput(1)]
                    actionport = 1
                    match1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02',eth_type=0x0800,ip_proto=6)
                    self.add_flow(datapath, 1, match1, action)
                    match1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02',eth_type=0x0800,ip_proto=1)
                    self.add_flow(datapath, 1, match1, action)

                elif dst == '00:00:00:00:00:04':
                    action = [parser.OFPActionOutput(2)]
                    actionport = 2
                    match3 = parser.OFPMatch(eth_dst='00:00:00:00:00:04',eth_type=0x0800,ip_proto=6)
                    self.add_flow(datapath, 1, match3, action)
                    match3 = parser.OFPMatch(eth_dst='00:00:00:00:00:04',eth_type=0x0800,ip_proto=1)
                    self.add_flow(datapath, 1, match3, action)

                elif dst == '00:00:00:00:00:01' or dst == '00:00:00:00:00:03':
                    action = [parser.OFPActionOutput(3)]
                    actionport = 3
                    match2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01',eth_type=0x0800,ip_proto=6)
                    match2a = parser.OFPMatch(eth_dst='00:00:00:00:00:03',eth_type=0x0800,ip_proto=6)
                    self.add_flow(datapath, 1, match2, action)
                    self.add_flow(datapath, 1, match2a, action)
                    match2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01',eth_type=0x0800,ip_proto=1)
                    match2a = parser.OFPMatch(eth_dst='00:00:00:00:00:03',eth_type=0x0800,ip_proto=1)
                    self.add_flow(datapath, 1, match2, action)
                    self.add_flow(datapath, 1, match2a, action)
                else:
                    print ''

            else:
                print ''
                

            #actionport = self._handle_tcp(datapath, dst, dpid, parser)
       

        if pkt_udp:

            if dpid == 3:

                if (dst == '00:00:00:00:00:02' and src == '00:00:00:00:00:03'):
                    actions = {}
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=None)
                    datapath.send_msg(out)
                    match = parser.OFPMatch(eth_dst='00:00:00:00:00:02', eth_src='00:00:00:00:00:03',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath,3,match,actions)
                    return

                elif dst == '00:00:00:00:00:02' or dst == '00:00:00:00:00:04':
                    action = [parser.OFPActionOutput(4)]
                    actionport = 4
                    match1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02',eth_type=0x0800,ip_proto=17)
                    match1a = parser.OFPMatch(eth_dst='00:00:00:00:00:04',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath, 1, match1, action)
                    self.add_flow(datapath, 1, match1a, action)
                    
                    
                elif dst == '00:00:00:00:00:01':            
                    action = [parser.OFPActionOutput(1)]
                    actionport = 1
                    match2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath, 1, match2, action)

                elif dst == '00:00:00:00:00:03':
                    action = [parser.OFPActionOutput(2)]
                    actionport = 2
                    match3 = parser.OFPMatch(eth_dst='00:00:00:00:00:03',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath, 1, match3, action)
                else:
                    print ''
                    

            elif dpid == 4:

                if (dst == '00:00:00:00:00:03' and src == '00:00:00:00:00:02'):
                    actions = {}
                    out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=None)
                    datapath.send_msg(out)
                    match = parser.OFPMatch(eth_dst='00:00:00:00:00:03', eth_src='00:00:00:00:00:02',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath,3,match,actions)
                 
                    return


                elif dst == '00:00:00:00:00:02':
                    action = [parser.OFPActionOutput(1)]
                    actionport = 1
                    match1 = parser.OFPMatch(eth_dst='00:00:00:00:00:02',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath, 1, match1, action)

                elif dst == '00:00:00:00:00:04':
                    action = [parser.OFPActionOutput(2)]
                    actionport = 2
                    match3 = parser.OFPMatch(eth_dst='00:00:00:00:00:04',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath, 1, match3, action)

                elif dst == '00:00:00:00:00:01' or dst == '00:00:00:00:00:03':
                    action = [parser.OFPActionOutput(4)]
                    actionport = 4
                    match2 = parser.OFPMatch(eth_dst='00:00:00:00:00:01',eth_type=0x0800,ip_proto=17)
                    match2a = parser.OFPMatch(eth_dst='00:00:00:00:00:03',eth_type=0x0800,ip_proto=17)
                    self.add_flow(datapath, 1, match2, action)
                    self.add_flow(datapath, 1, match2a, action)
                else:
                    print ''

            elif dpid == 5:

                if in_port == 1:
                    action1 = [parser.OFPActionOutput(2)]
                    actionport = 2
                    match1 = parser.OFPMatch(in_port = in_port)
                    self.add_flow(datapath, 1, match1, action1)
                elif in_port == 2:
                    action2 = [parser.OFPActionOutput(1)]
                    actionport = 1
                    match2 = parser.OFPMatch(in_port = in_port)
                    self.add_flow(datapath, 1, match2, action2)
            else:
                print ''

            #self._handle_udp(datapath, eth.dst, dpid, parser)        
            
                   
        if pkt_arp:
            if self.arp_host.has_key(pkt_arp.dst_ip):
                self._handle_arp(datapath, in_port, pkt_ethernet, pkt_arp)
            return

        #self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, actionport)

        actions = [parser.OFPActionOutput(actionport)]
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

   
    def _handle_arp(self, datapath, port, pkt_ethernet, pkt_arp):
        
        hw_addr = self.arp_host[pkt_arp.dst_ip]

        if pkt_arp.opcode != arp.ARP_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                            dst=pkt_ethernet.src,
                                            src=hw_addr))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=hw_addr,
                                src_ip=pkt_arp.dst_ip,
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
        self._send_packet(datapath, port, pkt)

    def _handle_tcp_reset(self,datapath, dst, src, pkt_ethernet, pkt_ipv4, in_port, src_ip, dst_ip):
        new_pkt = packet.Packet()
                
        new_pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                   dst=dst,
                                   src=src))
        new_pkt.add_protocol(ipv4.ipv4(dst=dst_ip,
                           src=src_ip,
                           proto=pkt_ipv4.proto))
        new_pkt.add_protocol(tcp.tcp(src_port=80, dst_port=1, rst=1, seq=0, ack=0, offset=0, bits=4, window_size=0, csum=0, urgent=0, option=None))
        self._send_packet(datapath, in_port, new_pkt)                
        

    def _handle_icmp(self, datapath, port, pkt_ethernet, pkt_ipv4, pkt_icmp):

        hw_addr = self.arp_host[pkt_ipv4.dst]

        if pkt_icmp.type != icmp.ICMP_ECHO_REQUEST:
            return
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=pkt_ethernet.ethertype,
                                            dst=pkt_ethernet.src,
                                            src=hw_addr))
        pkt.add_protocol(ipv4.ipv4(dst=pkt_ipv4.src,
                                    src=pkt_ipv4.dst,
                                    proto=pkt_ipv4.proto))
        pkt.add_protocol(icmp.icmp(type_=icmp.ICMP_ECHO_REPLY,
                                    code=icmp.ICMP_ECHO_REPLY_CODE,
                                    csum=0,
                                    data=pkt_icmp.data))
        self._send_packet(datapath, port, pkt)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions,
                                    data=data)
        datapath.send_msg(out)

    def send_set_config(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_DROP, 256)
        datapath.send_msg(req)

    
