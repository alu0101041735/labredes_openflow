#!/usr/bin/python
#coding=utf-8
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.base import app_manager
from ryu.lib import mac
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.ofproto import ether

class L2Forwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    mac_to_port = dict()
    ip_to_mac = list()

    def __init__(self, *args, **kwargs):
        super(L2Forwarding, self).__init__(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        datapath.id = msg.datapath_id

        ofproto_parser = datapath.ofproto_parser

        set_config = ofproto_parser.OFPSetConfig(
            datapath,
            datapath.ofproto.OFPC_FRAG_NORMAL,
            datapath.ofproto.OFPCML_MAX,
        )
	
        datapath.send_msg(set_config)
	
        match = datapath.ofproto_parser.OFPMatch()

        actions = [datapath.ofproto_parser.OFPActionOutput(
                datapath.ofproto.OFPP_CONTROLLER,
                datapath.ofproto.OFPCML_NO_BUFFER)]
        inst = [datapath.ofproto_parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = datapath.ofproto_parser.OFPFlowMod(
                datapath=datapath,
                priority=0,
                buffer_id=0xffffffff,
                match=match,
                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        msg = ev.msg               # Objeto que representa la estuctura de datos PacketIn.
        datapath = msg.datapath    # Identificador del datapath correspondiente al switch.
        ofproto = datapath.ofproto # Protocolo utilizado que se fija en una etapa 
                                   # de negociacion entre controlador y switch

        ofp_parser=datapath.ofproto_parser # Parser con la version OF
					   # correspondiente

        in_port = msg.match['in_port'] # Puerto de entrada.

        # Ahora analizamos el paquete utilizando las clases de la libreria packet.
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Extraemos la MAC de destino

        dst = eth.dst

        src = eth.src

        self.mac_to_port[src] = in_port


        ###############################

        if (haddr_to_bin(dst) == mac.BROADCAST) or mac.is_multicast(haddr_to_bin(dst)): 
            actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)
        
        else:
            if dst in self.mac_to_port.keys():
                self.send_packet(datapath, self.mac_to_port[dst], pkt)

            else:
                actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

        ###############################

        if eth.ethertype == ether.ETH_TYPE_ARP:
            print("arp message")
            arp_msg = pkt.get_protocol(arp.arp)

            import ipdb;ipdb.set_trace()
            ip_mac = (arp_msg.src_ip, arp_msg.src_mac)
            self.ip_to_mac.append(ip_mac)

            if (arp_msg.dst_ip == self.interfaces[in_port][0] and arp_msg.opcode == arp.ARP_REQUEST):
                print("dst ip on interfaces")
                if arp_msg.dst_ip in self.ip_to_mac:
                    print("dst mac on list, reply to original host")
                    e = ethernet.ethernet(dst = src, 
                        src = self.mac_to_port[dst],
                        ethertype=ether.ETH_TYPE_ARP)
                    a = arp.arp(opcode = arp.ARP_REPLY, 
                        src_mac = self.mac_to_port[dst], src_ip=arp_msg.dst_ip, 
                        dst_mac = src, dst_ip = arp_msg.src_ip)

                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)

                    self.send_packet(datapath, in_port, p)

                else:
                    print("Dst mac not on list, request to host")
                    e = ethernet.ethernet(src = arp_msg.src_mac,
                        ethertype=ether.ETH_TYPE_ARP)
                    a = arp.arp(opcode = arp.ARP_REQUEST, 
                        src_mac = arp_msg.src_mac, src_ip=arp_msg.src_ip, 
                        dst_ip = arp_msg.dst_ip)

                    p = packet.Packet()
                    p.add_protocol(e)
                    p.add_protocol(a)

                    self.send_packet(datapath, self.mac_to_port[dst].value, p)
            else:
                print("I don't know anything")
                # Inundamos
                actions = [ofp_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                match = ofp_parser.OFPMatch(in_port=in_port, eth_dst=dst)
                self.add_flow(datapath, 1, match, actions)

                



        ###############################

    #  Inserta una entrada a la tabla de flujo.
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                    priority=priority, match=match,
                    instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                    match=match, instructions=inst, idle_timeout=30,command=ofproto.OFPFC_ADD)
       
        datapath.send_msg(mod)


    # Envía un paquete construido en el controlador a través de un puerto
    # del switch.
    def send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
           
        # import pdb;pdb.set_trace()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions,
                                    data=data)
        datapath.send_msg(out)
