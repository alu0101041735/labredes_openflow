#!/usr/bin/python
#coding=utf-8

# Envía un paquete construido en el controlador a través de un puerto
# del switch.
def send_packet(self, datapath, port, pkt):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    pkt.serialize()
       
    data = pkt.data
    actions = [parser.OFPActionOutput(port=port)]
    out = parser.OFPPacketOut(datapath=datapath,
                                buffer_id=ofproto.OFP_NO_BUFFER,
                                in_port=ofproto.OFPP_CONTROLLER,
                                actions=actions,
                                data=data)
    datapath.send_msg(out)
        
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
