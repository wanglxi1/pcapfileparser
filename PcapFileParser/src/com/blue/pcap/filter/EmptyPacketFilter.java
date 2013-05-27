package com.blue.pcap.filter;

import com.blue.pcap.PacketFilter;
import com.blue.pcap.packet.Packet;

public class EmptyPacketFilter extends PacketFilterAdapter {

	@Override
	public void filter(PacketFilter filter, Packet p) {
		if(p.getData().length > 0){
			filter.filter(filter, p);
		}
	}

}
