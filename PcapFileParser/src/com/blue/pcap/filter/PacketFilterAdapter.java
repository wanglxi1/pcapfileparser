package com.blue.pcap.filter;

import com.blue.pcap.PacketFilter;
import com.blue.pcap.packet.Packet;

public class PacketFilterAdapter implements PacketFilter {
	
	@Override
	public void init() {}

	@Override
	public void filter(PacketFilter filter, Packet p) {	}

	@Override
	public void finish() {	}

}
