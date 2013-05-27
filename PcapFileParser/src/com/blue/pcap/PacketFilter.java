package com.blue.pcap;

import com.blue.pcap.packet.Packet;

public interface PacketFilter {
	public void init();
	
	public void filter(PacketFilter filter, Packet p);
	
	public void finish();
	
}
