package com.blue.pcap;

import com.blue.pcap.packet.Packet;

public interface PacketFilter {
	public void init();
	
	public void start();
	public void filter(PacketFilter filter, Packet p);
	public void end();
	
	public void finish();
	
}
