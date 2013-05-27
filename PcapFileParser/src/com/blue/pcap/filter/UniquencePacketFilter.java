package com.blue.pcap.filter;

import java.util.HashSet;
import java.util.Set;

import com.blue.pcap.PacketFilter;
import com.blue.pcap.packet.Packet;


public class UniquencePacketFilter extends PacketFilterAdapter {

	private Set<Long> tcpSequenceNumbers = new HashSet<Long>();
	
	@Override
	public void filter(PacketFilter filter, Packet p) {
		long curSequence = p.getTcp().getSequenceNumber();
		if(tcpSequenceNumbers.contains(curSequence)){
			//skip
		}else{
			tcpSequenceNumbers.add(curSequence);
			filter.filter(filter, p);
		}
	}
	
	@Override
	public void finish() {
		this.tcpSequenceNumbers.clear();
	}

}
