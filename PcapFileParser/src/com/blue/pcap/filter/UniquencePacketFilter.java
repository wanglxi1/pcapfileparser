package com.blue.pcap.filter;

import java.util.HashSet;
import java.util.Set;

import com.blue.pcap.PacketFilter;
import com.blue.pcap.packet.Packet;
import com.blue.pcap.protocol.Protocol;
import com.blue.pcap.protocol.TCP;


public class UniquencePacketFilter extends PacketFilterAdapter {

	private Set<Long> tcpSequenceNumbers = new HashSet<Long>();
	
	@Override
	public void filter(PacketFilter filter, Packet p) {
		Protocol pr = p.getProtocol();
		if(pr instanceof TCP) {
			TCP tcp = (TCP)pr;
			long curSequence = tcp.getSequenceNumber();
			if(tcpSequenceNumbers.contains(curSequence)){
				//skip
			}else{
				tcpSequenceNumbers.add(curSequence);
				filter.filter(filter, p);
			}
		}else {
			filter.filter(filter, p);
		}
	}
	
	@Override
	public void finish() {
		this.tcpSequenceNumbers.clear();
	}

}
