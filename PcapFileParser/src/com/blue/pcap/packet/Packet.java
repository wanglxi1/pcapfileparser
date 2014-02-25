package com.blue.pcap.packet;

import java.text.MessageFormat;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.protocol.IP;
import com.blue.pcap.protocol.IP.ProtocolEnum;
import com.blue.pcap.protocol.part.Ethernet;
import com.blue.pcap.protocol.Protocol;
import com.blue.pcap.protocol.TCP;
import com.blue.pcap.util.StringUtil;

public class Packet {
	long index;
	PacketHeader header;
	Ethernet ethernet;
	IP ip;
	Protocol protocol;
	byte[] data;
	
	public static Packet valueOf(IoBuffer buf) {
		Packet p = new Packet();
		
		p.header = PacketHeader.valueOf(buf);
		p.ethernet = Ethernet.valueOf(buf);
		p.ip = IP.valueOf(buf);
		
		int protocolHeaderLen = 0;
		ProtocolEnum protocol = p.ip.getProtocol();
		if(protocol != null) {
			Class clz = null;
			try {
				clz = Class.forName("com.blue.pcap.protocol."+protocol.name());
				
				if(clz != null) {
					Protocol proc = (Protocol) clz.newInstance();
					proc.valueOf(buf);
					protocolHeaderLen = proc.getHeaderLen();
					p.protocol = proc;
				}
			}catch(Exception e) {}
		}
		
		int dataLen = p.ip.getTotalLen() - p.ip.getHeaderLen() - protocolHeaderLen;
		p.data = new byte[dataLen];
		buf.get(p.data);
		
		int remain = p.header.getCaplen() - Ethernet.LENGTH - p.ip.getTotalLen();
		if(remain > 0) {
			byte[] bs = new byte[remain];
			buf.get(bs);
			p.ethernet.setPadding(bs);
		}
		
		return p; 
	}
	
	public PacketHeader getHeader() {
		return header;
	}

	public Ethernet getEthernet() {
		return ethernet;
	}

	public IP getIp() {
		return ip;
	}

	public Protocol getProtocol() {
		return protocol;
	}

	public byte[] getData() {
		return data;
	}

	public long getIndex() {
		return index;
	}

	public void setIndex(long index) {
		this.index = index;
	}

	@Override
	public String toString() {
		return MessageFormat.format("[{0}] S={2}:{3} D={4}:{5} ({1}) {6} \n{7}\n", 
				String.valueOf(index),
				String.valueOf(data.length),
				ip.getSource(),
				(protocol instanceof TCP)? String.valueOf(((TCP)protocol).getSourcePort()): "",
				ip.getDestination(),
				(protocol instanceof TCP)? String.valueOf(((TCP)protocol).getDestinationPort()): "",
				header,
				StringUtil.byte2HexString(data)
			);
	}
}
