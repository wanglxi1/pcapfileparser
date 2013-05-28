package com.blue.pcap.packet;

import java.text.MessageFormat;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.protocol.Ethernet;
import com.blue.pcap.protocol.Ip;
import com.blue.pcap.protocol.Tcp;
import com.blue.pcap.util.StringUtil;

public class Packet {
	long index;
	PacketHeader header;
	Ethernet ethernet;
	Ip ip;
	Tcp tcp;
	byte[] data;
	
	public static Packet valueOf(IoBuffer buf) {
		Packet p = new Packet();
		
		p.header = PacketHeader.valueOf(buf);
		
		p.ethernet = Ethernet.valueOf(buf);
		p.ip = Ip.valueOf(buf);
		p.tcp = Tcp.valueOf(buf);
		
		int dataLen = p.ip.getTotalLen() - p.ip.getHeaderLen() - p.tcp.getHeaderLen();
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

	public Ip getIp() {
		return ip;
	}

	public Tcp getTcp() {
		return tcp;
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
				String.valueOf(tcp.getSourcePort()),
				ip.getDestination(),
				String.valueOf(tcp.getDestinationPort()),
				header,
				StringUtil.byte2HexString(data)
			);
	}
}
