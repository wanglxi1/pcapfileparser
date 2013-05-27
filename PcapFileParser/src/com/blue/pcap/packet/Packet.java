package com.blue.pcap.packet;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.protocol.Ethernet;
import com.blue.pcap.protocol.Ip;
import com.blue.pcap.protocol.Tcp;

public class Packet {
	public static long PRE_SEQUENCENUMBER = -1;
	
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
		if(dataLen > 0) {//只读取有数据的
			if(PRE_SEQUENCENUMBER==-1 || p.tcp.getSequenceNumber()!=PRE_SEQUENCENUMBER) { //过滤重复包
				PRE_SEQUENCENUMBER = p.tcp.getSequenceNumber();
				p.data = new byte[dataLen];
				buf.get(p.data);
			}else {
				buf.skip(dataLen);
			}
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

	@Override
	public String toString() {
		return header + " - " + ethernet + " - " + ip + " - " + tcp + "\n" + data;
	}
}
