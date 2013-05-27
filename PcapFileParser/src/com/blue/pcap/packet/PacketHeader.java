package com.blue.pcap.packet;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

public class PacketHeader {
	TimeVal ts; 	/* time stamp */
	int caplen; 	/* length of portion present */
	int len; 		/* length this packet (off wire) */
	
	public int getCaplen() {
		return caplen;
	}

	public static PacketHeader valueOf(IoBuffer buf) {
		buf.order(ByteOrder.LITTLE_ENDIAN);
		PacketHeader ph = new PacketHeader();
		
		ph.ts = TimeVal.valueOf(buf);
		ph.caplen = buf.getInt();
		ph.len = buf.getInt();
		
		return ph;
	}

	@Override
	public String toString() {
		return ts + " -> " + len + "["+caplen+"]";
	}
	
}
