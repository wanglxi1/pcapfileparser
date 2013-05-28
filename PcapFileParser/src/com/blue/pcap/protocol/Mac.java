package com.blue.pcap.protocol;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

public class Mac {
	byte[] bs;
	
	public static Mac valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		Mac m = new Mac();
		m.bs = new byte[6];
		buf.get(m.bs);
		return m;
	}

	@Override
	public String toString() {
		String s = "";
		for(byte b: bs) {
			s += Integer.toHexString(b & 0xFF) + ":";
		}
		s.substring(0, s.length()-2);
		return s;
	}
}
