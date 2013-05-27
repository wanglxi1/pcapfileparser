package com.blue.pcap.protocol;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.util.StringUtil;

public class IpAddress {
	byte[] bs;
	
	public static IpAddress valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		IpAddress i = new IpAddress();
		i.bs = new byte[4];
		buf.get(i.bs);
		return i;
	}

	@Override
	public String toString() {
		String[] s = new String[bs.length];
		for(int i=0,ilen=bs.length; i<ilen; i++) {
			s[i] = String.valueOf(bs[i]);
		}
		return StringUtil.join(s, ".");
	}
}
