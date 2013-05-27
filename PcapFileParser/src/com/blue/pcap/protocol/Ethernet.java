package com.blue.pcap.protocol;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

/**
 * Ethernet II, Src: Vmware_d1:c0:d9 (00:0c:29:d1:c0:d9), Dst: Vmware_c0:00:08 (00:50:56:c0:00:08)
 * 
 * @author BluE
 *
 */
public class Ethernet {
	Mac destination;
	Mac source;
	int type; //Type: IP (0x0800)
	
	public static Ethernet valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		Ethernet e = new Ethernet();
		e.destination = Mac.valueOf(buf);
		e.source = Mac.valueOf(buf);
		e.type = buf.getUnsignedShort();
		return e;
	}

	@Override
	public String toString() {
		return "src:"+source + ", dest:" +destination + ", type:"+Integer.toHexString(type);
	}
}
