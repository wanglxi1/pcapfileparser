package com.blue.pcap.protocol;

import java.nio.ByteOrder;
import java.text.MessageFormat;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.util.StringUtil;

/**
 * Ethernet II, Src: Vmware_d1:c0:d9 (00:0c:29:d1:c0:d9), Dst: Vmware_c0:00:08 (00:50:56:c0:00:08)
 * 
 * @author BluE
 *
 */
public class Ethernet {
	public final static int LENGTH = 14;
	
	Mac destination;
	Mac source;
	int type; //Type: IP (0x0800)
	byte[] padding;
	
	public static Ethernet valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		Ethernet e = new Ethernet();
		e.destination = Mac.valueOf(buf);
		e.source = Mac.valueOf(buf);
		e.type = buf.getUnsignedShort();
		e.padding = null;
		return e;
	}

	public void setPadding(byte[] padding) {
		this.padding = padding;
	}

	@Override
	public String toString() {
		return MessageFormat.format("src:{0}, dest:{1}, type:{2} {3}", 
				source, destination, Integer.toHexString(type),
				padding==null? "": StringUtil.byte2HexString(padding)
			);
	}
}
