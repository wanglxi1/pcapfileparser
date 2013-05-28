package com.blue.pcap.protocol;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

/**
 * Internet Protocol Version 4, Src: 10.0.0.3 (10.0.0.3), Dst: 10.0.0.1 (10.0.0.1)
 * 
 * @author BluE
 *
 */
public class Ip {
	int version;
	int headerLen;
	byte differentiatedServicesField;	//Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00: Not-ECT (Not ECN-Capable Transport))
	int totalLen;
	int identification;
	byte flags;	//Flags: 0x02 (Don't Fragment)
	byte fragmentOffset;
	byte timeToLive;
	byte protocol;	//Protocol: TCP (6)
	int headerChecksum;
	IpAddress source;
	IpAddress destination;
	
	public static Ip valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		Ip i = new Ip();
		
		byte b = buf.get();
		i.version = b >> 4;
		i.headerLen = (b & 0x0F) * 4;
		
		i.differentiatedServicesField = buf.get();
		i.totalLen = buf.getUnsignedShort();
		i.identification = buf.getUnsignedShort();
		i.flags = buf.get();
		i.fragmentOffset = buf.get();
		i.timeToLive = buf.get();
		i.protocol = buf.get();
		i.headerChecksum = buf.getUnsignedShort();
		
		i.source = IpAddress.valueOf(buf);
		i.destination = IpAddress.valueOf(buf);
		
		return i;
	}
	

	public int getVersion() {
		return version;
	}

	public int getHeaderLen() {
		return headerLen;
	}

	public byte getDifferentiatedServicesField() {
		return differentiatedServicesField;
	}

	public int getTotalLen() {
		return totalLen;
	}

	public int getIdentification() {
		return identification;
	}

	public byte getFlags() {
		return flags;
	}

	public byte getFragmentOffset() {
		return fragmentOffset;
	}

	public byte getTimeToLive() {
		return timeToLive;
	}

	public byte getProtocol() {
		return protocol;
	}

	public int getHeaderChecksum() {
		return headerChecksum;
	}

	public IpAddress getSource() {
		return source;
	}

	public IpAddress getDestination() {
		return destination;
	}
}
