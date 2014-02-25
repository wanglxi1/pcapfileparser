package com.blue.pcap.protocol;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.protocol.part.IpAddress;

/**
 * Internet Protocol Version 4, Src: 10.0.0.3 (10.0.0.3), Dst: 10.0.0.1 (10.0.0.1)
 * 
 * @author BluE
 *
 */
public class IP {
	int version;
	int headerLen;
	byte differentiatedServicesField;	//Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00: Not-ECT (Not ECN-Capable Transport))
	int totalLen;
	int identification;
	byte flags;	//Flags: 0x02 (Don't Fragment)
	byte fragmentOffset;
	byte timeToLive;
	ProtocolEnum protocol;	//Protocol: TCP (6)
	int headerChecksum;
	IpAddress source;
	IpAddress destination;
	private byte[] options;
	
	private final static int PURE_LEN = 1 + 1 + 2 + 2 + 1 + 1 + 1+ 1 + 2 + 4 + 4;
	
	public static IP valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		IP i = new IP();
		
		byte b = buf.get();
		i.version = b >> 4;
		i.headerLen = (b & 0x0F) * 4;
		
		i.differentiatedServicesField = buf.get();
		i.totalLen = buf.getUnsignedShort();
		i.identification = buf.getUnsignedShort();
		i.flags = buf.get();
		i.fragmentOffset = buf.get();
		i.timeToLive = buf.get();
		
		i.protocol = ProtocolEnum.toType(buf.getUnsigned());
		i.headerChecksum = buf.getUnsignedShort();
		
		i.source = IpAddress.valueOf(buf);
		i.destination = IpAddress.valueOf(buf);
		
		int optionLen = i.headerLen - PURE_LEN;
		i.options = new byte[optionLen];
		buf.get(i.options);
		
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

	public ProtocolEnum getProtocol() {
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
	
	public enum ProtocolEnum{
		ICMP(1),
		IGMP(2),
		TCP(6),
		UDP(17),
        
        // this is used to represent a type code that we have not handled
        Other(-1);

        
        private int m_code;
        private ProtocolEnum(int code) {
            m_code = code;
        }
        
        public int getCode() {
            return m_code;
        }
        
        public static ProtocolEnum toType(int code) {
            for(ProtocolEnum p : ProtocolEnum.values()) {
                if (code == p.getCode()) {
                    return p;
                }
            }
            return Other;
        }
	}
}
