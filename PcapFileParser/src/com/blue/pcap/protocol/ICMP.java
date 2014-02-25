package com.blue.pcap.protocol;

import org.apache.mina.core.buffer.IoBuffer;

public class ICMP implements Protocol {
	private static int HEADER_LEN = 1+1+2+2+2;
	
	private ICMP_TYPE type;
	private int code;
	private int checksum;
	private int identifier;
	private int sequence;
	
	@Override
	public void valueOf(IoBuffer buf) {
		this.type = ICMP_TYPE.toType(buf.getUnsigned());
		this.code = buf.get();
		this.checksum = buf.getUnsignedShort();
		this.identifier = buf.getUnsignedShort();
		this.sequence = buf.getUnsignedShort();
	}
	
	
	@Override
	public int getHeaderLen() {
		return HEADER_LEN;
	}
	
	@Override
	public String toString() {
		return this.type.name() + ": " + this.identifier;
	}


	public ICMP_TYPE getType() {
		return type;
	}

	public int getCode() {
		return code;
	}

	public int getChecksum() {
		return checksum;
	}

	public int getIdentifier() {
		return identifier;
	}

	public int getSequence() {
		return sequence;
	}



	public enum ICMP_TYPE{
		EchoReply(0),
        DestUnreachable(3),
        SourceQuench(4),
        Redirect(5),
        EchoRequest(8),
        TimeExceeded(11),
        Traceroute(30),
        
        // this is used to represent a type code that we have not handled
        Other(-1);

        
        private int m_code;
        private ICMP_TYPE(int code) {
            m_code = code;
        }
        
        public int getCode() {
            return m_code;
        }
        
        public static ICMP_TYPE toType(int code) {
            for(ICMP_TYPE p : ICMP_TYPE.values()) {
                if (code == p.getCode()) {
                    return p;
                }
            }
            return Other;
        }
	}
}
