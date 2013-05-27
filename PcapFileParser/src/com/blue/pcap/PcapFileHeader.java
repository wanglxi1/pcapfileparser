package com.blue.pcap;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

public class PcapFileHeader {
	int magic;  
    short version_major;  
    short version_minor;  
    int thiszone;     /* gmt to local correction */  
    int sigfigs;    /* accuracy of timestamps */  
    int snaplen;    /* max length saved portion of each pkt */  
    int linktype;   /* data link type (LINKTYPE_*) */

    public static PcapFileHeader valueOf(IoBuffer buf) {
    	PcapFileHeader vo = new PcapFileHeader();
    	
    	buf.order(ByteOrder.LITTLE_ENDIAN);
    	
    	vo.magic = buf.getInt();
    	vo.version_major = buf.getShort();
    	vo.version_minor = buf.getShort();
    	vo.thiszone = buf.getInt();
    	vo.sigfigs = buf.getInt();
    	vo.snaplen = buf.getInt();
    	vo.linktype = buf.getInt();
    	
    	return vo;
    }


	@Override
	public String toString() {
		StringBuffer sb = new StringBuffer();
		sb.append(Integer.toHexString(magic)).append(" ");
		sb.append(version_major).append(" ");
		sb.append(version_minor).append(" ");
		sb.append(thiszone).append(" ");
		sb.append(sigfigs).append(" ");
		sb.append(snaplen).append(" ");
		sb.append(linktype);
		return sb.toString();
	}
    
    
    
}
