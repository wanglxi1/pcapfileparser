package com.blue.pcap.protocol;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.protocol.part.TcpFlags;


/**
 * Transmission Control Protocol, Src Port: paycash-wbp (8129), Dst Port: gpsd (2947), Seq: 0, Ack: 1, Len: 0
 * 
 * @author BluE
 *
 */
public class TCP implements Protocol {
	int sourcePort;
	int destinationPort;
	long sequenceNumber;
	long acknowledgementNumber;
	int headerLen;
	TcpFlags flags;
	int windowSize;
	int checksum;
	
	byte[] options;
	
	@Override
	public void valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		TCP i = this;
		
		i.sourcePort = buf.getUnsignedShort();
		i.destinationPort = buf.getUnsignedShort();
		i.sequenceNumber = buf.getUnsignedInt();
		i.acknowledgementNumber = buf.getUnsignedInt();
		
		i.flags = TcpFlags.valueOf(buf);
		i.headerLen = i.flags.getHeaderLen() * 4;
		
		i.windowSize = buf.getUnsignedShort();
		i.checksum = buf.getUnsignedShort();
		
		buf.getUnsignedShort();
		
		i.options = new byte[i.headerLen - 20];
		if(i.options.length > 0) {
			buf.get(i.options);
		}
	}

	public int getSourcePort() {
		return sourcePort;
	}

	public int getDestinationPort() {
		return destinationPort;
	}

	public long getSequenceNumber() {
		return sequenceNumber;
	}

	public long getAcknowledgementNumber() {
		return acknowledgementNumber;
	}

	@Override
	public int getHeaderLen() {
		return headerLen;
	}

	public TcpFlags getFlags() {
		return flags;
	}

	public int getWindowSize() {
		return windowSize;
	}

	public int getChecksum() {
		return checksum;
	}

	public byte[] getOptions() {
		return options;
	}
}
