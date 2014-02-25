package com.blue.pcap.protocol.part;

import java.nio.ByteOrder;

import org.apache.mina.core.buffer.IoBuffer;

/**
 * 
 * Flags: 0x12 (SYN, ACK)
 * 000. .... .... = Reserved: Not set
 * ...0 .... .... = Nonce: Not set
 * .... 0... .... = Congestion Window Reduced (CWR): Not set
 * .... .0.. .... = ECN-Echo: Not set
 * .... ..0. .... = Urgent: Not set
 * .... ...1 .... = Acknowledgement: Set
 * .... .... 0... = Push: Not set
 * .... .... .0.. = Reset: Not set
 * .... .... ..1. = Syn: Set
 * .... .... ...0 = Fin: Not set
 * 
 * @author BluE
 *
 */
public class TcpFlags {
	int headerLen;
	boolean reserved;
	boolean nonce;
	boolean cwr;
	boolean ecnEcho;
	boolean urgent;
	boolean ack;
	boolean push;
	boolean reset;
	boolean syn;
	boolean fin;
	
	
	
	public int getHeaderLen() {
		return headerLen;
	}

	public boolean isReserved() {
		return reserved;
	}

	public boolean isNonce() {
		return nonce;
	}

	public boolean isCwr() {
		return cwr;
	}

	public boolean isEcnEcho() {
		return ecnEcho;
	}

	public boolean isUrgent() {
		return urgent;
	}

	public boolean isAck() {
		return ack;
	}

	public boolean isPush() {
		return push;
	}

	public boolean isReset() {
		return reset;
	}

	public boolean isSyn() {
		return syn;
	}

	public boolean isFin() {
		return fin;
	}

	public static boolean checkBit(int b, int bitIndex) {
		int checkNum = 1 << bitIndex;
		return (b & checkNum) != 0;
	}
	
	public static TcpFlags valueOf(IoBuffer buf) {
		buf.order(ByteOrder.BIG_ENDIAN);
		
		TcpFlags i = new TcpFlags();
		int s = buf.getUnsignedShort();
		
		i.fin = checkBit(s, 0);
		i.syn = checkBit(s, 1);
		i.reset = checkBit(s, 2);
		i.push = checkBit(s, 3);
		i.ack = checkBit(s, 4);
		i.urgent = checkBit(s, 5);
		i.ecnEcho = checkBit(s, 6);
		i.cwr = checkBit(s, 7);
		i.nonce = checkBit(s, 8);
		i.reserved = checkBit(s, 9) || checkBit(s, 10) || checkBit(s, 11);
		
		i.headerLen = s >>> 12; 

		return i;
	}
}
