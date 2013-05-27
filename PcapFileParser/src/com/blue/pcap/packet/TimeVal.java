package com.blue.pcap.packet;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.mina.core.buffer.IoBuffer;

public class TimeVal {
	public final static DateFormat DF = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
	
	long sec; /* seconds (XXX should be time_t) */
	long usec; /* and microseconds */
	
	public static TimeVal valueOf(IoBuffer buf) {
		TimeVal tv = new TimeVal();
		tv.sec = buf.getUnsignedInt();
		tv.usec = buf.getUnsignedInt();
		return tv;
	}

	@Override
	public String toString() {
		return DF.format(new Date(sec*1000))+"."+usec;
	}
}
