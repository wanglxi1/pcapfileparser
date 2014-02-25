package com.blue.pcap.protocol;

import org.apache.mina.core.buffer.IoBuffer;

public interface Protocol {
	int getHeaderLen();
	void valueOf(IoBuffer buf);
}
