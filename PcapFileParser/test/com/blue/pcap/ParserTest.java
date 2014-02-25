package com.blue.pcap;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;

import com.blue.pcap.filter.PacketFilterAdapter;
import com.blue.pcap.packet.Packet;
import com.blue.pcap.protocol.ICMP;
import com.blue.pcap.protocol.Protocol;
import com.blue.pcap.util.StringUtil;

public class ParserTest extends TestCase {

	@Test
	public void test() throws Exception {
		
		PcapFileParser pfp = new PcapFileParser();
		pfp.addFilter(new PacketFilterAdapter() {
			@Override
			public void filter(PacketFilter filter, Packet p) {
				Protocol pr = p.getProtocol();
				if(pr instanceof ICMP) {
					ICMP icmp = (ICMP)pr;
					int id = icmp.getIdentifier();
					if(id == 49320) {
						System.out.printf("%s: %s \n", p.getIndex(), StringUtil.byte2HexString(p.getData()));
					}
				}
			}
		});
		
		pfp.parser(new File("E:\\DesktopBak\\test.pcap"));
	}

}
