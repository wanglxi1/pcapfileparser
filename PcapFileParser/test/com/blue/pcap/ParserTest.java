package com.blue.pcap;

import java.io.File;

import junit.framework.TestCase;

import org.junit.Test;

import com.blue.pcap.filter.PacketFilterAdapter;
import com.blue.pcap.packet.Packet;

public class ParserTest extends TestCase {

	@Test
	public void test() throws Exception {
		PcapFileParser pfp = new PcapFileParser();
		pfp.addFilter(new PacketFilterAdapter() {
			@Override
			public void filter(PacketFilter filter, Packet p) {
				System.out.println(p);
			}
		});
		
		pfp.parser(new File("G:\\Download\\金山快盘\\资料\\_Research\\alchemy\\lhsg\\socket\\KEY.pcap"));
	}

}
