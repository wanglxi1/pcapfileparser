package com.blue.pcap;

import java.io.File;
import java.io.RandomAccessFile;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.apache.mina.core.buffer.IoBuffer;

import com.blue.pcap.filter.EmptyPacketFilter;
import com.blue.pcap.filter.PacketFilterAdapter;
import com.blue.pcap.filter.UniquencePacketFilter;
import com.blue.pcap.packet.Packet;

public class PcapFileParser {
	
	private List<PacketFilter> filters = new ArrayList<>();
	public void addFilter(PacketFilter f){
		filters.add(f);
	}
	
	public PcapFileParser(){
		this.addFilter(new EmptyPacketFilter());
		this.addFilter(new UniquencePacketFilter());
	}
	
	public void parser(File f) throws Exception{
		RandomAccessFile file = new RandomAccessFile(f, "r"); 
		FileChannel fileChannel = file.getChannel();
		
		IoBuffer readBuf = IoBuffer.allocate((int)fileChannel.size());
		fileChannel.read(readBuf.buf());
		readBuf.flip();
		
		this.parser(readBuf);
	}	
	
	public void parser(IoBuffer buf){
		FilterChain filterChain = new FilterChain();
		
		filterChain.init();
		
		PcapFileHeader.valueOf(buf);
		
		long i = 1;
		
		while(buf.hasRemaining()){
			Packet p = Packet.valueOf(buf);
			p.setIndex(i++);
			filterChain.start();
			filterChain.filter(null, p);
			filterChain.end();
		}
		
		filterChain.finish();
	}
	
	private class FilterChain extends PacketFilterAdapter{
		private Iterator<PacketFilter> iterator = null;
		@Override
		public void init() {
			for(PacketFilter f: filters){
				f.init();
			}
		}
		
		@Override
		public void start() {
			iterator = filters.iterator();
			
			for(PacketFilter f: filters){
				f.start();
			}
		}

		@Override
		public void filter(PacketFilter filter, Packet p) {
			if(iterator.hasNext()){
				iterator.next().filter(this, p);
			}
		}
		
		@Override
		public void end() {
			for(PacketFilter f: filters){
				f.end();
			}
		}

		@Override
		public void finish() {
			iterator = null;
			
			for(PacketFilter f: filters){
				f.finish();
			}
		}
	}	
}
