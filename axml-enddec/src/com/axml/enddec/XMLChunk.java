package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;


public class XMLChunk extends Chunk{
	int type;
	int header_size;
	int chunk_size;
	
	public StringPool sp = new StringPool();
	public XMLResourceMap resMap = new XMLResourceMap();
	public startNC startNamespaceChunk= new startNC();
	public endNC endNamespaceChunk= new endNC();
	public LinkedList<StartElementChunk> element = new LinkedList<StartElementChunk>();
	public LinkedList<String> order = new LinkedList<String>();
	
	@Override
	public int getChunkType() {
		return RES_XML_TYPE;
	}
	
	public void setSize(int size) {
		this.chunk_size=size;
	}
	
	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 0x0008;
	}
	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);	
	}
	
	private int getElementSize() throws UnsupportedEncodingException {
		int sum=0;
		for(StartElementChunk el : element) {
			sum+= el.getSize()+el.endElement.getSize();
		}
		return sum;
	}
	
	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return this.getHeaderSize()+sp.getSize()+resMap.getSize()+this.startNamespaceChunk.getSize()
				+getElementSize()+this.endNamespaceChunk.getSize();
	}
	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		sp.write(output);
		resMap.write(output);
		startNamespaceChunk.write(output);
		for(String cmd : order) {
			String[] split= cmd.split(" ");
			StartElementChunk element = this.element.get(new Integer(split[1]));
			if(split[0].equals("start")) {
				element.write(output);
			} else {
				element.endElement.write(output);
			}
		}
		endNamespaceChunk.write(output);
	}
	
}
