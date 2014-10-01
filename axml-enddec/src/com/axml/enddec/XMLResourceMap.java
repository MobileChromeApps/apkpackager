package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;


public class XMLResourceMap extends Chunk{

	public int[] ref;
	int refSize;
	
	public void setRefSize(int size) {
		refSize=size;
		ref=new int[size];
	}
	
	@Override
	public int getChunkType() {
		return RES_XML_RESOURCE_MAP_TYPE;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 0x08;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return refSize*4+getHeaderSize();
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		for(int i=0;i<refSize;i++) {
			writeUint32(output, ref[i]);			
		}
	}

}
