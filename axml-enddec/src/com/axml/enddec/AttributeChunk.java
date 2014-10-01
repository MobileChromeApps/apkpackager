package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;


public class AttributeChunk extends Chunk{

	public int ns;
	public int name;
	public int rawValue;
	public int size;
	public int dataType;
	public int data;
	
	@Override
	public int getChunkType() {
		return 0;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 0;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return 20;
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeUint32(output, this.ns);		
		writeUint32(output, this.name);
		writeUint32(output, this.rawValue);		
		writeUint16(output, this.size);		
		writeUint8(output, 0);		
		writeUint8(output, this.dataType);
		writeUint32(output, this.data);		
	}

}
