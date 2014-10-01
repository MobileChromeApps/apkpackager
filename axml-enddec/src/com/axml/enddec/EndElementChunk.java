package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;


public class EndElementChunk extends Chunk{

	public int chunkSize;
	public int lineNumber;
	public int comment;
	public int ns;
	public int name;
	
	@Override
	public int getChunkType() {
		return RES_XML_END_ELEMENT_TYPE;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 16;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);
		writeUint32(output, this.lineNumber);
		writeUint32(output, this.comment);		
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return 24;
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		writeUint32(output, this.ns);
		writeUint32(output, this.name);		
	}

}
