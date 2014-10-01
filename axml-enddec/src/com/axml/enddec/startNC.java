package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;


public class startNC extends Chunk{

	public int line_number;
	public int comment;
	public int prefix,uri;
	
	@Override
	public int getChunkType() {
		return RES_XML_START_NAMESPACE_TYPE;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 16;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);
		writeUint32(output, line_number);
		writeUint32(output, comment);
		
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return 0x18;
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		writeUint32(output, prefix);
		writeUint32(output, uri);
		
	}

}
