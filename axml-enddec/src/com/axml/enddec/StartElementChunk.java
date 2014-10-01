package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;


public class StartElementChunk extends Chunk{
	public int chunkSize;
	public int lineNumber;
	public int comment;
	
	public int ns;
	public int name;
	public int attributeStart;
	public int attributeSize;
	public int attributeCount;
	public int idIndex;
	public int classIndex;
	public int styleIndex;
	
	public LinkedList<AttributeChunk> attr= new LinkedList<AttributeChunk>();
	public EndElementChunk endElement = new EndElementChunk();
	
	
	@Override
	public int getChunkType() {
		return RES_XML_START_ELEMENT_TYPE;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 16;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);
		writeUint32(output, lineNumber);		
		writeUint32(output, comment);	
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		int size=4+4+2+2+2+2+2+2;
		for(AttributeChunk e : attr) {
			size+=e.getSize();
		}
		return getHeaderSize()+size;
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		writeUint32(output, ns);
		writeUint32(output, name);
		writeUint16(output, this.attributeStart);		
		writeUint16(output, this.attributeSize);
		writeUint16(output, this.attributeCount);
		writeUint16(output, this.idIndex);
		writeUint16(output, this.classIndex);
		writeUint16(output, this.styleIndex);
		for(AttributeChunk e : attr) {
			e.write(output);
		}
	}

}
