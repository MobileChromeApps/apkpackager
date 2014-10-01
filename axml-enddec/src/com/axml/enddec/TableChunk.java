package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

public class TableChunk extends Chunk {

	public int size;
	public byte[] sp;
	public int packageCount;
	public PackageChunk pkg = new PackageChunk();
	
	@Override
	public int getChunkType() {
		return RES_TABLE_TYPE;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 0x0c;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);
		
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return size;
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		this.writeUint32(output, packageCount);
		for (int i = 0; i<this.sp.length; i++) this.writeUint8(output, this.sp[i]);
		pkg.write(output);
	}

}
