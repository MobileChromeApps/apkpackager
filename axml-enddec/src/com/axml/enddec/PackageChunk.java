package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

public class PackageChunk extends Chunk{

	public int size;
	public int id;
	public byte[] name;
	public int typeStrings;
	public int lastPublicType;
	public int keyStrings;
	public int lastPublicKey;
	public byte[] body;
	public String nameString;
	
	@Override
	public int getChunkType() {
		// TODO Auto-generated method stub
		return RES_TABLE_PACKAGE_TYPE;
	}

	@Override
	public int getHeaderSize() throws UnsupportedEncodingException {
		return 0x011c;
	}

	@Override
	public void writeHeader(OutputStream output) throws IOException {
		writeBaseHeader(output);
		this.writeUint32(output, id);
		//this.writeUint8Buffer(output, name);
		this.writeString(output, nameString);
		
		this.writeUint32(output, typeStrings);
		this.writeUint32(output, lastPublicType);
		this.writeUint32(output, keyStrings);
		this.writeUint32(output, lastPublicKey);
	}

	@Override
	public int computeSize() throws UnsupportedEncodingException {
		return getHeaderSize() + body.length;
	}

	@Override
	public void write(OutputStream output) throws IOException {
		writeHeader(output);
		this.writeUint8Buffer(output, body);
	}
	
    void writeString(OutputStream output, String string) throws IOException {
        byte[] encString;
        encString = string.getBytes("UTF-8");
        for(int p=0;p<encString.length;p++) {
          writeUint8(output,encString[p]);
          writeUint8(output,0);
        }
        for(int i=0;i<(0x011c-(encString.length*2)-12-16);i++)
          writeUint8(output, 0);
    }
	

}
