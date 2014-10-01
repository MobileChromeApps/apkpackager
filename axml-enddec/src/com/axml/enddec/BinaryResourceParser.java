package com.axml.enddec;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.Arrays;

public class BinaryResourceParser implements BinaryResource{

	private TableChunk table;
	private byte[] buf;
	
	public BinaryResourceParser(String filePath) throws IOException {
		FileInputStream is = new FileInputStream(filePath);
		
		table = new TableChunk();
		
		buf = new byte[200000];
		is.read(buf);
		is.close();
	}
	
	@Override
	public void parseResource() throws UnsupportedEncodingException {
		parseResource(0);
	}

	private void parseResource(int i) throws UnsupportedEncodingException {
   /*
    00000000 02 00       // type [TABLE]
    00000002 0c 00       // header size
    00000004 64 04 00 00 // chunk size
    --------------------

    00000008 01 00 00 00 // package count		
   */
		i+=4;
		this.table.size = this.table.readUint32(buf, i);
		i+=4;
		this.table.packageCount = this.table.readUint32(buf, i);
		i+=4;
		int spSize = this.table.readUint32(buf, i+4);
		this.table.sp = Arrays.copyOfRange(buf, i, i+spSize);
		i+=spSize;
		i+=2;
		int headerSize = this.table.readUint16(buf, i);
		i+=2;
		int chunkSize = this.table.readUint32(buf, i);
		i+=4;
		this.table.pkg.id = this.table.readUint32(buf, i);
		i+=4;
		//
		int nameSize = headerSize - 12-16;
		this.table.pkg.name = Arrays.copyOfRange(buf, i, i+nameSize);
		i+=nameSize;
		this.table.pkg.nameString = new String(this.table.pkg.name, "UTF-8");
		
		this.table.pkg.typeStrings = this.table.readUint32(buf, i);
		i+=4;
		this.table.pkg.lastPublicType = this.table.readUint32(buf, i);
		i+=4;
		this.table.pkg.keyStrings = this.table.readUint32(buf, i);
		i+=4;
		this.table.pkg.lastPublicKey = this.table.readUint32(buf, i);
		i+=4;
		this.table.pkg.body = Arrays.copyOfRange(buf, i, i + chunkSize - headerSize);
		
	}

	@Override
	public void exportResource(String exportPath) throws IOException {
		OutputStream output;
		if(!exportPath.equals("")) {
			output= new FileOutputStream(exportPath);
		} else {
			output= new FileOutputStream("../../../work/cmp/output.xml");
		}
		
		table.write(output);		
	}
	
	@Override
	public void changePackageName(String newName) {
		this.table.pkg.nameString = newName;
	}

}
