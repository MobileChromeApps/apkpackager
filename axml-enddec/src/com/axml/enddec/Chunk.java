package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

/**
 * Represents an object with a resource archive.
 * 
 * All Chunk types have a similar structure: A header followed by a
 * payload. The header is in two parts: a common base header, which
 * includes the chunk type, the total header size, and the total
 * chunk size (including header and payload); and the extended header
 * which varies by chunk type.
 * 
 * @author iclelland
 *
 */
public abstract class Chunk extends Streamable {
	// Top-level chunk types
	public static final int RES_NULL_TYPE               = 0x0000;
	public static final int RES_STRING_POOL_TYPE        = 0x0001;
	public static final int RES_TABLE_TYPE              = 0x0002;
	public static final int RES_XML_TYPE                = 0x0003;

	// Chunk types in RES_XML_TYPE
	public static final int RES_XML_FIRST_CHUNK_TYPE    = 0x0100;
	public static final int RES_XML_START_NAMESPACE_TYPE= 0x0100;
	public static final int RES_XML_END_NAMESPACE_TYPE  = 0x0101;
	public static final int RES_XML_START_ELEMENT_TYPE  = 0x0102;
	public static final int RES_XML_END_ELEMENT_TYPE    = 0x0103;
	public static final int RES_XML_CDATA_TYPE          = 0x0104;
	public static final int RES_XML_LAST_CHUNK_TYPE     = 0x017f;
	public static final int RES_XML_RESOURCE_MAP_TYPE   = 0x0180;

	// Chunk types in RES_TABLE_TYPE
	public static final int RES_TABLE_PACKAGE_TYPE      = 0x0200;
	public static final int RES_TABLE_TYPE_TYPE         = 0x0201;
	public static final int RES_TABLE_TYPE_SPEC_TYPE    = 0x0202;

	public abstract int getChunkType();
	public abstract int getHeaderSize() throws UnsupportedEncodingException;
	public abstract void writeHeader(OutputStream output) throws IOException;

	protected void writeBaseHeader(OutputStream output) throws IOException {
		writeUint16(output, getChunkType());
		writeUint16(output, getHeaderSize());
		writeUint32(output, getSize());
	}

}
