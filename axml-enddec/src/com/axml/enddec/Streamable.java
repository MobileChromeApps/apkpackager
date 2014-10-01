package com.axml.enddec;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

/**
 * Represents any object which can be written to a resource archive file.
 * 
 * The only requirements on Streamables are that they have a predictable
 * size in bytes, and that they can write themselves to an OutputStream.
 * 
 * @author iclelland
 *
 */
public abstract class Streamable {
	
	/* Size is a cached property. Parent objects can call getSize()
	 * on their children in order to construct their own headers.
	 * This method deals with the caching; subclasses should implement
	 * computeSize() to provide the actual calculation.
	 */
    protected Integer size = null;
    public int getSize() throws UnsupportedEncodingException {
        if (size == null) {
            size = computeSize();
        }
        return size;
    }
    public abstract int computeSize() throws UnsupportedEncodingException;
    
    /**
     * Write the object to the output stream.
     * @param output
     * @throws IOException
     */
	public abstract void write(OutputStream output) throws IOException;

	/* These are utility methods to write structured data */
	
	/**
	 * Write a single int as an unsigned 8-bit field
	 * @param output
	 * @param i
	 * @throws IOException
	 */
	protected void writeUint8(OutputStream output, int i) throws IOException {
		output.write((byte)(i%256));
	}

	/**
	 * Write a single int as an unsigned 16-bit field
	 * @param output
	 * @param i
	 * @throws IOException
	 */
	protected void writeUint16(OutputStream output, int i) throws IOException {
		output.write((byte)(i%256));
		output.write((byte)(i/256));
	}

	/**
	 * Write a single int as an unsigned 32-bit field
	 * @param output
	 * @param i
	 * @throws IOException
	 */
	protected void writeUint32(OutputStream output, int i) throws IOException {
		output.write((byte)(i%256));
		output.write((byte)((i>>8)%256));
		output.write((byte)((i>>16)%256));
		output.write((byte)(i>>24));
	}
	
	protected void writeUint8Buffer(OutputStream output, byte[] buffer) throws IOException {
		for(int i=0;i<buffer.length;i++)this.writeUint8(output, buffer[i]);
	}
	
	public int readUint32(byte[] buf, int i) {
		return (buf[i]&0xFF)+((buf[i+1]&0xFF)<<8)+((buf[i+2]&0xFF)<<16)+((buf[i+3]&0xFF)<<24);
	}

	public int readUint16(byte[] buf, int i) {
		return (buf[i]&0xFF)+((buf[i+1]&0xFF)<<8);
	}

	public int readUint8(byte[] buf, int i) {
		return (buf[i]&0xFF);
	}
	
	/**
	 * Write a single String as a padded UTF-16 string. The field is padded to
	 * bufferSize *characters*, which is (bufferSize * 2) *bytes*.
	 * 
	 * (Yes, this implies UCS-2 encoding).
	 * TODO: Verify aapt behaviour in the presence of non-BMP data
	 * 
	 * @param output
	 * @param string
	 * @param bufferSize
	 * @throws IOException
	 */
	protected void writePaddedUTF16(OutputStream output, String string, int bufferSize) throws IOException {
		byte[] buffer = new byte[bufferSize*2];
		for (int i=0; i < bufferSize *2; ++i) {
			buffer[i] = 0;
		}
		byte[] strBytes = string.getBytes("UTF-16LE");
		for (int i=0, n=strBytes.length; i < n; ++i) {
			buffer[i] = strBytes[i];
		}
		output.write(buffer);
	}
}
