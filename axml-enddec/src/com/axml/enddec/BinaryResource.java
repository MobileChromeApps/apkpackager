package com.axml.enddec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public interface BinaryResource {

	public void parseResource() throws UnsupportedEncodingException;
	
	public void changePackageName(String newName);
	
	public void exportResource(String exportPath) throws IOException;
	
}
