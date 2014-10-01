package com.axml.enddec;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Vector;


public interface BinaryXML {
	/**
	 * Set the input file which needs to be parsed
	 * @param filePath
	 */
	public void setInputPath(String filePath);
	
	/**
	 * parses the XML and saves the structure
	 */
	public void parseXML() throws UnsupportedEncodingException ;
	
	/**
	 * Exports the modified XML
	 * @param exportPath
	 */
	public void exportXML(String exportPath)  throws IOException;
	
	/**
	 * 
	 * @return the strings in the StringPool
	 */
	public Vector<String> getStringPool();
	
	/**
	 * Changes the string in the string pool at the speficed position
	 * @param position
	 * @param newString
	 */
	public void changeString(int position, String newString);
	
	/**
	 * Returns permissions from the XML file
	 * @return
	 */
	public Vector<String> getPermisions();
	
	/**
	 * 
	 * @return the position in the string pool of the app name
	 */
	public int getAppName();
	
	/**
	 * 
	 * @return the position in the string pool of the package name
	 */
	public int getPackageName();
	
	/**
	 * 
	 * @return
	 */
	public int getActivityName();
	
	public int getVersion();
	
}
