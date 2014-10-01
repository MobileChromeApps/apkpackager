package com.axml.enddec;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;
import java.util.Vector;


public class BinaryXMLParser implements BinaryXML{
	private XMLChunk xml;
	private byte[] buf;
	public BinaryXMLParser(String filePath) throws IOException {
		FileInputStream is = new FileInputStream(filePath);
		
		xml = new XMLChunk();
		
		buf = new byte[10240];
		is.read(buf);
		is.close();
	}
	
	@Override
	public void parseXML() throws UnsupportedEncodingException {
		parseXML(buf , 0 , xml);		
		
	}
	
	@Override
	public void exportXML(String exportPath) throws IOException {
		OutputStream output;
		if(!exportPath.equals("")) {
			output= new FileOutputStream(exportPath);
		} else {
			output= new FileOutputStream("../../../work/cmp/output.xml");
		}
		
		xml.write(output);
		
	}
	
	private void parseXML(byte[] buf, int start, XMLChunk xml) throws UnsupportedEncodingException {
		xml.setSize(xml.readUint32(buf, start+4));
		//System.out.println(xml.readUint32(buf, start+4));
		parseStringPool(buf, start+xml.getHeaderSize(), xml);
	}

	private void parseStringPool(byte[] buf, int start, XMLChunk xml) throws UnsupportedEncodingException {
		int i=start;
		i+=4;
		int chunkSize= xml.readUint32(buf, i);
		i+=4;
		int stringCount= xml.readUint32(buf, i);
		i+=4;
		//int styleCount= xml.readUint32(buf, i);
		i+=4;
		//int flags= xml.readUint32(buf, i);
		i+=4;
		int stringsStart= xml.readUint32(buf, i);
		i+=4;
		//int stylesStart= xml.readUint32(buf, i);
		i+=4;
		//System.out.println("StringPool chunk size "+chunkSize);
		//System.out.println("String count "+stringCount);
		//System.out.println("strings start "+stringsStart);
		int[] stringOffset = new int[stringCount+1];
		for(int j=0;j<stringCount;j++) {
			stringOffset[j]=xml.readUint32(buf, i);
			i+=4;
		}
		stringOffset[stringCount]=chunkSize-stringsStart;

		for(int j=0;j<stringCount;j++) {
			String temp="";
			int len=stringOffset[j+1]-stringOffset[j];
			int ll= xml.readUint16(buf, i);
			byte[] subbuf=new byte[ll];
			for(int p=0;p<ll;p++)subbuf[p]=(byte)xml.readUint16(buf, i+2+2*p);
			i+=len;
			temp=new String(subbuf, "UTF-8");
			xml.sp.addString(temp);
			//System.out.println(j+" "+temp+" "+temp.length());
		}
		
		parseXMLResourceMap(buf, i, xml);
	}

	private void parseXMLResourceMap(byte[] buf, int i, XMLChunk xml) {
		i+=4;
		int chunkSize=xml.readUint32(buf, i);
		int refSize=(chunkSize-8)/4;
		int[] ref=new int[refSize];
		xml.resMap.setRefSize(refSize);
		i+=4;
		//System.out.println("ref size "+refSize);
		for(int j=0;j<refSize;j++) {
			ref[j]=xml.readUint32(buf, i);
			xml.resMap.ref[j]=ref[j];
			i+=4;
			//System.out.println("ref "+j+" "+ref[j]);
		}
		
		parseXMLStartNamespace(buf,i,xml);
	}

	private void parseXMLStartNamespace(byte[] buf, int i, XMLChunk xml) {
		i+=8;
		xml.startNamespaceChunk.line_number=xml.readUint32(buf, i);i+=4;
		xml.startNamespaceChunk.comment=xml.readUint32(buf, i);i+=4;
		xml.startNamespaceChunk.prefix=xml.readUint32(buf, i);i+=4;
		xml.startNamespaceChunk.uri=xml.readUint32(buf, i);i+=4;
		
		//System.out.println(xml.sp.getStrings().get(xml.startNamespaceChunk.uri));
		//System.out.println(xml.sp.getStrings().get(xml.startNamespaceChunk.prefix));
		
		parseXMLStart(buf,i,xml);
	}

	private  void parseXMLStart(byte[] buf, int i, XMLChunk xml) {
		LinkedList<Integer> openedTags=new LinkedList<Integer>();
		int index=0;
		do 
		{
			if(xml.readUint16(buf, i)==Chunk.RES_XML_START_ELEMENT_TYPE) {
				i+=4;
				StartElementChunk ne=new StartElementChunk();
				ne.chunkSize=xml.readUint32(buf, i);i+=4;
				ne.lineNumber=xml.readUint32(buf, i);i+=4;
				ne.comment=xml.readUint32(buf, i);i+=4;
				ne.ns=xml.readUint32(buf, i);i+=4;
				ne.name=xml.readUint32(buf, i);i+=4;
				ne.attributeStart=xml.readUint16(buf, i);i+=2;
				ne.attributeSize=xml.readUint16(buf, i);i+=2;
				ne.attributeCount=xml.readUint16(buf, i);i+=2;
				ne.idIndex=xml.readUint16(buf, i);i+=2;
				ne.classIndex=xml.readUint16(buf, i);i+=2;
				ne.styleIndex=xml.readUint16(buf, i);i+=2;
				//System.out.println("startTag "+xml.sp.getStrings().get(ne.name));
				for(int j=0;j<ne.attributeCount;j++) {
					AttributeChunk ac=new AttributeChunk();
					ac.ns=xml.readUint32(buf, i);i+=4;
					ac.name=xml.readUint32(buf, i);i+=4;
					ac.rawValue=xml.readUint32(buf, i);i+=4;
					ac.size=xml.readUint16(buf, i);i+=2;
					i+=1;
					ac.dataType=xml.readUint8(buf, i);i+=1;
					ac.data=xml.readUint32(buf, i);i+=4;
					ne.attr.add(ac);
					/*
					if(ac.rawValue!=-1)
						System.out.println("attr "+j+" "+xml.sp.getStrings().get(ac.name)+" "+xml.sp.getStrings().get(ac.rawValue));
					else
						System.out.println("attr "+j+" "+xml.sp.getStrings().get(ac.name));*/
				}
				openedTags.add(index);
				xml.order.add("start "+index);
				index++;
				xml.element.add(ne);
			} else if(xml.readUint16(buf, i)==Chunk.RES_XML_END_ELEMENT_TYPE) {
				i+=4;
				int temp=openedTags.getLast();
				openedTags.removeLast();
				EndElementChunk ee = new EndElementChunk();
				ee.chunkSize=xml.readUint32(buf, i);i+=4;
				ee.lineNumber=xml.readUint32(buf, i);i+=4;
				ee.comment=xml.readUint32(buf, i);i+=4;
				ee.ns=xml.readUint32(buf, i);i+=4;
				ee.name=xml.readUint32(buf, i);i+=4;
				xml.element.get(temp).endElement=ee;
				xml.order.add("end "+temp);
				
				//System.out.println("endTag "+xml.sp.getStrings().get(ee.name));
			}
		}while(openedTags.isEmpty()==false);
		parseXMLEndNamespace(buf,i,xml);
	}

	private void parseXMLEndNamespace(byte[] buf, int i, XMLChunk xml) {
		i+=8;
		xml.endNamespaceChunk.line_number=xml.readUint32(buf, i);i+=4;
		xml.endNamespaceChunk.comment=xml.readUint32(buf, i);i+=4;
		xml.endNamespaceChunk.prefix=xml.readUint32(buf, i);i+=4;
		xml.endNamespaceChunk.uri=xml.readUint32(buf, i);i+=4;
		
		//System.out.println("end xml namespace: "+xml.sp.getStrings().get(xml.endNamespaceChunk.prefix));
	}

	@Override
	public void setInputPath(String filePath) {
		
	}

	@Override
	public Vector<String> getStringPool() {
		return this.xml.sp.getStrings();
	}

	@Override
	public void changeString(int position, String newString) {
		this.xml.sp.getStrings().set(position, newString);
		
	}

	private String getString(int index) {
		return this.xml.sp.getStrings().get(index);
	}
	
	@Override
	public Vector<String> getPermisions() {
		Vector<String> perm = new Vector<String>();
		for(StartElementChunk el : this.xml.element) {
			if(getString(el.name).equals("uses-permission")) {
				for(AttributeChunk attr : el.attr) {
					if(getString(attr.name).equals("name")) {
						perm.add(getString(attr.rawValue));
					}
				}
			}
		}
		return perm;
	}

	private int getAttributeValue(String tag, String attrbute) {
		for(StartElementChunk el : this.xml.element) {
			if(getString(el.name).equals(tag)) {
				for(AttributeChunk attr : el.attr) {
					if(getString(attr.name).equals(attrbute))
						return attr.data;
				}
				break;
			}
		}
		return 0;
		
	}
	
	@Override
	public int getActivityName() {
		return this.getAttributeValue("application", "label");
	}

	@Override
	public int getPackageName() {
		return this.getAttributeValue("manifest", "package");
	}

	@Override
	public int getAppName() {
		return this.getAttributeValue("activity", "label");
	}
	
	@Override
	public int getVersion() {
		return this.getAttributeValue("manifest", "versionName");
	}

}
