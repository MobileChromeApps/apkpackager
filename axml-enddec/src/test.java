import java.io.IOException;
import java.util.Vector;

import com.axml.enddec.BinaryResourceParser;
import com.axml.enddec.BinaryXMLParser;

class test{
	public static void main(String[] args) throws IOException {
		/*BinaryXMLParser parser = new BinaryXMLParser(args[0]);
		parser.parseXML();
		printString(parser.getStringPool());
		System.out.println("-----------------");
		//printString(parser.getPermisions());
		System.out.println(parser.getAppName());
		System.out.println(parser.getActivityName());
		System.out.println(parser.getPackageName());
		System.out.println(parser.getVersion());
		parser.exportXML("");*/
		BinaryResourceParser parser= new BinaryResourceParser(args[0]);
		parser.parseResource();
		parser.changePackageName("org.chromium.cadt.template");
		parser.exportResource(args[1]);
	}

	static void printString(Vector<String> vec) {
		int poz=0;
		for(String st : vec) {
			System.out.println(poz+" "+st);
			++poz;
		}
	}
	
}