package com.ibm.security.util;

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class SysUtil {
	

	Properties props;
	Set<Object> keys;
	Set<String> keyz;
	
	public SysUtil() {
		props = System.getProperties();
		keys = props.keySet();
		keyz = new HashSet<String>();
		for (Object object : keys) {
			keyz.add(object.toString());
		}
	}

	
	public void reloadProperties() {
				
	}
	
	public static void main(String[] args) {
		
		SysUtil sysUtil = new SysUtil();
//		sysUtil.printInfo();
		System.out.println(sysUtil.getOS());
	
		
	}
	
	public Set<String> getPropertyKeys() {
		return keyz;
		
	}
	
	public void printInfo() {
		for (String key : keyz) {
			
			System.out.println(key + " = " + props.get(key));
		}

	}
	
	public void logInfo() {
		for (String key : keyz) {
			Logger.logToAllLevels(key + " = " + props.get(key));
		}
		
	}
	
	public String getOS() {
		return props.get("os.name").toString();
	}
	
	public String getSystemProperty(String key) {
		return props.getProperty(key);
		
	}

}
