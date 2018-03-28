package com.ibm.security.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.InputMismatchException;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import sun.util.locale.StringTokenIterator;

public class PropertiesManager {

	private static Properties sysProps;
	private static Properties appProps;
	private static SysUtil sysUtil = new SysUtil();
	

	private static com.ibm.security.util.Properties[] propsArray;
	
	private final static String _delim_ = "=";
	
	
	static {
		
		
		try {
			loadSysProperties();
			loadApplicationProperties();
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			Logger.logToAllLevels(e.getMessage());
		}
		
	}
	


	
	private static void loadSysProperties() {
		Logger.logToAllLevels("Loading System Properties");
		if (sysProps == null) 
			sysProps = System.getProperties();
		
	}
	
	public static void loadApplicationProperties() throws IOException {
		Logger.debug("Inside method: " + PropertiesManager.class.getName()
				+ ".loadApplicationProperties()");
		
		if (propsArray != null) propsArray = null;
		
		// Add the various Properties files implementations
		propsArray = new com.ibm.security.util.Properties[] {
						new GlobalIBMw3idProperties()
						, new ActivationProperties()
						, new WebSEALProperties()
						, new IsamProperties()
						, new IsamFedProperties()
						, new F5Properties()
					  };
		 
		 if (appProps == null) appProps= new Properties();
		 
		for (com.ibm.security.util.Properties properties : propsArray) {
			Logger.logToAllLevels("Loading application properties from " + properties.getConfigFile());
			properties.loadApplicationProperties();
			Properties props = properties.getProperties();
			Set<Object> keys = props.keySet();
			for (Object object : keys) {
				appProps.put(object.toString(), props.getProperty(object.toString()));
			}
			
		}
	}
	
	public static TimeUnit parseTimeUnit(String timeUnitInString) {
		return TimeUnit.valueOf(timeUnitInString);
	}
	
	public static Properties getSystemProperties() {
		if (sysProps == null) loadSysProperties();
		return sysProps;
	}
	
	public static Properties getApplicationProperties() throws IOException {
		Logger.debug("Inside method: " + PropertiesManager.class.getName()
				+ ".getApplicationProperties()");
		if (appProps == null) {
			loadApplicationProperties();
		}
		return appProps;
	}
	
	public static String getApplicationProperty(String key) throws InputMismatchException {
		String propCheck = appProps.getProperty(key);
		if (propCheck == null) throw new InputMismatchException(key + " is not associated with a valid property value.");
		
		return propCheck;
	}

	private String toStringSystemProps() {
		StringBuilder sb = new StringBuilder();
		Set<Object> keys = sysProps.keySet();
		
		for (Object object : keys) {
			sb.append(object.toString() + " = " + sysProps.get(object) + "\n\r");
//			System.out.println(object.toString() + " = " + props.get(object));
		}
		
		return sb.toString();
	}
	
	public static String[] parseProps(String prop, String delim) {
		Logger.debug("Inside static method: " + PropertiesManager.class.getName()
				+ ".parseProps(String prop, String delim)");
		
		Logger.debug("Properties to parse: " + prop);
		Logger.debug("Delimieter to use: " + delim);
		
		StringTokenIterator st = new StringTokenIterator(prop, delim);
		ArrayList<String> parsedProp = new ArrayList<String>();
		do {
			parsedProp.add(st.current().toString());
			Logger.debug("Parsed value: " + st.current().toString());
			st.next();
		} while (!st.isDone());
		
		String[] parsedPropArray = new String[parsedProp.size()];
		
		return parsedProp.toArray(parsedPropArray);
		
	}
	

}
