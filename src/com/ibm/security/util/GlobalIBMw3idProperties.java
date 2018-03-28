package com.ibm.security.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;
import java.util.Set;

public class GlobalIBMw3idProperties implements com.ibm.security.util.Properties {
	
	private final static String APPLICATION_PROPS_FILENAME = "w3id.properties";
	private final static String SYSTEM_PROPERTY_SHARED_CONFIG_DIR ="shared.config.dir";
	private String APPLICATION_PROPS_FILE_FQ;

	private static java.util.Properties appProps;
	

	private SysUtil sysUtil;
	
	public GlobalIBMw3idProperties() {
		Logger.debug("Inside contructor: " + getClass().getName()
				+ "()");
		sysUtil = new SysUtil();
		APPLICATION_PROPS_FILE_FQ = 
				sysUtil.getSystemProperty(SYSTEM_PROPERTY_SHARED_CONFIG_DIR) + APPLICATION_PROPS_FILENAME;
		
		if (sysUtil.getOS().equals("Mac OS X")) {
			APPLICATION_PROPS_FILE_FQ += ".rk";
		}
		
		Logger.logToAllLevels("Registered application properties file: " + APPLICATION_PROPS_FILE_FQ);
		appProps = new Properties();
				
	}
	
	
	@Override
	public void loadApplicationProperties() throws FileNotFoundException, IOException {
		Logger.debug("Inside method: " + getClass().getName()
				+ ".laodApplicationProperties()");
		Logger.logToAllLevels("Loading Application Properties from " + APPLICATION_PROPS_FILE_FQ);
		loadApplicationProperties(APPLICATION_PROPS_FILE_FQ, true);

	}

	@Override
	public void loadApplicationProperties(String file, boolean isFile) throws IOException {
		Logger.debug("Inside method: " + getClass().getName()
				+ ".loadApplicationProperties(String file, boolean isFile)");

		File f = new File(file);
		
		if (!isFile && f.isDirectory()) {
			String[] dirContents = f.list();
			for (String propFile : dirContents) {
				loadApplicationProperties(file + propFile, true);			
			}
		} else if (isFile && !f.getName().endsWith(".swp")) {
			Logger.debug("Loading application property file: " + file);
			BufferedReader bf = new BufferedReader(new FileReader(f));
			appProps.load(bf);
			bf.close();
			logKeys();
		} // end if-else	
		
	}

	@Override
	public String getProperty(String key) {
		return appProps.getProperty(key);
	}

	@Override
	public Properties getProperties() {
		
		return appProps;
	}
	
	public Set<Object> getKeys() {
		return appProps.keySet();
	}

	@Override
	public String getConfigFile() {
		return APPLICATION_PROPS_FILE_FQ;
	}
	
	public void logKeys() {
		Logger.debug("Inside method: " + getClass().getName()
				+ ".logKeys()");

		Set<Object> keys = appProps.keySet();
		Logger.debug("Listing keys...");
		for (Object object : keys) {
			Logger.debug(object.toString());
		}
	}
	
	

}
