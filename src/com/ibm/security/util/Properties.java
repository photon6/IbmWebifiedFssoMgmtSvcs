package com.ibm.security.util;

import java.io.FileNotFoundException;
import java.io.IOException;

public interface Properties {
	
	public String getConfigFile();

	public void loadApplicationProperties() throws FileNotFoundException, IOException;

	public void loadApplicationProperties(String file, boolean isFile) throws FileNotFoundException, IOException;
	
	public String getProperty(String key);
	
	public java.util.Properties getProperties();
	
}
