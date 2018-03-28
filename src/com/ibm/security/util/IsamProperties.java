package com.ibm.security.util;

public class IsamProperties extends ApplicationProperties {
	
	private final static String APPLICATION_PROPS_FILENAME = "isam.properties";
	private final static String SYSTEM_PROPERTY_SHARED_CONFIG_DIR ="shared.config.dir";
	private static java.util.Properties appProps;


	public IsamProperties() {
		super(APPLICATION_PROPS_FILENAME, SYSTEM_PROPERTY_SHARED_CONFIG_DIR);
		appProps = super.getProperties();
	}

	public IsamProperties(String propertiesFile, String configDir) {
		super(propertiesFile, configDir);
		appProps = super.getProperties();
	}
	
	

}
