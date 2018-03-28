package com.ibm.security.util;

public class IsamFedProperties extends ApplicationProperties {
	
	private final static String APPLICATION_PROPS_FILENAME = "isamfed.properties";
	private final static String SYSTEM_PROPERTY_SHARED_CONFIG_DIR ="shared.config.dir";
	private static java.util.Properties appProps;


	public IsamFedProperties() {
		super(APPLICATION_PROPS_FILENAME, SYSTEM_PROPERTY_SHARED_CONFIG_DIR);
		appProps = super.getProperties();
	}

	public IsamFedProperties(String propertiesFile, String configDir) {
		super(propertiesFile, configDir);
		appProps = super.getProperties();
	}
	
	

}
