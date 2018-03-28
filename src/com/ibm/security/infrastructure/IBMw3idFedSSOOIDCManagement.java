package com.ibm.security.infrastructure;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;

import com.ibm.security.util.CliLinux;
import com.ibm.security.util.CliOS;
import com.ibm.security.util.Environment;
import com.ibm.security.util.FileUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;

public class IBMw3idFedSSOOIDCManagement {
	
	private static final String W3ID_OIDC_TOKEN_OFFBOARD_REMOVE_DIR_PROP = "W3ID_OIDC_TOKEN_OFFBOARD_REMOVE_DIR";
	private static final String W3ID_OIDC_TOKEN_OFFBOARD_REMOVE_MF_PROP = "W3ID_OIDC_TOKEN_OFFBOARD_REMOVE_MF";
	
	
	private CliOS cliOS;
	
	private void initialize() throws IOException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".initialize()"); 
		
		Logger.debug("Size of application properies: " + PropertiesManager.getApplicationProperties().keySet().size());
		
	}
	
	public void removeOidcTokens(String[] userIds, String env) throws IOException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".removeOidcTokens(String[] userIds, String env)");
		
		Enum<Environment> environment = Environment.parseEnvironment(env);

		Logger.debug("userIds: " + Arrays.toString(userIds)); 
		Logger.debug("env: " + environment.name().toUpperCase());
		
		String removeMfFilename = 
				PropertiesManager.getApplicationProperty(W3ID_OIDC_TOKEN_OFFBOARD_REMOVE_DIR_PROP + "_" + environment.name().toUpperCase())
				+ "/" 
				+ PropertiesManager.getApplicationProperty(W3ID_OIDC_TOKEN_OFFBOARD_REMOVE_MF_PROP);
		
		Logger.debug("Removal OIDC Token Manifest file: " + removeMfFilename);
		
		StringBuilder sb = new StringBuilder();
		for (String userId : userIds) {
			sb.append(userId);
			sb.append(System.lineSeparator());
		}
		
		FileUtil.writeToFile(removeMfFilename, sb.toString(), false);
		
	}
	

}
