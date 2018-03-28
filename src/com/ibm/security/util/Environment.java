package com.ibm.security.util;

import java.util.InputMismatchException;

public enum Environment {
	PROD, STAG, TEST;
	
	
	
	public static Enum<Environment> parseEnvironment(String environment) {
		Enum<Environment> env = PROD;
		
		Logger.debug("Inside method: " + Environment.class.getName()
				+ ".setEnvironment(String environment)"); 
		
		Logger.debug("environment: " + environment);
		if (environment.toLowerCase().startsWith("stag")) env = Environment.STAG;
		else if (environment.equalsIgnoreCase("test")) env = Environment.TEST;
		else if (environment.equalsIgnoreCase("dev")) env = Environment.TEST;
		else {
			if (!environment.equalsIgnoreCase("prod")) {
				throw new InputMismatchException("Invalid entry provided.");
			}
		}
		
		return env;

	}
	

}
