package com.ibm.security.util;

import java.util.InputMismatchException;

public enum ServerType {
	ISAM, ISAM_FED, WEBSEAL, TFIM;
	
	public static Enum<ServerType> parseServerType(String serverType) {
		Logger.debug("Inside method: " + Environment.class.getName()
				+ ".parseServerType(String serverType)"); 
		
		Enum<ServerType> type = WEBSEAL; // set this by default
		
		Logger.debug("serverType: " + serverType);
		if (serverType.equalsIgnoreCase("isam")) type = ServerType.ISAM;
		else if (serverType.equalsIgnoreCase("isam_fed")) type = ServerType.ISAM_FED;
		else if (serverType.equalsIgnoreCase("tfim")) type = ServerType.TFIM;
		else {
			if (!serverType.equalsIgnoreCase("webseal")) {
				throw new InputMismatchException("Invalid entry provided.");
			}
		}
		
		return type;

	}
}
