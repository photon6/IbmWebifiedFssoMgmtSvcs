package com.ibm.security.util;

import java.util.InputMismatchException;

public enum LogFile {
	
	ALL, LATEST, SPECIFIED; // note that "specified" is not expected since that is the default value
	
	public static Enum<LogFile> parseEnvironment(String logsRequeted) {
		Enum<LogFile> logs = LogFile.SPECIFIED;
		
		Logger.debug("Inside method: " + Environment.class.getName()
				+ ".parseEnvironment(String logsRequeted)"); 
		
		Logger.debug("Logs requested: " + logsRequeted);
		if (logsRequeted.equalsIgnoreCase("latest")) logs = LogFile.LATEST;
		else if (logsRequeted.equalsIgnoreCase("all")) logs = LogFile.ALL;
		else {
			if (!logsRequeted.equalsIgnoreCase("specified")) {
				throw new InputMismatchException("Invalid entry provided.");
			}
		}
		
		return logs;

	}
	
	public static void downloadLogs(String url, String filename) {
		
	}
}
