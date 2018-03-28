package com.ibm.security.util;

public interface CliOS {
	
//	public String exec(String command) throws Exception;
	
	public CommandMap exec(CommandMap commandMap, boolean wait) throws Exception;
	
	public CommandMap exec(CommandMap commandMap, String host, String user, String pw) throws Exception;

	
//	public String getInfo();

}
