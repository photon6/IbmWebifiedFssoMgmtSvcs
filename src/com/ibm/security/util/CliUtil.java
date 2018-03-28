package com.ibm.security.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
<<<<<<< HEAD
=======
import java.util.concurrent.TimeUnit;
>>>>>>> logs-download

import com.ibm.util.JSSH;

public class CliUtil {
	
	public static String exec(String command) throws Exception {
		Logger.debug("Inside method: " + CliUtil.class.getName() 
			+ ":exec(String command)");
		StringBuilder sb = new StringBuilder();
		BufferedReader br = null;
		
		try {
			Process proc = Runtime.getRuntime().exec(command);
			
			if (proc.exitValue() == 0) {
			
				br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				
				String s = null;
				while ((s = br.readLine()) != null) {
					sb.append(s + "\r\n");
				}
			} else 
				sb.append("Command returned no response.");
					
			proc = null;
			br = null;
			
		} catch (Exception e) {
			throw e;
		} 
		
		return sb.toString();
		
	}
	
	public static CommandMap exec(CommandMap commandMap, boolean wait) throws Exception {
		Logger.debug("inside '" + CliUtil.class.getName() + 
				":exec(CommandMap commandMap, boolean wait)'");
		StringBuilder sb = new StringBuilder();
		BufferedReader br = null;

		try {
			Logger.debug("Executing command: " + commandMap.getCommand());
			Process proc = Runtime.getRuntime().exec(commandMap.getCommand());
			if (wait) {
				Logger.debug("Process waiting...");
<<<<<<< HEAD
				proc.waitFor();
				int rc = proc.exitValue();
				Logger.debug("Process exited with return code: " + rc);

				Logger.debug("Adding return code to CommandMap instance");
				commandMap.setCommandResultCode(Integer.toString(rc));
				
				Logger.debug("Process exited successfully");

				br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
					
				String s = null;
				while ((s = br.readLine()) != null) {
					Logger.debug("Ouput from command execution: " + s);
					sb.append(s);
					if (br.ready()) sb.append(System.lineSeparator());
				}
				
=======
				int rc = 0;
				if (proc.waitFor(10, TimeUnit.SECONDS)) {
				
					rc = proc.exitValue();
					Logger.debug("Process exited with return code: " + rc);
	
					Logger.debug("Adding return code to CommandMap instance");
					commandMap.setCommandResultCode(Integer.toString(rc));
					
					Logger.debug("Process exited successfully");
	
					br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
						
					String s = null;
					while ((s = br.readLine()) != null) {
						Logger.debug("Ouput from command execution: " + s);
						sb.append(s);
						if (br.ready()) sb.append(System.lineSeparator());
					}
					
				} else {
					rc = 1;
					Logger.debug("Process timed out");
					
					Logger.debug("Adding return code of 1 to CommandMap instance");
					commandMap.setCommandResultCode(Integer.toString(rc));
					
					sb.append("Process timed out");
	
				}
					
				proc = null;
				br = null;

			
			} // end waiting			
		} catch (Exception e) {
			throw e;
		} finally {
			Logger.debug("Ouput from command execution: " + sb.toString());
			Logger.debug("Adding ouput from command execution to CommandMap instance.");
			commandMap.setCommandResultMessage(sb.toString());
		}
		
		return commandMap;
		
	}

	public static CommandMap exec(CommandMap commandMap, boolean wait, int timeout, TimeUnit timeUnit) throws Exception {
		Logger.debug("inside '" + CliUtil.class.getName() + 
				".exec(CommandMap commandMap, boolean wait, int timeout, TimeUnit timeUnit)'");
		StringBuilder sb = new StringBuilder();
		BufferedReader br = null;

		try {
			Logger.debug("Executing command: " + commandMap.getCommand());
			Process proc = Runtime.getRuntime().exec(commandMap.getCommand());
			if (wait) {
				Logger.debug("Process waiting for " + timeout + " " + timeUnit.name() + "...");
				int rc = 0;
				if (proc.waitFor(timeout, timeUnit)) {
				
					rc = proc.exitValue();
					Logger.debug("Process exited with return code: " + rc);
	
					Logger.debug("Adding return code to CommandMap instance");
					commandMap.setCommandResultCode(Integer.toString(rc));
					
					Logger.debug("Process exited successfully");
	
					br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
						
					String s = null;
					while ((s = br.readLine()) != null) {
						Logger.debug("Ouput from command execution: " + s);
						sb.append(s);
						if (br.ready()) sb.append(System.lineSeparator());
					}
					
				} else {
					rc = 1;
					Logger.debug("Process timed out");
					
					Logger.debug("Adding return code of 1 to CommandMap instance");
					commandMap.setCommandResultCode(Integer.toString(rc));
					
					sb.append("Process timed out");
	
				}
					
>>>>>>> logs-download
				proc = null;
				br = null;

			
			} // end waiting			
		} catch (Exception e) {
			throw e;
		} finally {
			Logger.debug("Ouput from command execution: " + sb.toString());
			Logger.debug("Adding ouput from command execution to CommandMap instance.");
			commandMap.setCommandResultMessage(sb.toString());
		}
		
		return commandMap;
		
	}
}


<<<<<<< HEAD
=======




>>>>>>> logs-download
