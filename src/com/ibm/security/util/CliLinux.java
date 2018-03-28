package com.ibm.security.util;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;

import com.ibm.util.JSSH;

public class CliLinux implements CliOS {
	
	private Runtime rt;
	
	private BufferedReader br;
	
	private JSSH jssh;
	
	private StringBuilder sb;
	
	public CliLinux() {
	}
	
	public synchronized String exec(String command) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
			+ ":exec(String command)");
		sb = new StringBuilder();
		
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
			
		} catch (Exception e) {
			throw e;
		} 
		
		return sb.toString();
		
	}
	
	public CommandMap exec(CommandMap commandMap, String host, String user, String pw) throws Exception {		
		Logger.debug("inside '" + getClass().getName() 
				+ ":exec(CommandMap commandMap, String pw)'");
		sb = new StringBuilder();

		try {
//			proc = rt.exec(commandMap.getCommand());
//			proc.waitFor();
//			
//			BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(proc.getOutputStream()));
//			bw.write(pw);
//			bw.newLine();
//			bw.close();
			

			
//			commandMap.setCommandResultCode(Integer.toString(proc.exitValue()));
			
			jssh = new JSSH(host, user, pw);
			
			jssh.setCommand(commandMap.getCommand());
			
			Logger.logToAllLevels("Connecting. Please wait...");
			int rc = jssh.run();
			Logger.logToAllLevels("Run completed...");
			commandMap.setCommandResultCode(Integer.toString(rc));
			
			if (rc == 0) {
//				
//				is = proc.getInputStream();
//					
//				br = new BufferedReader(new InputStreamReader(is));
//					
//				String s = null;
//				while ((s = br.readLine()) != null) {
					sb.append(jssh.getCommandOutput());
//					if (br.ready()) sb.append("\r\n");
//				}
			} else 
				sb.append("Command returned no response.");
					
						
		} catch (Exception e) {
			throw e;
		} finally {
			commandMap.setCommandResultMessage(sb.toString());
//			proc = null;
			jssh = null;
		}
		
		return commandMap;
		
	}
	
	public synchronized CommandMap exec(CommandMap commandMap, boolean wait) throws Exception {
		Logger.debug("inside '" + getClass().getName() + 
				":exec(CommandMap commandMap, boolean wait)'");
		sb = new StringBuilder();

		try {
			Logger.debug("Executing command: " + commandMap.getCommand());
			Process proc = Runtime.getRuntime().exec(commandMap.getCommand());
			if (wait) {
				Logger.debug("Process waiting...");
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
