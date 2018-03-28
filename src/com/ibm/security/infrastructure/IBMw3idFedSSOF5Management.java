package com.ibm.security.infrastructure;

import com.ibm.security.util.CliUtil;
import com.ibm.security.util.CommandMap;
import com.ibm.security.util.FileUtil;
import com.ibm.security.util.JSONUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;

public class IBMw3idFedSSOF5Management {
	
	private static final String F5COOKIE_DECODER_REST_API_PROP = "F5COOKIE_DECODER_REST_API";
	private static final String F5COOKIE_DECODER_REST_API_METHOD_PROP = "F5COOKIE_DECODER_REST_API_METHOD";
	private static final String F5COOKIE_DECODER_REST_API_HEADER_PROP = "F5COOKIE_DECODER_REST_API_HEADER";
	private static final String F5COOKIE_DECODER_REST_API_JSON_INPUT_PARAMS_PROP = "F5COOKIE_DECODER_REST_API_JSON_INPUT_PARAMS";
	private static final String F5COOKIE_DECODER_REST_API_JSON_INPUT_FILE_PROP = "F5COOKIE_DECODER_REST_API_JSON_INPUT_FILE";
	
	
	public String decodeF5Cookie(String cookie) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".decodeF5Cookie(String cookie)");
		
		String resultMessage = new String();
		CommandMap commandMap = new CommandMap();
		String decodedCookieValues = "";		
		
		String jsonInputParamsFromProp = PropertiesManager.getApplicationProperty(F5COOKIE_DECODER_REST_API_JSON_INPUT_PARAMS_PROP);
		
		String jsinInputParamsFile = PropertiesManager.getApplicationProperty(F5COOKIE_DECODER_REST_API_JSON_INPUT_FILE_PROP);
		
		FileUtil.writeToFile(jsinInputParamsFile, "{ \"" + jsonInputParamsFromProp + "\" : \"" + cookie + "\" }", true);
		
		String decodeF5CookieCmd = 
				  "curl -H \"Accept:"  
				+ " " + PropertiesManager.getApplicationProperty(F5COOKIE_DECODER_REST_API_HEADER_PROP) + "\"" 
				+ " --data @" + jsinInputParamsFile
				+ " -X " + PropertiesManager.getApplicationProperty(F5COOKIE_DECODER_REST_API_METHOD_PROP)
				+ " " + PropertiesManager.getApplicationProperty(F5COOKIE_DECODER_REST_API_PROP);  
						
		try {		

			Logger.debug("Decode F5 Cookie command: " + decodeF5CookieCmd);

			Logger.debug("Adding pending jobs command to CommandMap object");
			commandMap.setCommand(decodeF5CookieCmd);

			Logger.debug("Executing command on OS");
			commandMap = CliUtil.exec(commandMap, true);

			
			if (commandMap.getCommandResultCode().equals("0")) {
				
				resultMessage = commandMap.getCommandResultMessage();
				Logger.debug("ResultMessage");
				Logger.debug("[[" + resultMessage + "]]");				
				
				decodedCookieValues = resultMessage;
				
				resultMessage = "";
			}
			
			commandMap.setCommandResultMessage(" ");
			
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		} finally {
			resultMessage = null;
			commandMap = null;
		}
		
		return decodedCookieValues;
		
	}

}
