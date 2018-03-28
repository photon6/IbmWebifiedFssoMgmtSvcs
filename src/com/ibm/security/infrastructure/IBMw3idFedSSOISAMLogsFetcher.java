package com.ibm.security.infrastructure;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import com.ibm.security.util.CliUtil;
import com.ibm.security.util.CommandMap;
import com.ibm.security.util.JSONUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;

public class IBMw3idFedSSOISAMLogsFetcher implements LogsFetcher {
	
	private final static String SCRIPT_ISAM_REST_PROP = "SCRIPT_ISAM_REST";
	private final static String ISAM_FED_HOSTS_PROP = "ISAM_FED_HOSTS";
	private final static String ISAM_FED_LOGS_PROP = "ISAM_FED_LOGS";
	private final static String ISAM_REST_URL_ISAM_FED_LOGFILES_PROP = "ISAM_REST_URL_ISAM_FED_LOGFILES";
	private final static String ISAM_FED_LOGS_LOCAL_PATH_PROP = "ISAM_FED_LOGS_LOCAL_PATH";
	private static final String PROCESS_TIMEOUT_PROP = "PROCESS_TIMEOUT";
	private static final String PROCESS_TIMEOUT_UNITS_PROP = "PROCESS_TIMEOUT_UNITS";	   

	private static int processTimeout;
	private static TimeUnit processTimeoutTimeUnit;
	
	public IBMw3idFedSSOISAMLogsFetcher() {
		initialize();
	}
	
	private void initialize() {
		processTimeout = Integer.parseInt(PropertiesManager.getApplicationProperty(PROCESS_TIMEOUT_PROP));
		processTimeoutTimeUnit = (PropertiesManager.getApplicationProperty(PROCESS_TIMEOUT_UNITS_PROP).equalsIgnoreCase("seconds")?TimeUnit.SECONDS:TimeUnit.MILLISECONDS);

	}

	@Override
	public JSONArray getLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey,
			String email, boolean wait) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public JSONArray getLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email,
			boolean wait) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public JSONArray searchLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email,
			String searchString, boolean wait) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public JSONArray searchLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey,
			String email, String searchString, boolean wait) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public JSONArray getLogsListing(String host, String url, String[] logsToFetch) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogsListing(String host, String url, String[] logsToFetch)");
		
		Logger.debug("Host: " + host);
		Logger.debug("Log files requested: " + Arrays.toString(logsToFetch));
		
		String resultMessage = new String();
		CommandMap commandMap = new CommandMap();

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
	
		try {
			Logger.debug("URL for " + host + " to consume: " + url);
			
			String logsFetchCmd = PropertiesManager.getApplicationProperty(SCRIPT_ISAM_REST_PROP) + " " + url; 
			Logger.debug("Adding command to CommandMap object: " + logsFetchCmd);
			
			commandMap.setCommand(logsFetchCmd);

			Logger.debug("Executing command on OS");
		
			
			commandMap = CliUtil.exec(commandMap, true, processTimeout, processTimeoutTimeUnit);
		
//			if (commandMap.getCommandResultCode().equals("0")) {
				
			resultMessage = commandMap.getCommandResultMessage();
			Logger.debug("ResultMessage");
			Logger.debug("[[" + resultMessage + "]]");			
			
			Logger.debug("Building JSON Array");
			jsonObject = new JSONObject();
			jsonObject.put("Host", host);

			if (commandMap.getCommandResultCode().equals("0")) {
				JSONArray jsonArrayTmp = new JSONArray(); 					
				JSONArray jsonArrayTmp2 = 
						processLogsListingJSONStringIntoJSONArray(resultMessage);
				
				
				for (int j = 0; j < jsonArrayTmp2.size(); j++) {
					JSONObject jObject = (JSONObject) jsonArrayTmp2.get(j);
					for (String logToFetch : logsToFetch) {
						Logger.debug("Evaluating \"" + logToFetch + "\" against \"" + jObject.get(JSONUtil.JSON_KEY_FILE).toString() + "\"");
						if (jObject.get(JSONUtil.JSON_KEY_FILE).toString().startsWith(logToFetch)
								| jObject.get(JSONUtil.JSON_KEY_FILE).toString().equalsIgnoreCase(logToFetch)) {
							Logger.debug("Matching with \"" + logToFetch + "\" found");
							jsonArrayTmp.add(jObject);
						} // if file matches the log file name (or type) requested
					} // end for (String logToFetch : logsToFetch)
				} // end for (int j = 0; j < jsonObject.length; j++)
				
				jsonArrayTmp2 = null;
				
				jsonObject.put("Logs", jsonArrayTmp);
				Logger.debug("Added 'Logs' value of '" + jsonArrayTmp + "' to JSON Arrray");
			} else {
				jsonObject.put("Error", commandMap.getCommandResultMessage());
				Logger.debug("Added 'Error' message to JSON Array: '" + commandMap.getCommandResultMessage());
				
			}
			jsonArray.add(jsonObject);
			Logger.debug("Added 'Host' value of '" + host + "' to JSON Arrray");

			resultMessage = "";
			
			commandMap.setCommandResultMessage(" ");
				
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		} finally {
			resultMessage = null;
			commandMap = null;
		}
					
		Logger.debug("JSON Array Compiled: " + jsonArray.toJSONString());
		
		return jsonArray;
	}
	
	public JSONArray processLogsListingJSONStringIntoJSONArray(String jsonString) throws ParseException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".convertStringToJSONArray(String jsonString)");
		
		Logger.debug("JSON String: " + jsonString);
		try {
			jsonString = jsonString.substring(jsonString.indexOf("[")+1);
			jsonString = jsonString.substring(0, jsonString.indexOf("]"));
		} catch (Exception e) {
			if (!e.getMessage().contains("Unexpected internal error near index 1")) {
				throw new ParseException(e.hashCode());
			}
		}
		Logger.debug("JSON String after adjustment: " + jsonString);
		

		JSONArray jsonArray = new JSONArray();
		
		StringTokenizer st = new StringTokenizer(jsonString, ",");
		while (st.hasMoreElements()) {
			String jsonObjectInString = JSONUtil.removeJSONStringChars(st.nextElement().toString().trim());
			StringTokenizer st2 = new StringTokenizer(jsonObjectInString, ":");
			Map<String, String> jsonObjectMap = new HashMap<String, String>();
			while (st2.hasMoreTokens()) {
				Object obj = st2.nextElement();
				if (obj != null) {
					String stringToMap = JSONUtil.removeJSONStringChars(obj.toString().trim());
					if (stringToMap.equals("id")) {
						String key = stringToMap;
						String value = JSONUtil.removeJSONStringChars(st2.nextElement().toString().trim());
						Logger.debug("Found Log File: " + value);
						jsonObjectMap.put(key, value);
						jsonArray.add((JSONObject) new JSONObject(jsonObjectMap));
					} // end if
				} // end if
			} // end while re: st2
		}  // end while re: st
		 
		Logger.debug("Processed JSON Array : " + jsonArray.toJSONString());
		return jsonArray;
	}

}
