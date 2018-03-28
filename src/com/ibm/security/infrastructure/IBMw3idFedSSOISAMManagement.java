package com.ibm.security.infrastructure;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;

import javax.mail.search.IntegerComparisonTerm;
import javax.ws.rs.ProcessingException;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

import com.ibm.security.util.CliUtil;
import com.ibm.security.util.CommandMap;
import com.ibm.security.util.Environment;
import com.ibm.security.util.FileUtil;
import com.ibm.security.util.HttpServletUtil;
import com.ibm.security.util.JSONUtil;
import com.ibm.security.util.LogFile;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;
import com.ibm.security.util.VectorUtil;


public class IBMw3idFedSSOISAMManagement {
	
	private static Properties appProps;
	private Enum<Environment> environment;
	private String host;
	
	private static final String ISAM_REST_URL_WEBSEAL_LOGFILES_PROP = "ISAM_REST_URL_WEBSEAL_LOGFILES"; 
	private static final String ISAM_REST_URL_ISAM_APP_LOGFILES_PROP = "ISAM_REST_URL_ISAM_APP_LOGFILES"; 
	private static final String ISAM_REST_URL_ISAM_APP_LOGFILES_APPEND_PROP = "ISAM_REST_URL_ISAM_APP_LOGFILES_APPEND"; 
	private static final String ISAM_REST_URL_ISAM_FED_LOGFILES_PROP = "ISAM_REST_URL_ISAM_FED_LOGFILES"; 
	private static final String ISAM_REST_URL_ISAM_FED_LOGFILES_APPEND_PROP = "ISAM_REST_URL_ISAM_FED_LOGFILES_APPEND"; 
	private static final String ISAM_DOMAIN_PROP_PREFIX = "ISAM_DOMAIN_"; 
	private static final String ISAM_HOSTS_PROP_PREFIX = "ISAM_HOSTS_"; 
	private static final String ISAM_FED_HOSTS_PROP_PREFIX = "ISAM_FED_HOSTS_"; 
	private static final String ISAM_HOSTS_PROP_DELIM = ",";
	private static final String ISAM_WEBSEAL_LOGS_PROP="ISAM_WEBSEAL_LOGS";
	private static final String ISAM_APP_LOGS_PROP="ISAM_APP_LOGS";
	private static final String ISAM_FED_LOGS_PROP="ISAM_FED_LOGS";
	private static final String W3ID_LOGS_FETCH_MF_FILE_PROP = "W3ID_LOGS_FETCH_MF_FILE";
	private static final String W3ID_LOGS_NOTIFICATION_MF_FILE_PROP = "W3ID_LOGS_NOTIFICATION_MF_FILE";
	private static final String W3ID_LOGS_SEARCH_MF_FILE_PROP = "W3ID_LOGS_SEARCH_MF_FILE";
	private static final String ISAM_WEBSEAL_LOGS_LOCAL_PATH_PROP = "ISAM_WEBSEAL_LOGS_LOCAL_PATH";
	private static final String W3ID_LOGS_LOCAL_PATH_PROP = "W3ID_LOGS_LOCAL_PATH";
	private static final String W3ID_LOGS_FETCH_MF_FILE_PROCESSING_PROP = "W3ID_LOGS_FETCH_MF_FILE_PROCESSING";
	private static final String ISAM_APP_LOGS_LOCAL_PATH_PROP = "ISAM_APP_LOGS_LOCAL_PATH";
	private static final String ISAM_FED_LOGS_LOCAL_PATH_PROP = "ISAM_FED_LOGS_LOCAL_PATH";
	private static final String SCRIPT_ISAM_REST_PROP = "SCRIPT_ISAM_REST";	
	private static final String SCRIPT_LOGS_FETCHER_PROP = "SCRIPT_LOGS_FETCHER";
	private static final String ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP = "ISAM_WEBSEAL_LOGS_SWITCH_KEYS";
	private static final String ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP_PREFIX = "<";
	private static final String ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP_SUFFIX = ">";
	private static final String ISAM_APP_LOGS_SWITCH_KEYS_PROP = "ISAM_APP_LOGS_SWITCH_KEYS";
	private static final String ISAM_APP_LOGS_SWITCH_KEYS_PROP_PREFIX = "<";
	private static final String ISAM_APP_LOGS_SWITCH_KEYS_PROP_SUFFIX = ">";
	private static final String LATEST_LOGS_SUFFIX = ".log";
	private static final String TIMEFRAME_PATTERN_FILECHECK_PROP = "TIMEFRAME_PATTERN_FILECHECK";
	private static final String ISAM_REST_URL_DEVICE_FP_PROP = "ISAM_REST_URL_DEVICE_FP";
	private static final String ISAM_REST_URL_DEVICE_FP_SWITCH_KEYS_PROP = "ISAM_REST_URL_DEVICE_FP_SWITCH_KEYS";
	private static final String PROCESS_TIMEOUT_PROP = "PROCESS_TIMEOUT";
	private static final String PROCESS_TIMEOUT_UNITS_PROP = "PROCESS_TIMEOUT_UNITS";	   
	
	private static ArrayList<String> isamWebSealLogsList;
	private static ArrayList<String> isamAppLogsList;
	private static ArrayList<String> isamFedLogsList;
	
	private static ArrayList<String> isamWebSealLogsSwitchKeys;
	private static ArrayList<String> isamAppLogsSwitchKeys;
	private static ArrayList<String> isamFedLogsSwitchKeys;
	
	private static HashMap<String, String> isamWebSealLogsSwitchKeysMap;
	private static HashMap<String, String> isamAppLogsSwitchKeysMap;
	private static HashMap<String, String> isamFedLogsSwitchKeysMap;
	
	private static int processTimeout;
	private static TimeUnit processTimeoutTimeUnit;
	
	public IBMw3idFedSSOISAMManagement() throws IOException {
		Logger.debug("Inside constructor: " + this.getClass().getName()
				+ "()");
		
		initialize();
	}
	
	public IBMw3idFedSSOISAMManagement(String env) throws IOException {
		Logger.debug("Inside contructor: " + this.getClass().getName() 
				+ "(String env)");
		
		initialize();
		
		this.environment = Environment.parseEnvironment(env);
		Logger.debug("Environment is " + this.environment.name());			
	}

	public IBMw3idFedSSOISAMManagement(String env, String host) throws IOException {
		Logger.debug("Inside contructor: " + this.getClass().getName() 
				+ "(String env, String host)");
		
		initialize();
		
		this.environment = Environment.parseEnvironment(env);
		Logger.debug("Environment is " + this.environment.name());
		
		this.host = host;
		Logger.debug("Host is " + this.host);
		
		
	}
	
	private void initialize() throws IOException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".initialize()"); 
		
		appProps = PropertiesManager.getApplicationProperties();
		Logger.debug("Size of application properies: " + PropertiesManager.getApplicationProperties().keySet().size());
		
		host = "";
		processTimeout = Integer.parseInt(PropertiesManager.getApplicationProperty(PROCESS_TIMEOUT_PROP));
		processTimeoutTimeUnit = (PropertiesManager.getApplicationProperty(PROCESS_TIMEOUT_UNITS_PROP).equalsIgnoreCase("seconds")?TimeUnit.SECONDS:TimeUnit.MILLISECONDS);
		
		initWebSealLogsProps();
		initIsamAppLogsProps();
		initIsamFedLogsProps();
	}
	
	
	@SuppressWarnings("unchecked")
	public JSONArray getLogsListing(String host) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogsListing()");
		
		String instanceLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_WEBSEAL_LOGFILES_PROP); 
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + instanceLogFilesURL);
		
		String domainFromProp = PropertiesManager.getApplicationProperty(ISAM_DOMAIN_PROP_PREFIX + environment.name().toUpperCase());
		Logger.debug("Domain from properties file: " + domainFromProp);
		
		String resultMessage = new String();
		CommandMap commandMap = new CommandMap();
		
		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
	
		try {
			
			String url = host + instanceLogFilesURL + "/" + domainFromProp;
			Logger.debug("URL for " + host + " to consume: " + url);
			
			
			String logsFetchCmd = PropertiesManager.getApplicationProperty(SCRIPT_ISAM_REST_PROP) + " " + url; 
			Logger.debug("Adding command to CommandMap object: " + logsFetchCmd);
			
			commandMap.setCommand(logsFetchCmd);

			Logger.debug("Executing command on OS");
		
			commandMap = CliUtil.exec(commandMap, true);
			
			if (commandMap.getCommandResultCode().equals("0")) {
				
				resultMessage = commandMap.getCommandResultMessage();
				Logger.debug("ResultMessage");
				Logger.debug("[[" + resultMessage + "]]");			
				
				Logger.debug("Building JSON Array");
				jsonObject = new JSONObject();
				jsonObject.put("Host", host);
				JSONArray jsonArrayTmp = 
						processLogsListingJSONStringIntoJSONArray(resultMessage);
				jsonObject.put("Logs", jsonArrayTmp);
				jsonArray.add(jsonObject);
				Logger.debug("Added 'Host' value of '" + host + "' to JSON Arrray");
				Logger.debug("Added 'Logs' value of '" + jsonArrayTmp + "' to JSON Arrray");

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
					
		Logger.debug("JSON Array Compiled: " + jsonArray.toJSONString());
		
		return jsonArray;
		
	}
	
	@SuppressWarnings("unchecked")
	public JSONArray getLogsListing() throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogsListing()");

		String hostsFromProp = PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
		Logger.debug("Hosts from properties file: " + hostsFromProp);

		String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
		
//		JSONObject[] jsonObject = new JSONObject[hosts.length];
		JSONArray jsonArray = new JSONArray();
		
		for (String host : hosts) {
			jsonArray.add(getLogsListing(host));
		}
		
		return jsonArray;

		
	} // end method public JSONArray getLogsListing() throws Exception {
	
	@SuppressWarnings("unchecked")
	private JSONArray getWebSealLogsListing(String host, String[] logsToFetch) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getWebSealLogsListing(String host, String[] logsToFetch)");
		
		Logger.debug("Host: " + host);
		Logger.debug("Log files requested: " + Arrays.toString(logsToFetch));
		
		String instanceLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_WEBSEAL_LOGFILES_PROP); 
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + instanceLogFilesURL);
		
		String domainFromProp = PropertiesManager.getApplicationProperty(ISAM_DOMAIN_PROP_PREFIX + environment.name().toUpperCase());
		Logger.debug("Domain from properties file: " + domainFromProp);

		String url = host + instanceLogFilesURL + "/" + domainFromProp;
		Logger.debug("URL  for " + host + " to consume: " + url);
			
		return getIsamLogsListing(host, url, logsToFetch);

		
	} // end method public JSONArray getLogsListing() throws Exception {

	@SuppressWarnings("unchecked")
	private JSONArray getIsamAppLogsListing(String host, String[] logsToFetch) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getIsamAppLogsListing(String host, String[] logsToFetch)");
		
		Logger.debug("Host: " + host);
		Logger.debug("Log files requested: " + Arrays.toString(logsToFetch));
		
		String instanceLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_APP_LOGFILES_PROP); 
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + instanceLogFilesURL);
		
		String url = host + instanceLogFilesURL;
		Logger.debug("URL for " + host + " to consume: " + url);
			
		HashMap<String, String> logzToFetchMap = new HashMap<String, String>();
		addIsamAppLogsToFetchBaseFilenamesToHashMap(logsToFetch, instanceLogFilesURL, logzToFetchMap);

		Set<String> isamAppLogsURLKeys = logzToFetchMap.keySet();
		HashSet<String> logzToFetchList = new HashSet<String>();
		for (String isamAppLogsURLKey : isamAppLogsURLKeys) {
			Logger.debug("Value for " + isamAppLogsURLKey + " is " + logzToFetchMap.get(isamAppLogsURLKey));
			logzToFetchList.add(logzToFetchMap.get(isamAppLogsURLKey));
		}
		
		String[] logzToFetch = new String[logzToFetchList.size()];
		logzToFetchList.toArray(logzToFetch);
		
		return getIsamLogsListing(host, url, logzToFetch);
		
	} // end method public JSONArray getLogsListing() throws Exception {

	@SuppressWarnings("unchecked")
	private JSONArray getIsamFedLogsListing(String host, String[] logsToFetch) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getIsamFedLogsListing(String host, String[] logsToFetch)");
		
		Logger.debug("Host: " + host);
		Logger.debug("Log files requested: " + Arrays.toString(logsToFetch));
		
		String instanceLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_FED_LOGFILES_PROP); 
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + instanceLogFilesURL);
		
		String url = host + instanceLogFilesURL;
		Logger.debug("URL for " + host + " to consume: " + url);
			
		HashMap<String, String> logzToFetchMap = new HashMap<String, String>();
		logzToFetchMap = addIsamFedLogsToFetchBaseFilenamesToHashMap(logsToFetch, instanceLogFilesURL, logzToFetchMap);
		Logger.debug("Map with URLs to fetch logs: " + logzToFetchMap.toString());

		Set<String> isamFedLogsURLKeys = logzToFetchMap.keySet();
		HashSet<String> logzToFetchList = new HashSet<String>();
		for (String isamFedLogsURLKey : isamFedLogsURLKeys) {
			Logger.debug("Value for " + isamFedLogsURLKey + " is " + logzToFetchMap.get(isamFedLogsURLKey));
			logzToFetchList.add(logzToFetchMap.get(isamFedLogsURLKey));
		}
		
		String[] logzToFetch = new String[logzToFetchList.size()];
		logzToFetchList.toArray(logzToFetch);
		
		return getIsamLogsListing(host, url, logzToFetch);
		
	} // end method public JSONArray getLogsListing() throws Exception {

	
	@SuppressWarnings("unchecked")
	private JSONArray getIsamLogsListing(String host, String url, String[] logsToFetch) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getIsamLogsListing(String host, String url, String[] logsToFetch)");
		
		Logger.debug("Host: " + host);
		Logger.debug("URL: " + url);
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
		
//			commandMap = cliOS.exec(commandMap, true);
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
		
	} // end method public JSONArray getLogsListing() throws Exception {


	public Object getDeviceFingerprints(String[] userIds, String zipFileName) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getDeviceFingerprints(String[] userIds, String zipFileName)");
		
		Logger.debug("User IDs to search device fingerprints on: " + Arrays.toString(userIds));
		
		Object returnObj = "";
		String zipFile = "";
		File zfDir = null;
		
		if (!zipFileName.equals("")) {
			zipFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_LOCAL_PATH_PROP) 
					+ "/" + zipFileName + ".zip";

			Logger.debug("Full path to zip file: " + zipFile);

			zfDir = new File(PropertiesManager.getApplicationProperty(W3ID_LOGS_LOCAL_PATH_PROP) 
					+ "/" + zipFileName);
			Logger.debug("Parent directory of zip file: " + zfDir.getAbsolutePath());
			if (!zfDir.isDirectory()) {
				Logger.debug((zfDir.mkdirs()?"Successfully created: ":"Failed to create: ") + zfDir.getAbsolutePath());
				
			}
		}
		
		
		
		String hostsFromProp = PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
		String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
		Logger.debug("Will use only one of these hosts: " + Arrays.toString(hosts));
		
		String url = hosts[1] +  "/" + PropertiesManager.getApplicationProperty(ISAM_REST_URL_DEVICE_FP_PROP);
		String switchKey = PropertiesManager.getApplicationProperty(ISAM_REST_URL_DEVICE_FP_SWITCH_KEYS_PROP);

		JSONArray jsonArray = new JSONArray();
		
		for (int i = 0; i < userIds.length; i++) {
			Logger.debug("Now preparring for user ID: " + userIds[i]);
			url = (url.contains(switchKey)?url.replace(switchKey, userIds[i]):url.replace(userIds[i-1], userIds[i]));
			
			String resultMessage = new String();
			CommandMap commandMap = new CommandMap();

			JSONObject jsonObject = new JSONObject();
		
			try {
				Logger.debug("URL for " + host + " to consume: " + url);
				String userIdFile = "";
				
				String logsFetchCmd = PropertiesManager.getApplicationProperty(SCRIPT_ISAM_REST_PROP) + " " + url;
				if (!zipFileName.equals("")) {
					userIdFile = (userIds[i].contains("@")?userIds[i].substring(0, userIds[i].indexOf("@")):userIds[i]) + "-fp.txt";
					logsFetchCmd += " > " +  PropertiesManager.getApplicationProperty(W3ID_LOGS_LOCAL_PATH_PROP) 
					+ "/" + zipFileName + "/" + userIdFile;
				}
				
				Logger.debug("Adding command to CommandMap object: " + logsFetchCmd);
				
				commandMap.setCommand(logsFetchCmd);

				Logger.debug("Executing command on OS");
			
				commandMap = CliUtil.exec(commandMap, true);
			
				if (commandMap.getCommandResultCode().equals("0")) {
					
					resultMessage = commandMap.getCommandResultMessage();
					Logger.debug("ResultMessage");
					Logger.debug("[[" + resultMessage + "]]");
					
					if (zipFileName.equals("")) {
					
						Logger.debug("Building JSON Array");
						jsonObject = new JSONObject();
						jsonObject.put("UserID", userIds[i]);
						
						String fps = resultMessage;
						
						if (fps.contains("FBTRBA322E")) {
							jsonObject.put("Error", fps);
						} else {
							jsonObject.put("DeviceFingerprints", fps);
						}
	
						jsonArray.add(jsonObject);
						Logger.debug("Added 'UserID' value of '" + userIds[i] + "' to JSON Arrray");
						Logger.debug("Added 'Fingerprints' value of '" + fps + "' to JSON Arrray");
						
					} else {

						String zipCmd = "zip " + zipFile + " " + PropertiesManager.getApplicationProperty(W3ID_LOGS_LOCAL_PATH_PROP) 
							+ "/" + zipFileName + "/" + userIdFile;
							
						Logger.debug("Adding command to CommandMap object: " + zipCmd);
							
						commandMap.setCommand(zipCmd);

						Logger.debug("Executing command on OS");
						
						commandMap = CliUtil.exec(commandMap, true);
						
						if (commandMap.getCommandResultCode().equals("0")) {
							resultMessage = commandMap.getCommandResultMessage();
							Logger.debug("ResultMessage");
							Logger.debug("[[" + resultMessage + "]]");
								
								resultMessage = "";
						} // end if (commandMap.getCommandResultCode().equals("0")) {

						resultMessage = "";
					
					} // end if-else (zipFileName.equals("")) {
				}  // end if (commandMap.getCommandResultCode().equals("0")) {
				
				commandMap.setCommandResultMessage(" ");
					
			} catch (Exception e) {
				Logger.logToAllLevels("Exception caught: " + e.getMessage());
				throw e;
			} finally {
				resultMessage = null;
				commandMap = null;
			} // end try-catch
			
		} // end for (String userId : userIds) {
		
		if (zipFileName.equals("")) {
			Logger.debug("JSON Array Compiled: " + jsonArray.toJSONString());
			returnObj = jsonArray.toJSONString();			
		} else {

				File zf = new File(zipFile);
				if (zf.exists()) {
					returnObj = (Object) zf;
					if (zfDir.exists()) {
						zfDir.delete();
					}
//					zf.delete();
				} else {
					throw new FileNotFoundException("Cannot find " + zipFile);
				} // end if (zf.exists()) {
				

		} // end if-else (saveAsFile) {
	
		return returnObj;
	}
	
	/**
	 * This overloaded method assumes that only latest or all logs are requested from WebSEALs
	 * 
	 * @param logsToFetch 		Array of log files to fetch (full log file names)
	 * @param allOrLatesetLogs	Key word to indicate whether 'all' or 'latest' or 'specified'
	 * @param newKey 			Unique key by which log files are associated on the backend
	 * @param email 			Email address to which notifications that log files have been downloaded will be sent
	 * @param wait 				True or False value to direct this method to wait for completion (i.e., synchronous); true by default
	 */
	@SuppressWarnings("unchecked")
	public JSONArray getLogs(String[] logsToFetch, String allOrLatesetLogs, String newKey, String email, boolean wait) throws Exception {
		
		JSONArray jsonArray = new JSONArray();

		HashMap<String, String> requestedLogsAndHostsMap = new HashMap<String, String>(logsToFetch.length);
		for (String logToFetch : logsToFetch) {
			if (isamWebSealLogsList.contains(logToFetch)) {
				Logger.debug("Request includes log type from WebSEAL, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
				requestedLogsAndHostsMap.put(logToFetch, (PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase())));
			} else if (isamAppLogsList.contains(logToFetch)) {
				Logger.debug("Request includes log type from ISAM, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
				requestedLogsAndHostsMap.put(logToFetch, (PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase())));
			} else if (isamFedLogsList.contains(logToFetch)) {
				Logger.debug("Request includes log type from ISAM Fed, so fetching from properties: " + ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
				requestedLogsAndHostsMap.put(logToFetch, (PropertiesManager.getApplicationProperty(ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase())));
			}
		}

		Logger.debug("Map of requested logs and hosts: " + requestedLogsAndHostsMap.toString());
		
		for (String logToFetch : logsToFetch) {
		
//			String hostsFromProp = PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
			String hostsFromProp = requestedLogsAndHostsMap.get(logToFetch);
			Logger.debug("Hosts from properties file: " + hostsFromProp);
			String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
	//		String[] hosts = (host.equals("")?PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM):(new String[] {host}));
	
			HashSet<String> keys = new HashSet<String>();
			
			
			for (int i = 0; i < hosts.length; i++) {
				this.host = hosts[i];
	//			keys.add(getLogs(hosts[i], logsToFetch, allOrLatesetLogs, newKey, email, wait));
				
				JSONObject jsonObject = new JSONObject();
				jsonObject.put("Host", hosts[i]);
				jsonObject.put("Report", getLogs(hosts[i], new String[] {logToFetch}, allOrLatesetLogs, newKey, email, wait, false));
				jsonArray.add(jsonObject);
				
			}
			
		} // end for (String logToFetch : logsToFetch) {
		
//		Logger.debug("Keys: " + keys.toString());
		
		String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
		Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);

		writeToNotifyManifestFile(newKey, email, logsNotifyManifestFile);
		
//		String returnKey = "";
//		for (Iterator iterator = keys.iterator(); iterator.hasNext();) {
//			returnKey += (String) iterator.next();
//			if (iterator.hasNext()) returnKey += ",";
//			
//		}

//		return returnKey;
		
		return jsonArray;

	}

	/**
	 * This overloaded method assumes that only latest or all logs are requested from a single instance of WebSEAL
	 * 
	 * @param host 				Single host from which to downlaod log files
	 * @param logsToFetch 		Array of log files to fetch (full log file names)
	 * @param allOrLatesetLogs	Key word to indicate whether 'all' or 'latest' or 'specified'
	 * @param newKey 		Unique key by which log files are associated on the backend
	 * @param email 			Email address to which notifications that log files have been downloaded will be sent
	 * @param wait 				True or False value to direct this method to wait for completion (i.e., synchronous); true by default
	 */
	@SuppressWarnings("unchecked")
	public JSONArray getLogs(String host, String[] logsToFetch, String allOrLatesetLogs, String newKey, String email, boolean wait, boolean writeToNotifyFile) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogs(String[] logsToFetch, String allOrLatesetLogs, String sessionID, String email, boolean wait)");
		
		Logger.debug("Log files requested: " + Arrays.toString(logsToFetch));

		Enum<LogFile> allOrLatestLogFiles = LogFile.parseEnvironment(allOrLatesetLogs);
		Logger.debug("Logs requested: " + allOrLatestLogFiles.name());
		Logger.debug("Wait for fetch? " + !wait);
		
		String logsManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROP);
		Logger.debug("Logs manifest file from properties file: " + logsManifestFile);

		String logsManifestProcessingFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROCESSING_PROP);
		Logger.debug("Logs manifest processing file from properties file: " + logsManifestProcessingFile);

		HashMap<String, String> returnMap = new HashMap<String, String>();
		String tmp = "";
		
		try {
		
			for (String logToFetch : logsToFetch) {
				
				if (host.toLowerCase().contains("host")) {
					String hostsFromProp = getPropertyByLogToFetchType(logToFetch);
					Logger.debug("Hosts from properties file: " + hostsFromProp);
					String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
					host = hosts[Integer.parseInt(host.substring("host".length()))-1]; // get the ordinal number
				}
				
				if (isamWebSealLogsList.contains(logToFetch)) {
					Logger.debug("Request includes log type from WebSEAL, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
					tmp = getWebSealLogs(host, logsToFetch, allOrLatestLogFiles, newKey, logsManifestFile, wait);
					Logger.debug("Result concerning logs from WebSEAL: " + tmp);
					returnMap = evaluateResult("Key", "Message", tmp, returnMap);
				} else if (isamAppLogsList.contains(logToFetch)) {
					Logger.debug("Request includes log type from ISAM, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
					tmp = getIsamAppLogs(host, logsToFetch, allOrLatestLogFiles, newKey, logsManifestFile, wait);
					Logger.debug("Result concerning applicaiton logs from ISAM: " + tmp);
					returnMap = evaluateResult("Key", "Message", tmp, returnMap);
				} else if (isamFedLogsList.contains(logToFetch)) {
					Logger.debug("Request includes log type from ISAM Fed, so fetching from properties: " + ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
					tmp = getIsamFedLogs(host, logsToFetch, allOrLatestLogFiles, newKey, logsManifestFile, wait);
					Logger.debug("Result concerning federation logs from ISAM: " + tmp);
					returnMap = evaluateResult("Key", "Message", tmp, returnMap);
				}
			}
	
			FileUtil.touchFile(logsManifestProcessingFile);
			
			if (writeToNotifyFile) {
				String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
				Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);
						
				writeToNotifyManifestFile(newKey, email, logsNotifyManifestFile);
			}
			
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		} 
		
		return mapToJSONArray(returnMap);
		
	} // end method public JSONArray getLogs(String[] logsToFetch, String allOrLatesetLogs, String sessionID, String email, boolean wait)
	

	
	
	/**
	 * This overloaded method assumes that only logs within a date range are requested from WebSEALs
	 * 
	 * @param host 			Single host from which to download log files
	 * @param logsToFetch 	Array of log files to fetch (full log file names)
	 * @param fromDate 		Start of time frame to filter logs to download; format is YYYYMMDD in Java
	 * @param toDate 		End of time frame to filter logs to download; format is YYYYMMDD in Java
	 * @param newKey 		Unique key by which log files are associated on the backend
	 * @param email 		Email address to which notifications that log files have been downloaded will be sent
	 * @param wait 			True or False value to direct this method to wait for completion (i.e., synchronous); true by default
	 */
	@SuppressWarnings("unchecked")
	public JSONArray getLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey, String email, boolean wait, boolean writeToNotifyFile) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogs(String host, String[] logsToFetch, String fromDate, String toDate, String sessionID, String email, boolean wait)");
		
		Logger.debug("Logs file to fetch: " + Arrays.toString(logsToFetch));
		
		Logger.debug("Wait for fetch? " + !wait);
		
		String logsManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROP);
		Logger.debug("Logs manifest file from properties file: " + logsManifestFile);

		String logsManifestProcessingFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROCESSING_PROP);
		Logger.debug("Logs manifest processing file from properties file: " + logsManifestProcessingFile);

//		String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
//		Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);
		
		Logger.debug("Logs fitting time frame requested, so fetching logs listing from host: " + host);
		
		SimpleDateFormat sdf = new SimpleDateFormat(PropertiesManager.getApplicationProperty(TIMEFRAME_PATTERN_FILECHECK_PROP));
		
		HashMap<String, Boolean> success = new HashMap<String, Boolean>();
		HashMap<String, String> returnMap = new HashMap<String, String>();
		
		boolean nologsrequested = true;

		
		try {
			
			String[] dateRange = getDateRange(fromDate, toDate, sdf);
			if (dateRange.length > 0) {
				Logger.debug("Date range requested: " + Arrays.toString(dateRange));
			}
			
			for (String logToFetch : logsToFetch) {
				
				if (host.toLowerCase().contains("host")) {
					Logger.debug("Using new 'hostN' directive");
					String hostsFromProp = getPropertyByLogToFetchType(logToFetch);
					Logger.debug("Hosts from properties file: " + hostsFromProp);
					String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
					host = hosts[Integer.parseInt(host.substring("host".length()))-1]; // get the ordinal number
				}

				
				String tmp = "";
				
				if (isamWebSealLogsList.contains(logToFetch)) {  // for WebSEAL logs
					Logger.debug("Request includes log type from WebSEAL, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
					HashMap<String, String> webSealLogsMap = new HashMap<String, String>();
					addWebSealLogsToFetchBaseFilenamesToHashMap(logsToFetch, webSealLogsMap);
					
					if (webSealLogsMap.size() > 0) {
						nologsrequested = false;
					
						Logger.debug("Size of WebSEAL logs map: " + webSealLogsMap.size());
						String[] webSealLogsToFetchWithDates = appendDatesToLogFilenamesAsStringArray(webSealLogsMap, dateRange);
						Logger.debug("File name prefix of WebSeal logs to fetch: " + Arrays.toString(webSealLogsToFetchWithDates));
						JSONArray webSealLogsListing = (JSONArray) getWebSealLogsListing(host, webSealLogsToFetchWithDates);
						ArrayList<String> webSealLogsWithDates = processLogsToFetch(webSealLogsListing, webSealLogsToFetchWithDates);
						String[] webSealLogzToFetch = new String[webSealLogsWithDates.size()];
						webSealLogsWithDates.toArray(webSealLogzToFetch);
						Logger.debug("Count of WebSEAL logs file listing: " + webSealLogzToFetch.length);
						
						Logger.debug("WebSeal logs to fetch: " + Arrays.toString(webSealLogzToFetch));
						tmp = getWebSealLogs(host, webSealLogzToFetch, LogFile.parseEnvironment("specified"), newKey, logsManifestFile, wait);
						Logger.debug("Result concerning logs from WebSEAL with date range: " + tmp);
						returnMap = evaluateResult("Key", "Message", "Re: " + logToFetch + " from " + host + ": " + tmp + System.lineSeparator(), returnMap);
					} // end if (webSealLogsMap.size() > 0) {
					
					if (sdf.parse(toDate).compareTo(sdf.parse(sdf.format(new Date()))) == 0) {
						Logger.debug("Today's date is included in the request...");
						
						if (webSealLogsMap.size() > 0) {

							nologsrequested = false;
							tmp = getWebSealLogs(host, logsToFetch, LogFile.parseEnvironment("latest"), newKey, logsManifestFile, wait);
							Logger.debug("Result concerning logs from WebSEAL: " + tmp);
							returnMap = evaluateResult("Key", "Message", "Re: " + logToFetch + " from " + host + ": " + tmp + System.lineSeparator(), returnMap);
						} // if (webSealLogsMap.size() > 0) {

					} // end if (sdf.parse(toDate).compareTo(sdf.parse(sdf.format(new Date()))) == 0) {
				} else if (isamAppLogsList.contains(logToFetch)) { // for ISAM Application runtime logs
					Logger.debug("Request includes log type from ISAM, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
					HashMap<String, String> isamAppLogsMap = new HashMap<String, String>();
					addIsamAppLogsToFetchBaseFilenamesToHashMap(logsToFetch, isamAppLogsMap);
					
					if (isamAppLogsMap.size() > 0) {
						nologsrequested = false;

						Logger.debug("Size of ISAM App logs map: " + isamAppLogsMap.size());
						String[] isamAppLogsToFetchWithDates = appendDatesToLogFilenamesAsStringArray(isamAppLogsMap, dateRange);
						if (isamAppLogsToFetchWithDates.length > 0) {
							Logger.debug("ISAM App log files to fetch with dates: " + Arrays.toString(isamAppLogsToFetchWithDates));
						}
						JSONArray isamAppLogsListing = (JSONArray) getIsamAppLogsListing(host, isamAppLogsToFetchWithDates);
						ArrayList<String> isamAppLogsWithDates = processLogsToFetch(isamAppLogsListing, isamAppLogsToFetchWithDates);
						String[] isamAppLogzToFetch = new String[isamAppLogsWithDates.size()];
						isamAppLogsWithDates.toArray(isamAppLogzToFetch);
						Logger.debug("Count of ISAM App logs file listing: " + isamAppLogzToFetch.length);
					
						Logger.debug("ISAM application logs to fetch: " + Arrays.toString(isamAppLogzToFetch));
						tmp = getIsamAppLogs(host, isamAppLogzToFetch, LogFile.parseEnvironment("specified"), newKey, logsManifestFile, wait);
						Logger.debug("Result concerning logs from ISAM with date range: " + tmp);
						returnMap = evaluateResult("Key", "Message", "Re: " + logToFetch + " from " + host + ": " + tmp + System.lineSeparator(), returnMap);
						
					} // end if (isamAppLogsMap.size() > 0) {
					
					if (sdf.parse(toDate).compareTo(sdf.parse(sdf.format(new Date()))) == 0) {
						Logger.debug("Today's date is included in the request...");
						
						if (isamAppLogsMap.size() > 0) {
							nologsrequested = false;				
							tmp = getIsamAppLogs(host, logsToFetch, LogFile.parseEnvironment("latest"), newKey, logsManifestFile, wait);
							Logger.debug("Result concerning logs from ISAM: " + tmp);
							returnMap = evaluateResult("Key", "Message", "Re: " + logToFetch + " from " + host + ": " + tmp + System.lineSeparator(), returnMap);
						} // end if (isamAppLogsMap.size() > 0) {

					} // end if (sdf.parse(toDate).compareTo(sdf.parse(sdf.format(new Date()))) == 0) {
				} else if (isamFedLogsList.contains(logToFetch)) { // for ISAM Federation runtime logs
					Logger.debug("Request includes log type from ISAM Fed, so fetching from properties: " + ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
					
					HashMap<String, String> isamFedLogsMap = new HashMap<String, String>();
					isamFedLogsMap = addIsamFedLogsToFetchBaseFilenamesToHashMap(logsToFetch, isamFedLogsMap);
					
					if (isamFedLogsMap.size() > 0) {
						nologsrequested = false;

						Logger.debug("Size of ISAM Fed logs map: " + isamFedLogsMap.size());
						Logger.debug("Contents of ISAM Fed logs map: " + isamFedLogsMap.toString());
						String[] isamFedLogsToFetchWithDates = appendDatesToLogFilenamesAsStringArray(isamFedLogsMap, dateRange);
						if (isamFedLogsToFetchWithDates.length > 0) {
							Logger.debug("ISAM Fed log files to fetch with dates: " + Arrays.toString(isamFedLogsToFetchWithDates));
						}
						JSONArray isamFedLogsListing = (JSONArray) getIsamFedLogsListing(host, isamFedLogsToFetchWithDates);
						ArrayList<String> isamFedLogsWithDates = processLogsToFetch(isamFedLogsListing, isamFedLogsToFetchWithDates);
						String[] isamFedLogzToFetch = new String[isamFedLogsWithDates.size()];
						isamFedLogsWithDates.toArray(isamFedLogzToFetch);
						Logger.debug("Count of ISAM Fed logs file listing: " + isamFedLogzToFetch.length);
					
						Logger.debug("ISAM Federation logs to fetch: " + Arrays.toString(isamFedLogzToFetch));
						tmp = getIsamFedLogs(host, isamFedLogzToFetch, LogFile.parseEnvironment("specified"), newKey, logsManifestFile, wait);
						Logger.debug("Result concerning logs from ISAM Fed with date range: " + tmp);
						returnMap = evaluateResult("Key", "Message", "Re: " + logToFetch + " from " + host + ": " + tmp + System.lineSeparator(), returnMap);
						
					} // end if (isamFedLogsMap.size() > 0) {
					
					if (sdf.parse(toDate).compareTo(sdf.parse(sdf.format(new Date()))) == 0) {
						Logger.debug("Today's date is included in the request...");

						if (isamFedLogsMap.size() > 0) {
							nologsrequested = false;				
							tmp = getIsamFedLogs(host, logsToFetch, LogFile.parseEnvironment("latest"), newKey, logsManifestFile, wait);
							Logger.debug("Result concerning logs from ISAM: " + tmp);
							returnMap = evaluateResult("Key", "Message", "Re: " + logToFetch + " from " + host + ": " + tmp + System.lineSeparator(), returnMap);
						} // end if (isamFedLogsMap.size() > 0) {
					} // end if (sdf.parse(toDate).compareTo(sdf.parse(sdf.format(new Date()))) == 0) {
					
				} // end if-else based on log type
				
				Logger.debug("Return Map Values: " + returnMap.toString());

			} // end for (String logToFetch : logsToFetch) {
			
			if (nologsrequested) {
				returnMap.put("Message", "No logs are to be downloaded or searched based on your criteria. Please try again.");
			} else {
				FileUtil.touchFile(logsManifestProcessingFile);
				if (writeToNotifyFile) {
					String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
					Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);
							
					writeToNotifyManifestFile(newKey, email, logsNotifyManifestFile);
				}

			}
			
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		}
		
		return mapToJSONArray(returnMap);
		
	} // end method public String getLogs(String host, String[] logsToFetch, String fromDate, String toDate, String sessionID, String email, boolean wait)
	

	
	public JSONArray getLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email, boolean wait) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogs(String[] logsToFetch, String fromDate, String toDate, String sessionID, String email, boolean wait)");
		
		
		JSONArray jsonArray = new JSONArray();


		HashMap<String, String> requestedLogsAndHostsMap = new HashMap<String, String>(logsToFetch.length);
		for (String logToFetch : logsToFetch) {
			if (isamWebSealLogsList.contains(logToFetch)) {
				Logger.debug("Request includes log type from WebSEAL, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
//				requestedLogsAndHostsMap.put(logToFetch, (PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase())));
				requestedLogsAndHostsMap.put(logToFetch, getPropertyByLogToFetchType(logToFetch));
			} else if (isamAppLogsList.contains(logToFetch)) {
				Logger.debug("Request includes log type from ISAM, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
//				requestedLogsAndHostsMap.put(logToFetch, (PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase())));
				requestedLogsAndHostsMap.put(logToFetch, getPropertyByLogToFetchType(logToFetch));
			} else if (isamFedLogsList.contains(logToFetch)) {
				Logger.debug("Request includes log type from ISAM Fed, so fetching from properties: " + ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
//				requestedLogsAndHostsMap.put(logToFetch, (PropertiesManager.getApplicationProperty(ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase())));
				requestedLogsAndHostsMap.put(logToFetch, getPropertyByLogToFetchType(logToFetch));
			}

		}
		
		Logger.debug("Map of requested logs and hosts: " + requestedLogsAndHostsMap.toString());
		
		for (String logToFetch : logsToFetch) {
			
			String hostsFromProp = requestedLogsAndHostsMap.get(logToFetch);
			Logger.debug("Hosts from properties file: " + hostsFromProp);
			String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
			
			for (String host : hosts) {
				JSONObject jsonObject = new JSONObject();
				jsonObject.put("Host", host);
				jsonObject.put("Report", getLogs(host, new String[] {logToFetch}, fromDate, toDate, newKey, email, wait, false));
				jsonArray.add(jsonObject);
			}
			
			String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
			Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);
	
			writeToNotifyManifestFile(newKey, email, logsNotifyManifestFile);
			
		} // for (String logToFetch : logsToFetch) {
		
		return jsonArray;
		
	}
	

	private String getWebSealLogs(String host, String[] logsToFetch, Enum<LogFile> allOrLatestLogFiles, String newKey, String logsManifestFile, boolean wait) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getWebSealLogs(String[] logsToFetch, Enum<LogFile> allOrLatestLogFiles, String sessionID, boolean wait)");

		boolean latestLogs = (allOrLatestLogFiles.compareTo(LogFile.LATEST) == 0)?true:false;
		boolean allLogs = (allOrLatestLogFiles.compareTo(LogFile.ALL) == 0)?true:false;
		boolean specifiedLogs = (allOrLatestLogFiles.compareTo(LogFile.SPECIFIED) == 0)?true:false;
		
	
		String webSealLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_WEBSEAL_LOGFILES_PROP);
		Logger.debug("WEBSEAL REST URL for instance's log files from properties file: " + webSealLogFilesURL);
	
		String domainFromProp = PropertiesManager.getApplicationProperty(ISAM_DOMAIN_PROP_PREFIX + environment.name().toUpperCase());
		Logger.debug("Domain from properties file: " + domainFromProp);
		
		Logger.debug("Logs manifest file from properties file: " + logsManifestFile);
		
		String logFileBasePath = PropertiesManager.getApplicationProperty(ISAM_WEBSEAL_LOGS_LOCAL_PATH_PROP);
		Logger.debug("Log files base path: " + logFileBasePath);

		HashMap<String, String> logzToFetch = new HashMap<String, String>();
		
		String returnString = "";
		
		if (latestLogs) {
			Logger.debug("Latest WebSEAL logs requested");
			addWebSealLogsToFetchBaseFilenamesToHashMap(logsToFetch, webSealLogFilesURL, domainFromProp, logzToFetch);
		} else if (specifiedLogs) {
			Logger.debug("Specified WebSEAL logs requested; count of " + logsToFetch.length);
			for (String logToFetch : logsToFetch) { // for loop over log files to fetch
				String newHostUrl = host + webSealLogFilesURL + "/" + domainFromProp;
				Logger.debug("Host URL is now: " +  newHostUrl + "/" + logToFetch);
				logzToFetch.put(newHostUrl + "/" + logToFetch, logToFetch);
			} // for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
		} // end if (latestLogs)
		
		if (logzToFetch.isEmpty()) {
			returnString = "There are no WebSEAL logs based on search criteria to fetch from " + host;
		} else if (writeToLogsManifestFile(host, logzToFetch, newKey, logFileBasePath, logsManifestFile)) {
			returnString = "Key: " + newKey;
		}
		
		return returnString;
	}
	
	
	
	private String getIsamAppLogs(String host, String[] logsToFetch, Enum<LogFile> allOrLatestLogFiles, String newKey, String logsManifestFile, boolean wait) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getIsamAppLogs(String host, String[] logsToFetch, Enum<LogFile> allOrLatestLogFiles, String sessionID, boolean wait)");

		boolean latestLogs = (allOrLatestLogFiles.compareTo(LogFile.LATEST) == 0)?true:false;
		boolean allLogs = (allOrLatestLogFiles.compareTo(LogFile.ALL) == 0)?true:false;
		boolean specifiedLogs = (allOrLatestLogFiles.compareTo(LogFile.SPECIFIED) == 0)?true:false;
		
		String isamAppLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_APP_LOGFILES_PROP);
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + isamAppLogFilesURL);
	
		Logger.debug("Logs manifest file from properties file: " + logsManifestFile);
		
		String logFileBasePath = PropertiesManager.getApplicationProperty(ISAM_APP_LOGS_LOCAL_PATH_PROP);
		Logger.debug("Log files base path: " + logFileBasePath);
		
		HashMap<String, String> logzToFetch = new HashMap<String, String>();
		
		if (latestLogs) {
			Logger.debug("Latest ISAM Application logs requested");
			addIsamAppLogsToFetchBaseFilenamesToHashMap(logsToFetch, isamAppLogFilesURL, logzToFetch);
		} else if (specifiedLogs) {
			Logger.debug("Specified ISAM Application logs requested; count of " + logsToFetch.length);
			for (String logToFetch : logsToFetch) { // for loop over log files to fetch
				String newHostUrl = host + isamAppLogFilesURL;
				Logger.debug("Host URL is now: " +  newHostUrl + "/" + logToFetch);
				logzToFetch.put(newHostUrl + "/" + logToFetch, logToFetch);
			} // for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
		} // end if (latestLogs)
		
		String returnString = "";

		if (logzToFetch.isEmpty()) {
			returnString = "There are no ISAM Application logs based on search criteria to fetch from " + host;
		} else if (writeToLogsManifestFile(host, logzToFetch, newKey, logFileBasePath, logsManifestFile)) {
			returnString = newKey;			
		}
		
		return returnString;

	}

	private String getIsamFedLogs(String host, String[] logsToFetch, Enum<LogFile> allOrLatestLogFiles, String newKey, String logsManifestFile, boolean wait) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getIsamFedLogs(String host, String[] logsToFetch, Enum<LogFile> allOrLatestLogFiles, String sessionID, boolean wait)");

		boolean latestLogs = (allOrLatestLogFiles.compareTo(LogFile.LATEST) == 0)?true:false;
		boolean allLogs = (allOrLatestLogFiles.compareTo(LogFile.ALL) == 0)?true:false;
		boolean specifiedLogs = (allOrLatestLogFiles.compareTo(LogFile.SPECIFIED) == 0)?true:false;
		
		String isamFedLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_FED_LOGFILES_PROP);
		Logger.debug("ISAM FED REST URL for instance's log files from properties file: " + isamFedLogFilesURL);
	
		Logger.debug("Logs manifest file from properties file: " + logsManifestFile);
		
		String logFileBasePath = PropertiesManager.getApplicationProperty(ISAM_FED_LOGS_LOCAL_PATH_PROP);
		Logger.debug("Log files base path: " + logFileBasePath);
		
		HashMap<String, String> logzToFetch = new HashMap<String, String>();
		
		if (latestLogs) {
			Logger.debug("Latest ISAM Federation logs requested");
			addIsamFedLogsToFetchBaseFilenamesToHashMap(logsToFetch, isamFedLogFilesURL, logzToFetch);
		} else if (specifiedLogs) {
			Logger.debug("Specified ISAM Federation logs requested; count of " + logsToFetch.length);
			for (String logToFetch : logsToFetch) { // for loop over log files to fetch
				String newHostUrl = host + isamFedLogFilesURL;
				Logger.debug("Host URL is now: " +  newHostUrl + "/" + logToFetch);
				logzToFetch.put(newHostUrl + "/" + logToFetch, logToFetch);
			} // for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
		} // end if (latestLogs)
		
		String returnString = "";

		if (logzToFetch.isEmpty()) {
			returnString = "There are no ISAM Federation logs based on search criteria to fetch from " + host;
		} else if (writeToLogsManifestFile(host, logzToFetch, newKey, logFileBasePath, logsManifestFile)) {
			returnString = newKey;			
		}
		
		return returnString;

	}
	

	
	@SuppressWarnings("unchecked")
	public Object getLogs(String downloadedLogsKey, String environment) throws FileNotFoundException, Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".getLogs(String downloadedLogsKey, boolean wait)");
		
		Logger.debug("Key: " + downloadedLogsKey);
		Logger.debug("Environment: " + downloadedLogsKey);
		
		String logsManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_FETCH_MF_FILE_PROP);
		Logger.debug("Log files manifest: " + logsManifestFile);
				
		CommandMap commandMap = new CommandMap();
		
		JSONArray jsonArray = new JSONArray();
		
		Object returnObj = null;
		
		try {
			
			String logsFetchCmd = appProps.getProperty(SCRIPT_LOGS_FETCHER_PROP) 
							+ " " + downloadedLogsKey + " " + Environment.parseEnvironment(environment).name().toLowerCase();
			
			String logFileBasePath = PropertiesManager.getApplicationProperty(W3ID_LOGS_LOCAL_PATH_PROP);
			Logger.debug("Log files base path: " + logFileBasePath);


			String zipFileExpected = (logFileBasePath + "/" + downloadedLogsKey + ".zip");
			Logger.debug("Checking if " + zipFileExpected + " is ready");
			
			
			Logger.debug("Adding command to CommandMap object: " + logsFetchCmd);
			commandMap.setCommand(logsFetchCmd);
			
			Logger.debug("Executing command on OS");
			commandMap = CliUtil.exec(commandMap, true);
			
			String rc = commandMap.getCommandResultCode();
			Logger.debug("Command ResultCode: " + rc);
			
			String resultMsg = commandMap.getCommandResultMessage();
			Logger.debug("Command ResultMessage: " + resultMsg);
			
			File zf = new File(zipFileExpected);
			if (zf.exists()) {
				Logger.debug(zipFileExpected + " exists, so prepareing to return.");
				returnObj = (Object) zf;
			} else {
				Logger.debug("Something went wong when running command: " + logsFetchCmd);
				JSONObject jsonObject = new JSONObject();
				jsonObject.put(JSONUtil.JSON_KEY, downloadedLogsKey);
				jsonObject.put("Message", resultMsg);
				jsonArray.add(jsonObject);
				returnObj = (Object) jsonArray;
			} // ed if-else

		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		} finally {
			commandMap = null;
		}
		
		return returnObj;
		
	} // end method public JSONArray getLogsListing() throws Exception {
	
	
	/**
	 * This overloaded method assumes that only specified logs are requested from a single instances of  
	 * WebSEAL, in order to search them for input string
	 * 
	 * @param host 			Single host from which to download log files
	 * @param logsToFetch 	Array of log files to fetch (full log file names)
	 * @param fromDate 		Start of time frame to filter logs to download; format is YYYYMMDD in Java
	 * @param toDate 		End of time frame to filter logs to download; format is YYYYMMDD in Java
	 * @param newKey 		Unique key by which log files are associated on the backend
	 * @param email 		Email address to which notifications that log files have been downloaded will be sent
	 * @param wait 			True or False value to direct this method to wait for completion (i.e., synchronous); true by default
	 */
	@SuppressWarnings("unchecked")
	public JSONArray searchLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey, String email, String searchString, boolean wait, boolean writeToNotifyFile) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".searchLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey, String email, String searchString, boolean wait)");
		
		Logger.debug("Log file to fetch: " + Arrays.toString(logsToFetch));
		Logger.debug("From date: " + fromDate + "\"");
		Logger.debug("To date: " + toDate + "\"");
		Logger.debug("Wait for fetch? " + !wait);
		
		String searchManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_SEARCH_MF_FILE_PROP);
		Logger.debug("Search manifest file from properties file: " + searchManifestFile);

		Logger.debug("Logs fitting time frame requested, so fetching logs listing from host: " + host);
		
		JSONArray jsonArray = getLogs(host, logsToFetch, fromDate, toDate, newKey, email, wait, false);
		
//		getLogs(host, logsToFetch, fromDate, toDate, newKey, email, wait);

		Logger.debug("Searching for \"" + searchString + "\"");
		StringBuilder sb = new StringBuilder();
		sb.append(newKey + "," + searchString);
		if (!FileUtil.isContentInFile(searchManifestFile, sb.toString())) {
			FileUtil.writeToFile(searchManifestFile, sb.toString() + System.lineSeparator(), false);
			if (writeToNotifyFile) {
				String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
				Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);
						
				writeToNotifyManifestFile(newKey, email, logsNotifyManifestFile);
			}

		}
		
		return jsonArray;
		
	} // end method public String getLogs(String host, String[] logsToFetch, String fromDate, String toDate, String sessionID, String email, boolean wait)
	

	@SuppressWarnings("unchecked")
	public JSONArray searchLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email, String searchString, boolean wait) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".searchLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email, String searchString, boolean wait)");
		
		String hostsFromProp = PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
		Logger.debug("Hosts from properties file: " + hostsFromProp);
		String[] hosts = PropertiesManager.parseProps(hostsFromProp, ISAM_HOSTS_PROP_DELIM);
		
		HashSet<String> keys = new HashSet<String>();
		JSONArray jsonArray = new JSONArray();

		for (String host : hosts) {
			JSONObject jsonObject = new JSONObject();
			jsonObject.put("Host", host);
			jsonObject.put("Report", searchLogs(host, logsToFetch, fromDate, toDate, newKey, email, searchString, wait, false));
			jsonArray.add(jsonObject);
		}
		
		Logger.debug("Keys: " + keys.toString());
		
		String logsNotifyManifestFile = PropertiesManager.getApplicationProperty(W3ID_LOGS_NOTIFICATION_MF_FILE_PROP);
		Logger.debug("Logs notification manifest file from properties file: " + logsNotifyManifestFile);
					
		writeToNotifyManifestFile(newKey, email, logsNotifyManifestFile);

		return jsonArray;
		
	}
	
	
	
	@SuppressWarnings("unchecked")
	private JSONArray processLogsListingJSONStringIntoJSONArray(String jsonString) throws ParseException {
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

	private String generateLine(String[] args) {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".generateLine(String[] args)");
		
		StringBuilder sb = new StringBuilder();
		
		for (int i = 0; i < args.length; i++) {
			sb.append(args[i]);
			if ((i+1) < args.length) sb.append(",");
		}
		
		String line = sb.toString();
		Logger.debug("Line: " + line);
		
		return line; 
	}
	
	private void initWebSealLogsProps() {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".initWebSealLogs()");

		if (isamWebSealLogsList == null) isamWebSealLogsList = new ArrayList<String>();
		initLogsProps(isamWebSealLogsList, ISAM_WEBSEAL_LOGS_PROP);
				
		if (isamWebSealLogsSwitchKeys == null) isamWebSealLogsSwitchKeys = new ArrayList<String>();
		if (isamWebSealLogsSwitchKeysMap == null) isamWebSealLogsSwitchKeysMap = new HashMap<String, String>();
		
		try {
			initLogsProps(isamWebSealLogsSwitchKeys, ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP);
			
			for (Iterator<String> iterator = isamWebSealLogsSwitchKeys.iterator(); iterator.hasNext();) {
				String switchKey = iterator.next();
				
				Logger.debug("Switch key: " + switchKey);
				
				String switchKeyProp = "ISAM_" + PropertiesManager.getApplicationProperty(ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP).substring(
						  PropertiesManager.getApplicationProperty(ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP).indexOf(ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP_PREFIX)+1
						, PropertiesManager.getApplicationProperty(ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP).indexOf(ISAM_WEBSEAL_LOGS_SWITCH_KEYS_PROP_SUFFIX));
				
				Logger.debug("Switch key prop: " + switchKeyProp);
				
				isamWebSealLogsSwitchKeysMap.put(switchKey, switchKeyProp);
			}
		} catch (Exception e) {
			Logger.debug("Caught exception: " + e.getMessage());
		}
		

		
	}
	
	private void initLogsProps(ArrayList<String> propList, String prop) {
		String logsProp = PropertiesManager.getApplicationProperty(prop);
		Logger.debug("Property \"" + prop + "\" has value: " + logsProp);
		
		StringTokenizer st = new StringTokenizer(logsProp, ISAM_HOSTS_PROP_DELIM);
		while (st.hasMoreTokens()) {
			String propVal = st.nextToken();
			Logger.debug("Detokenized property: " + propVal);
			propList.add(propVal);
		}		
	}

	private void initIsamAppLogsProps() {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".initIsamAppLogsProps()");

		if (isamAppLogsList == null) isamAppLogsList = new ArrayList<String>();
		initLogsProps(isamAppLogsList, ISAM_APP_LOGS_PROP);
		
		if (isamAppLogsSwitchKeys == null) isamAppLogsSwitchKeys = new ArrayList<String>();
		if (isamAppLogsSwitchKeysMap == null) isamAppLogsSwitchKeysMap = new HashMap<String, String>();
		
		try {
			initLogsProps(isamAppLogsSwitchKeys, ISAM_APP_LOGS_SWITCH_KEYS_PROP);
			Logger.debug("Size of isamAppLogsSwitchKeys is " + isamAppLogsSwitchKeys.size());

			for (Iterator<String> iterator = isamAppLogsSwitchKeys.iterator(); iterator.hasNext();) {
				String switchKey = (String) iterator.next();
				
				Logger.debug("Switch key: " + switchKey);
				
				String switchKeyProp = "ISAM_" + PropertiesManager.getApplicationProperty(ISAM_APP_LOGS_SWITCH_KEYS_PROP).substring(
						  PropertiesManager.getApplicationProperty(ISAM_APP_LOGS_SWITCH_KEYS_PROP).indexOf(ISAM_APP_LOGS_SWITCH_KEYS_PROP_PREFIX)+1
						, PropertiesManager.getApplicationProperty(ISAM_APP_LOGS_SWITCH_KEYS_PROP).indexOf(ISAM_APP_LOGS_SWITCH_KEYS_PROP_SUFFIX));
				
				Logger.debug("Switch key prop: " + switchKeyProp);
				
				isamAppLogsSwitchKeysMap.put(switchKey, switchKeyProp);
			}
			
			Logger.debug("Size of isamAppLogsSwitchKeysMap is " + isamAppLogsSwitchKeysMap.size());

		} catch (Exception e) {
			Logger.debug("Caught exception: " + e.getMessage());
		}
		

	}
	
	
	private void initIsamFedLogsProps() {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".initIsamFedLogsProps()");

		if (isamFedLogsList == null) isamFedLogsList = new ArrayList<String>();
		initLogsProps(isamFedLogsList, ISAM_FED_LOGS_PROP);
		
		if (isamFedLogsSwitchKeys == null) isamFedLogsSwitchKeys = new ArrayList<String>();
		if (isamFedLogsSwitchKeysMap == null) isamFedLogsSwitchKeysMap = new HashMap<String, String>();
		
		try {
//			initLogsProps(isamFedLogsSwitchKeys, ISAM_FED_LOGS_SWITCH_KEYS_PROP);
//			Logger.debug("Size of isamFedLogsSwitchKeys is " + isamFedLogsSwitchKeys.size());
//
//			for (Iterator<String> iterator = isamFedLogsSwitchKeys.iterator(); iterator.hasNext();) {
//				String switchKey = (String) iterator.next();
//				
//				Logger.debug("Switch key: " + switchKey);
//				
//				String switchKeyProp = "ISAM_" + PropertiesManager.getApplicationProperty(ISAM_FED_LOGS_SWITCH_KEYS_PROP).substring(
//						  PropertiesManager.getApplicationProperty(ISAM_FED_LOGS_SWITCH_KEYS_PROP).indexOf(ISAM_FED_LOGS_SWITCH_KEYS_PROP_PREFIX)+1
//						, PropertiesManager.getApplicationProperty(ISAM_FED_LOGS_SWITCH_KEYS_PROP).indexOf(ISAM_FED_LOGS_SWITCH_KEYS_PROP_SUFFIX));
//				
//				Logger.debug("Switch key prop: " + switchKeyProp);
//				
//				isamAppLogsSwitchKeysMap.put(switchKey, switchKeyProp);
//			}
			
			Logger.debug("Size of isamAppLogsSwitchKeysMap is " + isamAppLogsSwitchKeysMap.size());

		} catch (Exception e) {
			Logger.debug("Caught exception: " + e.getMessage());
		}
		

	}
	
	private boolean writeToLogsManifestFile(String host, HashMap<String, String> logzToFetch, String newKey, String logFileBasePath, String logsManifestFile) throws IOException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".writeToLogsManifestFile(String host, HashMap<String, String> logzToFetch, String newKey, String logFileBasePath, String logsManifestFile)");

		StringBuilder sb = new StringBuilder();
		
		Set<String> logzToFetchKeys = logzToFetch.keySet();
		Logger.debug("Expecting to fetch " + logzToFetch.size() + " number of logs from host " + host);
		
		for (Iterator<String> iterator = logzToFetchKeys.iterator(); iterator.hasNext();) {
			String hostUrl = iterator.next();
			Logger.debug("Host URL: " + hostUrl);
			String logFile = logzToFetch.get(hostUrl);
			Logger.debug("Log file to fetch: " + logFile);
			String mfLine = generateLine(new String[]{newKey, hostUrl, "TIME", (logFileBasePath + "/" + HttpServletUtil.parseHostNameFromURL(host) + "/" + logFile)});
			Logger.debug("Line for log file manifest: " + mfLine);
			sb.append(mfLine);
			sb.append(System.lineSeparator());	
		}

		Logger.debug("Contents of Fetch Log Files Manifest: " + sb.toString());			
		Logger.debug("Fetch Log Files Manifest Filename: " + logsManifestFile);
		if (!FileUtil.writeToFile(logsManifestFile, sb.toString(), false)) {
			String msg = "Failed to write logs fetch manifest";
			Logger.debug(msg);
			throw new IOException(msg);
		}
		
		File testFile = new File(logsManifestFile);
		if (!testFile.exists()) throw new FileNotFoundException(logsManifestFile + " did not get created successfully.");
		return testFile.exists();
		
	}

	private boolean writeToNotifyManifestFile(String newKey, String email, String logsManifestFile) throws IOException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".writeToNotifyManifestFile(String newKey, String email, String logsManifestFile)");

		String mfLine = generateLine(new String[] {newKey, email}) + System.lineSeparator();
		
		Logger.debug("Line for log file manifest: " + mfLine);

		Logger.debug("Contents of Fetch Log Files Manifest: " + mfLine);			
		Logger.debug("Fetch Log Files Manifest Filename: " + logsManifestFile);
		if (!FileUtil.writeToFile(logsManifestFile, mfLine, false)) {
			String msg = "Failed to write logs fetch manifest";
			Logger.debug(msg);
			throw new IOException(msg);
		}
		
		File testFile = new File(logsManifestFile);
		if (!testFile.exists()) throw new FileNotFoundException(logsManifestFile + " did not get created successfully.");
		return testFile.exists();
		
	}


	
	private String[] getDateRange(String fromDate, String toDate, SimpleDateFormat sdf) throws java.text.ParseException {
		
		Date from_date = sdf.parse(fromDate);
		Date to_date = sdf.parse(toDate);
		
		Calendar calFrom = Calendar.getInstance();
		calFrom.setTime(from_date);

		Calendar calTo = Calendar.getInstance();
		calTo.setTime(to_date);
		
		LocalDate fDate = LocalDate.of(calFrom.get(Calendar.YEAR), calFrom.get(Calendar.MONTH)+1, calFrom.get(Calendar.DAY_OF_MONTH));
		LocalDate tDate = LocalDate.of(calTo.get(Calendar.YEAR), calTo.get(Calendar.MONTH)+1, calTo.get(Calendar.DAY_OF_MONTH));
		LocalDate incDate = LocalDate.from(fDate);

		Logger.debug("From date is: " + fDate.toString());
		Logger.debug("To date is: " + tDate.toString());

		long daysDiff = incDate.until(tDate, ChronoUnit.DAYS);
		Logger.debug("The difference of " + ChronoUnit.DAYS.name().toLowerCase() + " between " + fromDate + " and " + toDate + " is: " + daysDiff);
		
		String[] dateRange = new String[new Long(daysDiff).intValue() + 1];
		dateRange[0] = fDate.toString();
		Logger.debug("Date range[0]: " + dateRange[0]);
		
		if (daysDiff > 0) {
			for (int i = 1; i < dateRange.length; i++) {
				incDate = incDate.plusDays(1);
				dateRange[i] = incDate.toString();
				Logger.debug("Date range[" + i + "]: " + dateRange[i]);
								
			}
		}		

		return dateRange;

	}
	
	private ArrayList<String> processLogsToFetch(JSONArray logsListing, String[] logzToFetch) {
		ArrayList<String> logzToFetchList = new ArrayList<String>();
		for (int j = 0; j < logsListing.size(); j++) {
			JSONObject jsonObject = (JSONObject) logsListing.get(j);
			Logger.debug("Json Object in String: " + jsonObject.toJSONString());
			if (!jsonObject.containsKey("Error")) {
				JSONArray logsArray = (JSONArray) jsonObject.get(JSONUtil.JSON_KEY_LOGS);
				for (Object obj : logsArray) {
					JSONObject jObject = (JSONObject) obj;
					String logFile = jObject.get(JSONUtil.JSON_KEY_FILE).toString();
					Logger.debug("Evaluating log file: \"" + logFile + "\"");
					for (int k = 0; k < logzToFetch.length; k++) {
						Logger.debug("Does log file \"" + logFile + "\" start with \"" + logzToFetch[k] + "\"?");
						if (logFile.toLowerCase().startsWith(logzToFetch[k].toLowerCase())) {
							Logger.debug("Matching log file found: " + logFile);
							logzToFetchList.add(logFile);
						} // end if (logFile.toLowerCase().startsWith(logzToFetch[k]))
					} // end for (int k = 0; k < logzToFetch.length; k++)
				} // end for (Object obj : logsArray)
			} // if (!jsonObject.containsKey("Error")) {
		} // end for (int j = 0; j < webSealLogsListing.size(); j++)
		
		return logzToFetchList;
		
	}
	
	private void addWebSealLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, String webSealLogFilesURL, String domainFromProp, HashMap<String, String> logzToFetch) {
		
		for (int i = 0; i < logsToFetch.length; i++) { // for loop over log files to fetch
			Logger.debug("Examining " + logsToFetch[i]);
			for (int j = 0; j < isamWebSealLogsList.size(); j++) { // for loop over list of WebSEAL logs list supported to fetch
				Logger.debug("Evaluating " + logsToFetch[i] + " against " + isamWebSealLogsList.get(j));
				if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase())) { //if check to determine if latest logs requested are supported
					String propValue = "";
					try {
						propValue = PropertiesManager.getApplicationProperty(ISAM_WEBSEAL_LOGS_PROP + "_" + isamWebSealLogsList.get(j).trim().toUpperCase());
					} catch(Exception ignore) {}
					if (!propValue.equals("")) {
						propValue = buildWebSealURL(propValue, webSealLogFilesURL, domainFromProp);
						Logger.debug("Property \"" + (ISAM_WEBSEAL_LOGS_PROP + "_" + isamWebSealLogsList.get(j).toUpperCase()) + "\" has value: " + propValue);
						String newHostUrl = host + webSealLogFilesURL + "/" + domainFromProp;
						Logger.debug("Host URL is now: " +  newHostUrl + "/" + propValue);
						logzToFetch.put(newHostUrl + "/" + propValue, propValue);
					} // end if (!propValue.equals(""))						
				} // end if check to determine if latest logs requested are supported; if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase()))
			} // end for loop over list of WebSEAL logs list supported to fetch; for (int j = 0; j < isamWebSealLogsList.size(); j++) 
		} // end for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
	}

	private void addWebSealLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, HashMap<String, String> logzToFetch) {
		
		String webSealLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_WEBSEAL_LOGFILES_PROP);
		Logger.debug("WEBSEAL REST URL for instance's log files from properties file: " + webSealLogFilesURL);
	
		String domainFromProp = PropertiesManager.getApplicationProperty(ISAM_DOMAIN_PROP_PREFIX + environment.name().toUpperCase());
		Logger.debug("Domain from properties file: " + domainFromProp);
		
		
		for (int i = 0; i < logsToFetch.length; i++) { // for loop over log files to fetch
			Logger.debug("Examining " + logsToFetch[i]);
			for (int j = 0; j < isamWebSealLogsList.size(); j++) { // for loop over list of WebSEAL logs list supported to fetch
				Logger.debug("Evaluating " + logsToFetch[i] + " against " + isamWebSealLogsList.get(j));
				if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase())) { //if check to determine if latest logs requested are supported
					String propValue = "";
					try {
						propValue = PropertiesManager.getApplicationProperty(ISAM_WEBSEAL_LOGS_PROP + "_" + isamWebSealLogsList.get(j).trim().toUpperCase());
					} catch(Exception ignore) {}
					if (!propValue.equals("")) {
						propValue = buildWebSealURL(propValue, webSealLogFilesURL, domainFromProp);
						Logger.debug("Property \"" + (ISAM_APP_LOGS_PROP + "_" + isamWebSealLogsList.get(j).toUpperCase()) + "\" has value: " + propValue);
						String newHostUrl = host + webSealLogFilesURL + "/" + domainFromProp;
						Logger.debug("Host URL is now: " +  newHostUrl + "/" + propValue);
						logzToFetch.put(newHostUrl + "/" + propValue, propValue);
					} // end if (!propValue.equals(""))						
				} // end if check to determine if latest logs requested are supported; if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase()))
			} // end for loop over list of WebSEAL logs list supported to fetch; for (int j = 0; j < isamWebSealLogsList.size(); j++) 
		} // end for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
	}
	

	
	private String buildWebSealURL(String propValue, String webSealLogFilesURL, String domainFromProp) {
		for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++) {
			Logger.debug("Checking " + propValue + " for " + isamWebSealLogsSwitchKeys.get(k).trim());
			if (propValue.contains(isamWebSealLogsSwitchKeys.get(k))) {
				String propKey = (isamWebSealLogsSwitchKeysMap.get(isamWebSealLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
				Logger.debug("Property key to be switched on: " + propKey);
				String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
				Logger.debug("Property key to be switched with: " + switchedPropVal);
				String switchedVal = propValue.replaceAll(isamWebSealLogsSwitchKeys.get(k).trim(), switchedPropVal);
				Logger.debug("New property value: " + switchedVal);
				propValue = new String(switchedVal.getBytes());
				switchedVal = "";
			} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
		} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
		
		return propValue;
	}
	
	private  HashMap<String, String> addIsamFedLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, String isamFedLogFilesURL, HashMap<String, String> logzToFetch) {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".addIsamFedLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, String isamFedLogFilesURL, HashMap<String, String> logzToFetch)");
		
		for (int i = 0; i < logsToFetch.length; i++) { // for loop over log files to fetch
			Logger.debug("Examining " + logsToFetch[i]);
			for (int j = 0; j < isamFedLogsList.size(); j++) { // for loop over list of WebSEAL logs list supported to fetch
				Logger.debug("Evaluating " + logsToFetch[i] + " against " + isamFedLogsList.get(j));
				if (logsToFetch[i].trim().toLowerCase().equals(isamFedLogsList.get(j).trim().toLowerCase())) { //if check to determine if latest logs requested are supported
					String propValue = "";
					try {
						propValue = PropertiesManager.getApplicationProperty(ISAM_FED_LOGS_PROP + "_" + isamFedLogsList.get(j).trim().toUpperCase());
					} catch(Exception ignore) {}
					if (!propValue.equals("")) {
//						for (int k = 0; k < isamAppLogsSwitchKeys.size(); k++) {
//							Logger.debug("Checking " + propValue + " for " + isamAppLogsSwitchKeys.get(k).trim());
//							if (propValue.contains(isamAppLogsSwitchKeys.get(k))) {
//								String propKey = (isamAppLogsSwitchKeysMap.get(isamAppLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
//								Logger.debug("Property key to be switched on: " + propKey);
//								String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
//								Logger.debug("Property key to be switched with: " + switchedPropVal);
//								String switchedVal = propValue.replaceAll(isamAppLogsSwitchKeys.get(k).trim(), switchedPropVal);
//								Logger.debug("New property value: " + switchedVal);
//								propValue = new String(switchedVal.getBytes());
//								switchedVal = "";
//							} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
//						} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
						propValue = buildIsamFedURL(propValue);
						Logger.debug("Property \"" + (ISAM_FED_LOGS_PROP + "_" + isamFedLogsList.get(j).toUpperCase()) + "\" has value: " + propValue);
						String newHostUrl = host + isamFedLogFilesURL + "/" + PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_FED_LOGFILES_APPEND_PROP + "_" + isamFedLogsList.get(j).toUpperCase());
						Logger.debug("Host URL is now: " +  newHostUrl + "/" + propValue);
						logzToFetch.put(newHostUrl + "/" + propValue, propValue);
					} // end if (!propValue.equals(""))						
				} // end if check to determine if latest logs requested are supported; if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase()))
			} // end for loop over list of WebSEAL logs list supported to fetch; for (int j = 0; j < isamWebSealLogsList.size(); j++) 
		} // end for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
		
		return logzToFetch;
	}

	private HashMap<String, String> addIsamFedLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, HashMap<String, String> logzToFetch) {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".addIsamFedLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, HashMap<String, String> logzToFetch)");
		
		String isamFedLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_FED_LOGFILES_PROP);
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + isamFedLogFilesURL);

		
		for (int i = 0; i < logsToFetch.length; i++) { // for loop over log files to fetch
			Logger.debug("Examining " + logsToFetch[i]);
			for (int j = 0; j < isamFedLogsList.size(); j++) { // for loop over list of WebSEAL logs list supported to fetch
				Logger.debug("Evaluating " + logsToFetch[i] + " against " + isamFedLogsList.get(j));
				if (logsToFetch[i].trim().toLowerCase().equals(isamFedLogsList.get(j).trim().toLowerCase())) { //if check to determine if latest logs requested are supported
					String propValue = "";
					try {
						propValue = PropertiesManager.getApplicationProperty(ISAM_FED_LOGS_PROP + "_" + isamFedLogsList.get(j).trim().toUpperCase());
					} catch(Exception ignore) {}
					if (!propValue.equals("")) {
//						for (int k = 0; k < isamAppLogsSwitchKeys.size(); k++) {
//							Logger.debug("Checking " + propValue + " for " + isamAppLogsSwitchKeys.get(k).trim());
//							if (propValue.contains(isamAppLogsSwitchKeys.get(k))) {
//								String propKey = (isamAppLogsSwitchKeysMap.get(isamAppLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
//								Logger.debug("Property key to be switched on: " + propKey);
//								String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
//								Logger.debug("Property key to be switched with: " + switchedPropVal);
//								String switchedVal = propValue.replaceAll(isamAppLogsSwitchKeys.get(k).trim(), switchedPropVal);
//								Logger.debug("New property value: " + switchedVal);
//								propValue = new String(switchedVal.getBytes());
//								switchedVal = "";
//							} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
//						} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
						propValue = buildIsamFedURL(propValue);
						Logger.debug("Property \"" + (ISAM_FED_LOGS_PROP + "_" + isamFedLogsList.get(j).toUpperCase()) + "\" has value: " + propValue);
						String newHostUrl = host + isamFedLogFilesURL + "/" + PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_FED_LOGFILES_APPEND_PROP + "_" + isamFedLogsList.get(j).toUpperCase());
						Logger.debug("Host URL is now: " +  newHostUrl + "/" + propValue);
						logzToFetch.put(newHostUrl + "/" + propValue, propValue);
					} // end if (!propValue.equals(""))						
				} // end if check to determine if latest logs requested are supported; if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase()))
			} // end for loop over list of WebSEAL logs list supported to fetch; for (int j = 0; j < isamWebSealLogsList.size(); j++)
		} // end for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
		
		return logzToFetch;
	}
		
	private String buildIsamFedURL(String propValue) {
		for (int k = 0; k < isamFedLogsSwitchKeys.size(); k++) {
			Logger.debug("Checking " + propValue + " for " + isamFedLogsSwitchKeys.get(k).trim());

			if (propValue.contains(isamFedLogsSwitchKeys.get(k))) {
				String propKey = (isamFedLogsSwitchKeysMap.get(isamFedLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
				Logger.debug("Property key to be switched on: " + propKey);
				String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
				Logger.debug("Property key to be switched with: " + switchedPropVal);
				String switchedVal = propValue.replaceAll(isamFedLogsSwitchKeys.get(k).trim(), switchedPropVal);
				Logger.debug("New property value: " + switchedVal);
				propValue = new String(switchedVal.getBytes());
				switchedVal = "";
			} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
		} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
		
		return propValue;

	}
	
	private void addIsamAppLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, String isamAppLogFilesURL, HashMap<String, String> logzToFetch) {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".addIsamAppLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, String isamAppLogFilesURL, HashMap<String, String> logzToFetch)");
		
		for (int i = 0; i < logsToFetch.length; i++) { // for loop over log files to fetch
			Logger.debug("Examining " + logsToFetch[i]);
			for (int j = 0; j < isamAppLogsList.size(); j++) { // for loop over list of WebSEAL logs list supported to fetch
				Logger.debug("Evaluating " + logsToFetch[i] + " against " + isamAppLogsList.get(j));
				if (logsToFetch[i].trim().toLowerCase().equals(isamAppLogsList.get(j).trim().toLowerCase())) { //if check to determine if latest logs requested are supported
					String propValue = "";
					try {
						propValue = PropertiesManager.getApplicationProperty(ISAM_APP_LOGS_PROP + "_" + isamAppLogsList.get(j).trim().toUpperCase());
					} catch(Exception ignore) {}
					if (!propValue.equals("")) {
						for (int k = 0; k < isamAppLogsSwitchKeys.size(); k++) {
							Logger.debug("Checking " + propValue + " for " + isamAppLogsSwitchKeys.get(k).trim());
							if (propValue.contains(isamAppLogsSwitchKeys.get(k))) {
								String propKey = (isamAppLogsSwitchKeysMap.get(isamAppLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
								Logger.debug("Property key to be switched on: " + propKey);
								String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
								Logger.debug("Property key to be switched with: " + switchedPropVal);
								String switchedVal = propValue.replaceAll(isamAppLogsSwitchKeys.get(k).trim(), switchedPropVal);
								Logger.debug("New property value: " + switchedVal);
								propValue = new String(switchedVal.getBytes());
								switchedVal = "";
							} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
						} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
						propValue = buildIsamAppURL(propValue);
						Logger.debug("Property \"" + (ISAM_APP_LOGS_PROP + "_" + isamAppLogsList.get(j).toUpperCase()) + "\" has value: " + propValue);
						String newHostUrl = host + isamAppLogFilesURL + "/" + PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_APP_LOGFILES_APPEND_PROP + "_" + isamAppLogsList.get(j).toUpperCase());
						Logger.debug("Host URL is now: " +  newHostUrl + "/" + propValue);
						logzToFetch.put(newHostUrl + "/" + propValue, propValue);
					} // end if (!propValue.equals(""))						
				} // end if check to determine if latest logs requested are supported; if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase()))
			} // end for loop over list of WebSEAL logs list supported to fetch; for (int j = 0; j < isamWebSealLogsList.size(); j++) 
		} // end for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
	}

	private void addIsamAppLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, HashMap<String, String> logzToFetch) {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".addIsamAppLogsToFetchBaseFilenamesToHashMap(String[] logsToFetch, HashMap<String, String> logzToFetch)");
		
		String isamAppLogFilesURL = PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_APP_LOGFILES_PROP);
		Logger.debug("ISAM REST URL for instance's log files from properties file: " + isamAppLogFilesURL);

		
		for (int i = 0; i < logsToFetch.length; i++) { // for loop over log files to fetch
			Logger.debug("Examining " + logsToFetch[i]);
			for (int j = 0; j < isamAppLogsList.size(); j++) { // for loop over list of WebSEAL logs list supported to fetch
				Logger.debug("Evaluating " + logsToFetch[i] + " against " + isamAppLogsList.get(j));
				if (logsToFetch[i].trim().toLowerCase().equals(isamAppLogsList.get(j).trim().toLowerCase())) { //if check to determine if latest logs requested are supported
					String propValue = "";
					try {
						propValue = PropertiesManager.getApplicationProperty(ISAM_APP_LOGS_PROP + "_" + isamAppLogsList.get(j).trim().toUpperCase());
					} catch(Exception ignore) {}
					if (!propValue.equals("")) {
						for (int k = 0; k < isamAppLogsSwitchKeys.size(); k++) {
							Logger.debug("Checking " + propValue + " for " + isamAppLogsSwitchKeys.get(k).trim());
							if (propValue.contains(isamAppLogsSwitchKeys.get(k))) {
								String propKey = (isamAppLogsSwitchKeysMap.get(isamAppLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
								Logger.debug("Property key to be switched on: " + propKey);
								String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
								Logger.debug("Property key to be switched with: " + switchedPropVal);
								String switchedVal = propValue.replaceAll(isamAppLogsSwitchKeys.get(k).trim(), switchedPropVal);
								Logger.debug("New property value: " + switchedVal);
								propValue = new String(switchedVal.getBytes());
								switchedVal = "";
							} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
						} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
						propValue = buildIsamAppURL(propValue);
						Logger.debug("Property \"" + (ISAM_APP_LOGS_PROP + "_" + isamAppLogsList.get(j).toUpperCase()) + "\" has value: " + propValue);
						String newHostUrl = host + isamAppLogFilesURL + "/" + PropertiesManager.getApplicationProperty(ISAM_REST_URL_ISAM_APP_LOGFILES_APPEND_PROP + "_" + isamAppLogsList.get(j).toUpperCase());
						Logger.debug("Host URL is now: " +  newHostUrl + "/" + propValue);
						logzToFetch.put(newHostUrl + "/" + propValue, propValue);
					} // end if (!propValue.equals(""))						
				} // end if check to determine if latest logs requested are supported; if (logsToFetch[i].trim().toLowerCase().equals(isamWebSealLogsList.get(j).trim().toLowerCase()))
			} // end for loop over list of WebSEAL logs list supported to fetch; for (int j = 0; j < isamWebSealLogsList.size(); j++) 
		} // end for loop over log files to fetch; for (int i = 0; i < logsToFetch.length; i++)
	}
		
	private String buildIsamAppURL(String propValue) {
		for (int k = 0; k < isamAppLogsSwitchKeys.size(); k++) {
			Logger.debug("Checking " + propValue + " for " + isamAppLogsSwitchKeys.get(k).trim());

			if (propValue.contains(isamAppLogsSwitchKeys.get(k))) {
				String propKey = (isamAppLogsSwitchKeysMap.get(isamAppLogsSwitchKeys.get(k)) + "_" + this.environment.name().toUpperCase());
				Logger.debug("Property key to be switched on: " + propKey);
				String switchedPropVal = PropertiesManager.getApplicationProperty(propKey);
				Logger.debug("Property key to be switched with: " + switchedPropVal);
				String switchedVal = propValue.replaceAll(isamAppLogsSwitchKeys.get(k).trim(), switchedPropVal);
				Logger.debug("New property value: " + switchedVal);
				propValue = new String(switchedVal.getBytes());
				switchedVal = "";
			} // end if (propValue.contains(isamWebSealLogsSwitchKeys.get(k)))
		} // end for (int k = 0; k < isamWebSealLogsSwitchKeys.size(); k++)
		
		return propValue;

	}
	
	private String[] addDateRangeToLogFilesToList(String[] logsToFetch, String[] dateRange) {
		ArrayList<String> logToFetchWithDatesList = new ArrayList<String>();
		
		for (int j = 0; j < logsToFetch.length; j++) {
			for (String date : dateRange) {
				Logger.debug("Log file to search: " + logsToFetch[j] + "." + date);
				logToFetchWithDatesList.add(logsToFetch[j] + "." + date);
			} // end for loop that prepares the partial file name with date(s)
		} // end for
		
		Logger.debug("Logs to fetch with these time-based file names: " + logToFetchWithDatesList.toString());

		String[] logToFetchWithDates = new String[logToFetchWithDatesList.size()];
		logToFetchWithDatesList.toArray(logToFetchWithDates);
		
		return logToFetchWithDates;
	}
	
	private String[] appendDatesToLogFilenamesAsStringArray(HashMap<String, String> map, String[] dateRange) {
		Logger.debug("Hashmap: " + map.toString());
		HashSet<String> set = VectorUtil.extractHashMapStringValuesIntoStringHashSet(map);
		Logger.debug("Hashset: " + set.toString());
		String[] logzToFetch = new String[set.size()];
		set.toArray(logzToFetch);
		Logger.debug("Log files to fetch (before appending date/time: " + Arrays.toString(logzToFetch));
		String[] logsToFetchWithDates = addDateRangeToLogFilesToList(logzToFetch, dateRange);
		Logger.debug("Log files, with date appended, to fetch: " + Arrays.toString(logsToFetchWithDates));
		
		return logsToFetchWithDates;
	}
	
//	private boolean evaluateSuccess(HashMap<String, Boolean> success) {
//		boolean evaluated = false;
//		if (success.containsValue(new Boolean(false))) {
//			String msg = "";
//			Set<String> successKeys = success.keySet();
//			for (String successKey : successKeys) {
//				if (!success.get(successKey).booleanValue()) {
//					msg += successKey + System.lineSeparator();
//				}
//			}
//			
//			throw new ProcessingException("Something went wrong with the following: " + System.lineSeparator() + msg);
//		} else {
//			evaluated = true;
//		}
//		
//		return evaluated;
//		
//	}
	
	private HashMap<String, String> evaluateResult(String searchString, String altString, String resultString, HashMap<String, String> returnMap) {
		if (resultString.contains(searchString)) {
			Logger.debug(searchString + " located, so adding to returnMap");
			returnMap.put(searchString, resultString.substring(resultString.indexOf(searchString) + searchString.length()+1));
		} else {
			Logger.debug(searchString + " not located");
			returnMap.put(altString, resultString);
		}
		
		return returnMap;
	}
	
	@SuppressWarnings("unchecked")
	private JSONArray mapToJSONArray(HashMap<String, String> returnMap) {
		JSONArray jsonArray = new JSONArray();
		
		Set<String> keys = returnMap.keySet();
		for (Iterator<String> iterator = keys.iterator(); iterator.hasNext();) {
			String key = iterator.next();
			
			JSONObject jsonObject = new JSONObject();
			jsonObject.put(key, returnMap.get(key));
			jsonArray.add(jsonObject);
			
		}
		
		
		return jsonArray;
		
	}
	
	private String getPropertyByLogToFetchType(String logToFetch) {
		String property = "";
		
		if (isamWebSealLogsList.contains(logToFetch)) {
			Logger.debug("Request includes log type from WebSEAL, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
			property = PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
		} else if (isamAppLogsList.contains(logToFetch)) {
			Logger.debug("Request includes log type from ISAM, so fetching from properties: " + ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
			property = PropertiesManager.getApplicationProperty(ISAM_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
		} else if (isamFedLogsList.contains(logToFetch)) {
			Logger.debug("Request includes log type from ISAM Fed, so fetching from properties: " + ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
			property = PropertiesManager.getApplicationProperty(ISAM_FED_HOSTS_PROP_PREFIX + environment.name().toUpperCase());
		}

		return property;

	}
	
	
	
}
