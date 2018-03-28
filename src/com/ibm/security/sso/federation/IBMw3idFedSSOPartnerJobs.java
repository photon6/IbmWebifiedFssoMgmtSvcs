package com.ibm.security.sso.federation;

import java.io.File;
import java.io.FileNotFoundException;

/**
 * Back end utility that detects and boards IBM w3id Federation Partner jobs provisioned 
 * by the SSO Self-Service Provisioner utility.
 * 
 * This Java program relies upon script running on the underlying OS this services is running on.
 * 
 * @author rkhanna@us.ibm.com
 * 
 * Change history:
 * --------------------------------------------------------------------------------------------------
 * | VERSION	| DATE			|	CHANGE DESCRIPTION												|
 * --------------------------------------------------------------------------------------------------
 * | 0.1		| 12/06/2016	|	Initial version with Staging and Dev jobs detection and boarding|
 * --------------------------------------------------------------------------------------------------
 * | 0.2		| 12/09/2016	|	Supporting simulated production jobs detection and boarding		|
 * --------------------------------------------------------------------------------------------------
 * | 1.0		| 12/16/2016	|	Supporting production jobs detection and boarding; baselined	|
 * |			|				|	release.														|
 * --------------------------------------------------------------------------------------------------
 * | 1.0.1		| 12/23/2016	|	Added crontab schedule check for boarding jobs in non-Prod 		|
 * |			|				|	environments.													|
 * --------------------------------------------------------------------------------------------------
 * | 1.0.2		| 12/24/2016	|	Fixed issue that disabled prod jobs detection.			 		|
 * --------------------------------------------------------------------------------------------------
 */

import java.io.IOException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.Locale;
import java.util.Properties;
import java.util.Scanner;
import java.util.StringTokenizer;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.core.util.CronExpression;
import org.json.simple.JSONArray;

import com.ibm.security.util.ActivationProperties;
import com.ibm.security.util.CliLinux;
import com.ibm.security.util.CliOS;
import com.ibm.security.util.CliUtil;
import com.ibm.security.util.CommandMap;
import com.ibm.security.util.Environment;
import com.ibm.security.util.FileUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;
import com.ibm.security.util.SysUtil;

public class IBMw3idFedSSOPartnerJobs {
	
	private static Properties appProps;
	private SysUtil sysUtil;
	private String check4jobsCmd;
	private Enum<AuthType> authType;
	private Enum<Environment> environment;
	private boolean remoteHost;
	
//	private File w3idUtilLogFile, w3idOidcPartnerBoardingLogFile, w3idSamlPartnerBoardingLogFile;
	
	public IBMw3idFedSSOPartnerJobs() throws IOException {
		Logger.debug("Inside contructor: " + this.getClass().getName() + "()");
		initialize();
	}
	
	public IBMw3idFedSSOPartnerJobs(String authType, String env) throws IOException {
		Logger.debug("Inside contructor: " + this.getClass().getName() 
				+ "(String authType, String env)");
		
		this.authType = AuthType.parseAuthType(authType);
		Logger.debug("Auth Type is " + this.authType.name());	

		this.environment = Environment.parseEnvironment(env);
		Logger.debug("Environment is " + this.environment.name());	
		
	}
			
	private void initialize() throws IOException {
		Logger.debug("Inside method: " + this.getClass().getName()
				+ ".initialize()"); 
		check4jobsCmd = "";
		sysUtil = new SysUtil();
		
		appProps = PropertiesManager.getApplicationProperties();
		Logger.debug("Size of application properies: " + appProps.keySet().size());

	}

	
	public boolean checkForPendingJobs(String authType, String env, boolean remoteHost) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".checkForPendingJobs(String authType, String env)");
		
		Logger.debug("authType = " + authType);
		Logger.debug("env = " + env);
		boolean success = false;
	
		try {
			
			this.authType = AuthType.parseAuthType(authType);
			Logger.debug("Auth Type is " + this.authType.name());	

			this.environment = Environment.parseEnvironment(env);
			Logger.debug("Environment is " + this.environment.name());	

			success = checkForPendingJobs(remoteHost);
			
		}catch (Exception e) {
			Logger.logToAllLevels(e.getMessage());
			throw e;
		}
		
		return success;
		
	}
	
	public boolean checkForPendingJobs(Enum<AuthType> authType, Enum<Environment> env, boolean remote) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".checkForPendingJobs(Enum<AuthType> authType, Enum<Environment> env)"); 		
		
		this.authType = authType;
		Logger.debug("Auth Type is " + this.authType.name());	

		this.environment = env;
		Logger.debug("Environment is " + this.environment.name());	

		return checkForPendingJobs(remote);
	}
	
	public boolean checkForPendingJobs(boolean remote) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".checkForPendingJobs(boolean remote)");
		
		Logger.debug("Size of application properies: " + appProps.keySet().size());
		
		boolean success = true;
		String resultMessage = new String();
		CommandMap commandMap = new CommandMap();
		
		Logger.debug("authType = " + authType);
		Logger.debug("environment = " + environment);
		Logger.debug("remote = " + remote);
		
		try {		
			if (sysUtil.getOS().equals("Mac OS X")) {
				check4jobsCmd = "ls -lrt"; // local test
				Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_check4PendingJobs"));
				Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_check4PendingJobs"));
			}
			else { // this is assuming deployed on TFIM server host
				if (remote) {
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_check4PendingJobs_remote"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_check4PendingJobs_remote"));
					check4jobsCmd = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_check4PendingJobs_remote"):appProps.getProperty("saml_script_check4PendingJobs_remote"));
				} else {
					
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_check4PendingJobs"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_check4PendingJobs"));
					check4jobsCmd = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_check4PendingJobs"):appProps.getProperty("saml_script_check4PendingJobs"));
				}
			}

			Logger.debug("Check for pending jobs command: " + check4jobsCmd);

			Logger.debug("Adding pending jobs command to CommandMap object");
			commandMap.setCommand(check4jobsCmd);

			Logger.debug("Executing command on OS");
			commandMap = CliUtil.exec(commandMap, true);

			
			if (commandMap.getCommandResultCode().equals("0")) {
				
				resultMessage = commandMap.getCommandResultMessage();
				Logger.debug("ResultMessage");
				Logger.debug("[[" + resultMessage + "]]");				
				
				if (authType.equals(AuthType.SAML2)) { 
					Logger.debug("Checking for result message: " + appProps.getProperty("saml_script_check4PendingJobs_noresultmsg"));
				} else if (authType.equals(AuthType.OIDC)) {
					Logger.debug("Checking for result message: " + appProps.getProperty("oidc_script_check4PendingJobs_noresultmsg"));
				} 
				
				success = (resultMessage.contains(appProps.getProperty("saml_script_check4PendingJobs_noresultmsg")) 
						|| resultMessage.contains(appProps.getProperty("oidc_script_check4PendingJobs_noresultmsg")))?false:true;
				
				Logger.debug("Pending jobs for " + authType.name() + ": " + Boolean.toString(success));
				
				// if there are any pending jobs, check here to see if current time conflicts with the time the script is scheduled to run via contab, 
				// if applicable				
				if (!this.environment.equals(Environment.PROD) & success) {
					Logger.debug("Because pending jobs are found, checking to ensure it is permissable to board these jobs.");
					success = isPermissiableToBoard(false, remote);
				}
				
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
		
		return success;
		
	}
	
	public boolean boardJobs(String authType, String env, boolean async, boolean remote) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".boardJobs(String authType, String env, boolean async)");
		
		Logger.debug("authType = " + authType);
		Logger.debug("env = " + env);
		Logger.debug("async = " + Boolean.toString(async));
		
		boolean success = false;
	
		try {

			this.authType = AuthType.parseAuthType(authType);
			Logger.debug("Auth Type is " + this.authType.name());	

			this.environment = Environment.parseEnvironment(env);
			Logger.debug("Environment is " + this.environment.name());	
			
			success = boardJobs(async, remote);
			
			Logger.debug("Jobs boarded successfullly: " + success);
			
		}catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		}
		
		return success;
		
	}
	
	public boolean boardJobs(boolean async, boolean remote) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".boardJobs(boolean async)");
		
		Logger.debug("Size of application properies: " + appProps.keySet().size());
		
		boolean success = false;
		
		String resultMessage = new String();
		CommandMap commandMap = new CommandMap();
//		CliOS cliOS = new CliLinux(); // refer to IMW-1622

		Logger.debug("async = " + Boolean.toString(async));
		
		String boardJobsCmd = "";

		try {
			Logger.debug("Checking OS: " + sysUtil.getOS());
			if (sysUtil.getOS().equals("Mac OS X")) {
				boardJobsCmd = "/Users/rkhanna/Documents/Misc/test.sh";
							
			}
			else { // this is assuming deployed on TFIM server host
				
				if (remote) {
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_boardJobs_remote"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_boardJobs_remote"));
					boardJobsCmd = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs_remote"):appProps.getProperty("saml_script_boardJobs_remote"));

				} else {
					
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_boardJobs"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_boardJobs"));
					boardJobsCmd = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs"):appProps.getProperty("saml_script_boardJobs"));
				}
			}
			
			if (async)
				boardJobsCmd += " &";

			Logger.debug("Boarding jobs command: " + boardJobsCmd);
			
			commandMap.setCommand(boardJobsCmd);
			
			// It seems to stall out at this point when using 256m JVM HeapSize; will evaluate this for a while
			// refer to IMW-1622
//			commandMap = cliOS.exec(commandMap, !async);
			commandMap = CliUtil.exec(commandMap, !async);
			
			if (!async) {
				
				if (commandMap.getCommandResultCode().equals("0")) {
					
					resultMessage = commandMap.getCommandResultMessage();
					Logger.debug("ResultMessage");
					Logger.debug("[[" + resultMessage + "]]");
					Logger.debug("Looking for " + ((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs_resultmsg"):appProps.getProperty("saml_script_boardJobs_resultmsg")));

					success = (resultMessage.contains("No activation failures"))?true:false;
					
					resultMessage = "";
				}
				
				commandMap.setCommandResultMessage(" ");
				
			}
			
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		} finally {
			resultMessage = null;
			commandMap = null;
		}
		
		return success;	
		
	}

	public boolean getSchedule(String authType, String env, boolean async, boolean remote) throws Exception {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".getSchedule(String authType, String env, boolean async, boolean remote)");
		
		Logger.debug("authType = " + authType);
		Logger.debug("env = " + env);
		Logger.debug("async = " + Boolean.toString(async));
		
		boolean success = false;
	
		try {

			this.authType = AuthType.parseAuthType(authType);
			Logger.debug("Auth Type is " + this.authType.name());	

			this.environment = Environment.parseEnvironment(env);
			Logger.debug("Environment is " + this.environment.name());	
			
			success = isPermissiableToBoard(async, remote);
			
			Logger.debug("Jobs are permissable to board: " + success);
			
		}catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		}
		
		return success;
		
	}
	
	/*
	 * TO-DO: Add remote crontab -l innovation on remote server via SSH for Prod support
	 */
	public boolean isPermissiableToBoard(boolean async, boolean remote) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getSchedule(boolean async, boolean remote)");
		
		Logger.debug("Size of application properies: " + appProps.keySet().size());
		
		boolean success = false;
		
		String resultMessage = new String();
		CommandMap commandMap = new CommandMap();
		CliOS cliOS = new CliLinux(); // refer to IMW-1622
	
		Logger.debug("async = " + Boolean.toString(async));
		
		String getScheduleCmd = "crontab -l"; 
		
		String scheduleSearchString  = "";
		
		try {
			Logger.debug("Checking OS: " + sysUtil.getOS());
			if (sysUtil.getOS().equals("Mac OS X")) {
				
				String APPLICATION_PROPS_FILENAME = "activation.properties.rk";
				String SYSTEM_PROPERTY_SHARED_CONFIG_DIR ="shared.config.dir";
				
				com.ibm.security.util.Properties prop = new ActivationProperties();
				prop.loadApplicationProperties(sysUtil.getSystemProperty(SYSTEM_PROPERTY_SHARED_CONFIG_DIR) + "/" + APPLICATION_PROPS_FILENAME, true);
				appProps = prop.getProperties();

				if (remote) {
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_boardJobs_remote"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_boardJobs_remote"));
					scheduleSearchString = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs_remote"):appProps.getProperty("saml_script_boardJobs_remote"));
				} else {
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_boardJobs"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_boardJobs"));
					scheduleSearchString = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs"):appProps.getProperty("saml_script_boardJobs"));
				}
				
			}
			else { // this is assuming deployed on TFIM server host


				if (remote) {
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_boardJobs_remote"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_boardJobs_remote"));
					scheduleSearchString = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs_remote"):appProps.getProperty("saml_script_boardJobs_remote"));
				} else {
					Logger.debug("OIDC app property: " + appProps.getProperty("oidc_script_boardJobs"));
					Logger.debug("OIDC app property: " + appProps.getProperty("saml_script_boardJobs"));
					scheduleSearchString = initCmd((authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs"):appProps.getProperty("saml_script_boardJobs"));
				}
			}
			
			if (async)
				getScheduleCmd += " &";

			Logger.debug("Crontab list command: " + getScheduleCmd);
			
			commandMap.setCommand(getScheduleCmd);
			commandMap = cliOS.exec(commandMap, !async);
			
			if (!async) {
				
				if (commandMap.getCommandResultCode().equals("0")) {
					
					resultMessage = commandMap.getCommandResultMessage();
					Logger.debug("ResultMessage");
					Logger.debug("[[" + resultMessage + "]]");
					
					Logger.debug("Searching for the following in the crontab schedule:\n\r\n\r" 
							+ scheduleSearchString + "\n\r\n\r");
					
					if (resultMessage.contains(scheduleSearchString)) {
						Logger.debug("Located schedule on crontab");
						
						String schedule = parseSchedule(resultMessage, scheduleSearchString);
						
						if (!schedule.equals("")) {
							Logger.debug("Parsed schedule: >>" + schedule + "<<");
							schedule = adjustForCronLib(schedule);
							success = isOutsideWindow(schedule
									, (authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs_window_before"):appProps.getProperty("saml_script_boardJobs_window_before")
									, (authType.compareTo(AuthType.OIDC) == 0)?appProps.getProperty("oidc_script_boardJobs_window_after"):appProps.getProperty("saml_script_boardJobs_window_after"));							
						}
						
					}
					
					resultMessage = "";
				}
				
				commandMap.setCommandResultMessage(" ");
				
			}
			
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		} finally {
			resultMessage = null;
			commandMap = null;
		}
		
		return success;	
		
	}

	public String getPartnerJobInfo(String env, String infoLevel, String format) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getPartnerJobInfo(String env, String infoRequest, String format)");
		
		String result = "No info";
		
		environment = Environment.parseEnvironment(env);
		PartnerJobInfo partnerJobInfo = PartnerJobInfo.parsePartnerJobInfo(infoLevel);
		
		Logger.debug("env = " + environment.name().toLowerCase());
		Logger.debug("infoRequest = " + partnerJobInfo.name().toLowerCase());
		Logger.debug("format = " + format);

		String w3idUtilLog = PropertiesManager.getApplicationProperty("W3ID_UTIL_AUDIT_LOG_FILE");
		String w3idOidcPartnerBoardingLog = PropertiesManager.getApplicationProperty("oidc_jobs_log_dir_" + environment.name().toLowerCase());
		String w3idSamlPartnerBoardingLog = PropertiesManager.getApplicationProperty("saml_jobs_log_dir_" + environment.name().toLowerCase());
		String w3idActivationLog = PropertiesManager.getApplicationProperty("activation_log_file_base");
		
		Logger.debug("w3id Utility log file: " + w3idUtilLog);
		Logger.debug("w3id OIDC activation log file: " + w3idOidcPartnerBoardingLog);
		Logger.debug("w3id SAML activation log file: " + w3idSamlPartnerBoardingLog);
		
		File w3idUtilLogFile = new File(w3idUtilLog);
		
		if (!w3idUtilLogFile.exists()) {
			if (!w3idUtilLogFile.createNewFile()) {
				throw new FileNotFoundException("Cannot locate " + w3idUtilLogFile.getAbsolutePath());
			}
		}
		
		File w3idOidcPartnerBoardingLogFile = new File(w3idOidcPartnerBoardingLog);
		
		if (!w3idOidcPartnerBoardingLogFile.exists()) {
			throw new FileNotFoundException("Cannot locate " + w3idOidcPartnerBoardingLogFile.getAbsolutePath());
		}

		File w3idSamlPartnerBoardingLogFile = new File(w3idSamlPartnerBoardingLog);
		
		if (!w3idSamlPartnerBoardingLogFile.exists()) {
			throw new FileNotFoundException("Cannot locate " + w3idSamlPartnerBoardingLogFile.getAbsolutePath());
		}

		

		try {
			
			ArrayList<String> matched = new ArrayList<String>();
			
			matched = FileUtil.loadFileLinesToArrayList(w3idUtilLogFile, " invoked /boardJobs", false, matched);
			
			result = matched.get(matched.size()-1);
			Logger.debug("Logged line of last time /boardJobs was invoked: " + result);
			
			StringTokenizer st = new StringTokenizer(result, " ");
			
			String dateStr = st.nextToken();
			
			Logger.debug("Date string: " + dateStr);
			
			SimpleDateFormat sdfFrom = new SimpleDateFormat(PropertiesManager.getApplicationProperty("W3ID_UTIL_DATETIME_FORMAT_LOG"));
			SimpleDateFormat sdfTo = new SimpleDateFormat(PropertiesManager.getApplicationProperty("W3ID_UTIL_DATETIME_FORMAT_HUMAN"));
			
			String dateTimeString = dateStr.substring(1, dateStr.length()-1);

			Logger.debug("Date string before adjustment with format: " + dateTimeString);
			
			dateTimeString = sdfTo.format(sdfFrom.parse(dateTimeString)) + " UTC";

			Logger.debug("Date string adjusted with format: " + dateTimeString);
			
			st = new StringTokenizer(result, "]");
			st.nextToken();
			result = st.nextToken().trim() + " at " + dateTimeString;
			
			if (w3idSamlPartnerBoardingLogFile.isDirectory()) {
				Logger.debug(w3idSamlPartnerBoardingLogFile.getAbsolutePath() + " is a directory");
				String activityLog = "";
				String[] dirContents = w3idSamlPartnerBoardingLogFile.list();
				Logger.debug("Listing of " + w3idSamlPartnerBoardingLogFile.getAbsolutePath()  + ": " + Arrays.toString(dirContents));
				
				for (String dirContent : dirContents) {
					Logger.debug("Evaluating listing: " + dirContent);
					
					if (dirContent.startsWith(w3idActivationLog)) {
						Logger.debug("Match found: " + dirContent + " (matched against " + w3idActivationLog + ")");
						activityLog = dirContent;
						matched = new ArrayList<String>();
					}
				}
				File activityLogFile = new File(w3idSamlPartnerBoardingLog + "/" + activityLog);
				Logger.debug("Preparing to scan " + activityLogFile.getAbsolutePath());
				matched = FileUtil.loadFileLinesToArrayList(activityLogFile, dateTimeString, false, matched);
				
				if (!matched.isEmpty()) {
					result += ", Status: ";

					switch (partnerJobInfo) {
					case INFO:
						for (int i = 0; i < matched.size(); i++) {
							String line = matched.get(i);
							if (line.contains("Activation Summary")) {
								result += matched.get(i+1).substring(matched.get(i+1).indexOf(":")+1, matched.get(i+1).length()-1).trim();
							}
						}
						break;

					default:
						break;
					}
					
				}
			}
					
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		}
		
		return result;
		
	}
	
	
	private String initCmd(String command) {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".initCmd(String command)");

		String check4jobsCmd = "";
		if (authType.compareTo(AuthType.OIDC) == 0) {
			if (environment.compareTo(Environment.STAG) == 0) {
				check4jobsCmd = appProps.getProperty("oidc_jobs_dir_stag") + "/";
				Logger.debug("Using value " + appProps.getProperty("oidc_jobs_dir_stag"));
			} else if (environment.compareTo(Environment.TEST) == 0) {
				check4jobsCmd = appProps.getProperty("oidc_jobs_dir_test") + "/";
	    		Logger.debug("Using value " + appProps.getProperty("oidc_jobs_dir_test"));
			}
			else if (environment.compareTo(Environment.PROD) == 0) {
				check4jobsCmd = appProps.getProperty("oidc_jobs_dir_prod") + "/";
	    		Logger.debug("Using value " + appProps.getProperty("oidc_jobs_dir_prod"));
			}
		} else if (authType.compareTo(AuthType.SAML2) == 0) {

			if (environment.compareTo(Environment.STAG) == 0) {
				check4jobsCmd = appProps.getProperty("saml_jobs_dir_stag") + "/";
				Logger.debug("Using value " + appProps.getProperty("saml_jobs_dir_stag"));
			} else if (environment.compareTo(Environment.TEST) == 0) {
				check4jobsCmd = appProps.getProperty("saml_jobs_dir_test") + "/";
	    		Logger.debug("Using value " + appProps.getProperty("saml_jobs_dir_test"));
			}
			else if (environment.compareTo(Environment.PROD) == 0) {
				check4jobsCmd = appProps.getProperty("saml_jobs_dir_prod") + "/";
	    		Logger.debug("Using value " + appProps.getProperty("saml_jobs_dir_prod"));
			}
		
		}
		
		check4jobsCmd += command;

		return check4jobsCmd; 
		
	}

	public boolean isRemoteHost() {
		return remoteHost;
	}

	public void setRemoteHost(boolean remoteHost) {
		this.remoteHost = remoteHost;
	}
	
	private String parseSchedule(String schedule, String searchString) {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".parseSchedule(String schedule, String searchString)");

		StringTokenizer st = new StringTokenizer(schedule, "\n");
		String returnString = "";
		Logger.debug("Looking for " + searchString);

		while (st.hasMoreTokens()) {
			String toCompare = st.nextToken();
			if (!toCompare.startsWith("#")) {
				Logger.debug("Looking for \"" + searchString + "\" against \"" + toCompare + "\"");
				if (toCompare.contains(searchString)) {
					Logger.debug("Located " + searchString);
					returnString = toCompare.substring(0, toCompare.indexOf(searchString)).trim();
					break;
				}
			}
		}
		
		return returnString;
	}
	
	private String adjustForCronLib(String schedule) {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".adjustForCronLib(String schedule)");

		StringTokenizer st1 = new StringTokenizer(schedule, " ");
		
		if (st1.countTokens() == 5) {
			schedule = "0 " + schedule;
			schedule = schedule.substring(0, schedule.lastIndexOf("*"));
			schedule += "?";
			Logger.debug("Adjusted schedule: " + schedule);
		}
		
		StringTokenizer st = new StringTokenizer(schedule, " ");

		Logger.debug("Schedule has " + st.countTokens() + " elements");


		return schedule;
	}
	
	private boolean isOutsideWindow(String schedule, String timeBeforeScheduledRun, String timeAfterScheduledRun) throws ParseException {
		Logger.debug("Inside method: " + this.getClass().getName() 
				+ ".isOutsideWindow(String line)");
		
		Logger.debug("Black out time (in minustes) before scheduled run: " + timeBeforeScheduledRun);
		Logger.debug("Black out time (in minustes) after scheduled run: " + timeAfterScheduledRun);
		
		CronExpression ex = new CronExpression(schedule);
		Logger.debug(ex.getExpressionSummary());
		
		Date d = new GregorianCalendar().getTime();

		long exInMillis = ex.getNextInvalidTimeAfter(d).getTime();
		
		long blackoutWindow = compareInMins(d.getTime(), exInMillis);
		
		Logger.debug("Current date/time: " + d);
		Logger.debug("Next time schedule is called: " + ex.getNextValidTimeAfter(d));
		
		Logger.debug("Time (in minutes) until next schedule kicked off: " + blackoutWindow);
		
		Calendar calStart = new GregorianCalendar();
		calStart.add(Calendar.MINUTE, -(Integer.parseInt(timeBeforeScheduledRun)));
		Logger.debug("Adjusted date/time of start: " + calStart.getTime());
		
		Calendar calEnd = new GregorianCalendar();
		calEnd.add(Calendar.MINUTE, (Integer.parseInt(timeAfterScheduledRun)));
		Logger.debug("Adjusted date/time of end: " + calEnd.getTime());
		
		long blackoutStart = calStart.getTimeInMillis();
		long blackoutEnd = calEnd.getTimeInMillis();
		
		Logger.debug("Time (in ms) window start: " + blackoutStart);
		Logger.debug("Time (in ms) window end: " + blackoutEnd);
		Logger.debug("Time (in ms) schedule run: " + exInMillis);
		
		
		Logger.debug("Comparison of window start to expected time run: " + ex.getTimeAfter(d).compareTo(calStart.getTime()));
		Logger.debug("Comparison of window end to expected time run: " + ex.getTimeAfter(d).compareTo(calEnd.getTime()));
		
		Logger.debug("Is it safe to board manually: " + 
				(ex.getTimeAfter(d).compareTo(calStart.getTime()) == 1 & ex.getTimeAfter(d).compareTo(calStart.getTime()) == 1));
		
		
		return ((ex.getTimeAfter(d).compareTo(calStart.getTime()) == 1 & ex.getTimeAfter(d).compareTo(calStart.getTime()) == 1));
	}
	
	private long compareInMins(long time1, long time2) {
		
		return (time2 - time1)/1000/60;
	}


}
