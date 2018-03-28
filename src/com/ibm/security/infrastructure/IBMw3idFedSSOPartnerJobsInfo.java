package com.ibm.security.infrastructure;

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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.StringTokenizer;
import com.ibm.security.sso.federation.PartnerJobInfo;
import com.ibm.security.util.Environment;
import com.ibm.security.util.FileUtil;
import com.ibm.security.util.Logger;
import com.ibm.security.util.PropertiesManager;

public class IBMw3idFedSSOPartnerJobsInfo {
	
	
	public IBMw3idFedSSOPartnerJobsInfo() throws IOException {
		Logger.debug("Inside contructor: " + this.getClass().getName() + "()");
	}

	public String getPartnerJobInfo(String env, String infoLevel, String format) throws Exception {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getPartnerJobInfo(String env, String infoRequest, String format)");
		
		String result = "No info";
		
		Enum<Environment> environment = Environment.parseEnvironment(env);
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
			
			int matchIndex = matched.size()-1;
			
			for (int i = matched.size()-1; i > 0; i--) {
				if (matched.get(i).toLowerCase().contains(environment.name().toLowerCase())) {
					matchIndex = i;
					break;
				} 
				
				if (i == 1) {
					matchIndex = -1;
				}
			}
	
			if (matchIndex == -1) {
				result += " regarding " + env;
			} else {
			
				String matchedLine = matched.get(matchIndex);
				Logger.debug("Logged line of last time /boardJobs was invoked: " + matchedLine);
				
				StringTokenizer st = new StringTokenizer(matchedLine, " ");
				
				String dateStr = st.nextToken();
				
				Logger.debug("Date string: " + dateStr);
				
				SimpleDateFormat sdfFrom = new SimpleDateFormat(PropertiesManager.getApplicationProperty("W3ID_UTIL_DATETIME_FORMAT_LOG"));
				SimpleDateFormat sdfTo = new SimpleDateFormat(PropertiesManager.getApplicationProperty("W3ID_UTIL_DATETIME_FORMAT_HUMAN"));
				
				String dateTimeString = dateStr.substring(1, dateStr.length()-1);
	
				Logger.debug("Date string before adjustment with format: " + dateTimeString);
				
				dateTimeString = sdfTo.format(sdfFrom.parse(dateTimeString)) + " UTC";
	
				Logger.debug("Date string adjusted with format: " + dateTimeString);
				
				st = new StringTokenizer(matchedLine, "]");
				st.nextToken();
				result = st.nextToken().trim() + " at " + dateTimeString;
				
				if (matchedLine.toLowerCase().contains("auth=saml") || matchedLine.toLowerCase().contains("auth=&")) {
									
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
						} // end for (String dirContent : dirContents) {
						
						Logger.debug("Preparing to scan file: " + w3idSamlPartnerBoardingLog + "/" + activityLog);
						File activityLogFile = new File(w3idSamlPartnerBoardingLog + "/" + activityLog);
						Logger.debug("Preparing to load file contents from " + activityLogFile.getPath() + " that match: " + dateStr.substring(0, dateStr.length()-1));
						matched = FileUtil.loadFileLinesToArrayList(activityLogFile, dateStr.substring(0, dateStr.length()-1), false, matched);
						
						if (!matched.isEmpty()) {
		
							switch (partnerJobInfo) {
							case INFO:
								for (int i = 0; i < matched.size(); i++) {
									String line = matched.get(i);
									Logger.debug("Evaluating line: " + line);
									if (line.contains("Activation Summary")) {
										result += ", SAML Status: ";
										result += matched.get(i+1).substring(matched.get(i+1).indexOf(":")+1, matched.get(i+1).length()-1).trim();
									}
								}
								break;
		
							default:
								break;
							}
						} else {
							Logger.debug("No match found in " + activityLogFile.getPath() + " to: " + dateStr.substring(0, dateStr.length()-1));
						} // end if (!matched.isEmpty()) {
					} // end if (w3idSamlPartnerBoardingLogFile.isDirectory()) {
				}
				
				if (matchedLine.toLowerCase().contains("auth=oidc") || matchedLine.toLowerCase().contains("auth=&")) {
					
					if (w3idOidcPartnerBoardingLogFile.isDirectory()) {
						Logger.debug(w3idOidcPartnerBoardingLogFile.getAbsolutePath() + " is a directory");
						String activityLog = "";
						String[] dirContents = w3idOidcPartnerBoardingLogFile.list();
						Logger.debug("Listing of " + w3idOidcPartnerBoardingLogFile.getAbsolutePath()  + ": " + Arrays.toString(dirContents));
						
						for (String dirContent : dirContents) {
							Logger.debug("Evaluating listing: " + dirContent);
							
							if (dirContent.startsWith(w3idActivationLog)) {
								Logger.debug("Match found: " + dirContent + " (matched against " + w3idActivationLog + ")");
								activityLog = dirContent;
								matched = new ArrayList<String>();
							}
						} // end for (String dirContent : dirContents) {
						
						Logger.debug("Preparing to scan file: " + w3idSamlPartnerBoardingLog + "/" + activityLog);
						File activityLogFile = new File(w3idOidcPartnerBoardingLog + "/" + activityLog);
						Logger.debug("Preparing to load file contents from " + activityLogFile.getPath() + " that match: " + dateStr.substring(0, dateStr.length()-1));
						matched = FileUtil.loadFileLinesToArrayList(activityLogFile, dateStr.substring(0, dateStr.length()-1), false, matched);
						
						if (!matched.isEmpty()) {
					
							switch (partnerJobInfo) {
							case INFO:
								for (int i = 0; i < matched.size(); i++) {
									String line = matched.get(i);
									if (line.contains("Activation Summary")) {
										result += ", OIDC Status: ";
										result += matched.get(i+1).substring(matched.get(i+1).indexOf(":")+1, matched.get(i+1).length()-1).trim();
									}
								}
								break;
					
							default:
								break;
							}
							
						} else {
							Logger.debug("No match found in " + activityLogFile.getPath() + " to: " + dateStr.substring(0, dateStr.length()-1));
						} // end if (!matched.isEmpty()) {
					} // end if (w3idSamlPartnerBoardingLogFile.isDirectory()) {
				}
			}
						
		} catch (Exception e) {
			Logger.logToAllLevels("Exception caught: " + e.getMessage());
			throw e;
		}
		
		return result;
		
	}

}
