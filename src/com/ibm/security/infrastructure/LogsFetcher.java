package com.ibm.security.infrastructure;

import org.json.simple.JSONArray;
import org.json.simple.parser.ParseException;

public interface LogsFetcher {
	
	public JSONArray getLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey, String email, boolean wait)  throws Exception;
	
	public JSONArray getLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email, boolean wait) throws Exception;
	
	public JSONArray searchLogs(String[] logsToFetch, String fromDate, String toDate, String newKey, String email, String searchString, boolean wait) throws Exception;
	
	public JSONArray searchLogs(String host, String[] logsToFetch, String fromDate, String toDate, String newKey, String email, String searchString, boolean wait) throws Exception;
	
	public JSONArray getLogsListing(String host, String url, String[] logsToFetch) throws Exception;
	
	public JSONArray processLogsListingJSONStringIntoJSONArray(String jsonString) throws ParseException ;
	
	
}
