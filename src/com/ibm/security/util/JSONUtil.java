package com.ibm.security.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.ParseException;

public class JSONUtil {
	
	public static final String JSON_KEY_HOST = "Host"; 
	public static final String JSON_KEY_LOGS = "Logs"; 
	public static final String JSON_KEY_FILE = "id"; 
	public static final String JSON_KEY_LOGS_LOCATION = "LogsLocation";
	public static final String JSON_KEY = "Key";
	
	public static JSONArray processStringIntoJSONArray(String jsonString, String filter) throws ParseException {
		Logger.debug("Inside method: " + JSONUtil.class.getName()
				+ ".processStringIntoJSONArray(String jsonString)");
		
		Logger.debug("JSON String: " + jsonString);
		int blockCharIndex = jsonString.indexOf("[");
		if  (blockCharIndex >= 0) 
			jsonString = jsonString.substring(blockCharIndex+1);
				
		blockCharIndex = jsonString.indexOf("]");
		if  (blockCharIndex >= 0) 			
			jsonString = jsonString.substring(0, blockCharIndex);
			
		Logger.debug("JSON String after adjustment: " + jsonString);
		
		JSONArray jsonArray = new JSONArray();
		
		StringTokenizer st = new StringTokenizer(jsonString, ",");
		while (st.hasMoreElements()) {
			String jsonObjectInString = st.nextElement().toString().trim();
			StringTokenizer st2 = new StringTokenizer(jsonObjectInString, ":");
			Map<String, String> jsonObjectMap = new HashMap<String, String>();
			while (st2.hasMoreTokens()) {
				Object obj = st2.nextElement();
				if (obj != null) {
					String stringToMap = obj.toString().trim();
					if (stringToMap.equals(filter)) {
						String key = stringToMap;
						String value = st2.nextElement().toString().trim();
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

	
	public static String removeJSONStringChars(String string) {
		string = string.trim();
		if (string.contains("{")) 
			string = string.substring(string.indexOf("{")+1);
		if (string.contains("}")) 
			string = string.substring(0, string.indexOf("}"));
		
		if (string.contains("\""))
			string = string.replaceAll("\"", "");

		if (string.contains("/"))
			string = string.replaceAll("/", "");

		if (string.contains("/"))
			string = string.replaceAll("/", "");
		
		return string;

	}

}
