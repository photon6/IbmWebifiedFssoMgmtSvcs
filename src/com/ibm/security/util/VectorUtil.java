package com.ibm.security.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

public class VectorUtil {
	
	public static ArrayList<String> extractHashMapStringValuesIntoStringArrayList(HashMap<String, String> hashMap) {
		ArrayList<String> list = new ArrayList<String>();
		Set<String> keys = hashMap.keySet();
		for (String key : keys) {
			list.add(hashMap.get(key));
		}
		return list;
	}

	public static HashSet<String> extractHashMapStringValuesIntoStringHashSet(HashMap<String, String> hashMap) {
		HashSet<String> list = new HashSet<String>();
		Set<String> keys = hashMap.keySet();
		for (String key : keys) {
			list.add(hashMap.get(key));
		}
		return list;
	}

	
}
