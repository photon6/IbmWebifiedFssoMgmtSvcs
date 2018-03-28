package com.ibm.security.util;

import java.util.Calendar;
import java.util.Date;

public class DateUtil {
	
	public static Object getTimeDiff(Date date1, Date date2, Object returnObj) {
		
		if (returnObj instanceof Long) {
			Long obj = new Long(date1.getTime() - date2.getTime());
			returnObj = (Object) obj;
		} else if (returnObj instanceof Date) {
//			Log obj = getTimeDiff(date1, date2, new Long(0));
//			
//			Date newDate = new (obj.longValue());
//			returnObj = (Object) newDate;
		}
		
		return returnObj;
		
	}
	

}
