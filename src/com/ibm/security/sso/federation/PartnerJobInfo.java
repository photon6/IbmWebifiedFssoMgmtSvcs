package com.ibm.security.sso.federation;

import java.util.InputMismatchException;

public enum PartnerJobInfo {
	INFO, ERROR, DEBUG, TRACE;
	
	public static PartnerJobInfo parsePartnerJobInfo(String infoLevel) {
		PartnerJobInfo partnerJobInfo = PartnerJobInfo.INFO;
		
		if (infoLevel.toLowerCase().contains("error")) {
			partnerJobInfo = PartnerJobInfo.ERROR;
		} else if (infoLevel.toLowerCase().contains("debug")) {
				partnerJobInfo = PartnerJobInfo.ERROR;
		} else if (infoLevel.toLowerCase().contains("trace")) {
			partnerJobInfo = PartnerJobInfo.ERROR;
		} else {
			if (!infoLevel.toLowerCase().contains("info")) {
				throw new InputMismatchException("Invalid entry provided.");
			}
		}
		return partnerJobInfo;
	}
}
