package com.ibm.security.sso.federation;

import java.util.InputMismatchException;

import com.ibm.security.util.Logger;

public enum AuthType {
	
	OIDC, SAML2;
	
	public static Enum<AuthType> parseAuthType(String authType) {
		Logger.debug("Inside method: " + AuthType.class.getName()
				+ ".parseAuthType(String authType)");

		Enum<AuthType> auth_type = OIDC;
		
		if (authType.toLowerCase().equals("saml2") || authType.toLowerCase().equals("saml")) {
			auth_type = SAML2;
			Logger.debug("Auth Type is " + SAML2.name());
		} else {
			if (!authType.toLowerCase().equals("oidc")) {
				throw new InputMismatchException("Invalid entry provided.");
			}
		}
		
		return auth_type;
	
	}


}
