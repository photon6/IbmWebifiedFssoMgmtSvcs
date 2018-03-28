package com.ibm.security.util;

public class CommandMap {
	
	private String command, commandResultMessage, commandResultCode, commandEnvironment, commandPlatform;
	
	public synchronized void setCommand(String command) {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".setCommand(String command)");
		this.command = command;
		Logger.debug("Command \"" + this.command + "\" has been set.");
	}
	
	public synchronized void setCommandResultCode(String commandResultCode) {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".setCommand(String command)");
		this.commandResultCode = commandResultCode;
	}
	
	public synchronized void setCommandResultMessage(String commandResultMessage) {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".setCommand(String command)");
		this.commandResultMessage = commandResultMessage;
	}

	public synchronized void setCommandEnvironment(String commandEnvironment) {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".setCommand(String command)");
		this.commandEnvironment = commandEnvironment;
	}
	
	public synchronized void setCommandPlatform(String commandPlatform) {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".setCommand(String command)");
		this.commandPlatform = commandPlatform;
	}
	
	public synchronized String getCommand() {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getCommand()");
		return command;
	}
	
	public String getCommandResultCode() {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getCommandResultCode)");
		return commandResultCode;
	}
	
	public synchronized String getCommandResultMessage() {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getCommandResultMessage()");
		return commandResultMessage;
	}

	public synchronized String getCommandEnvironment() {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getCommandEnvironment()");
		return commandEnvironment;
	}
	
	public synchronized String getCommandPlatform() {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".getCommandPlatform()");
		return commandPlatform;
	}
	
	public synchronized void clear() {
		Logger.debug("Inside method: " + getClass().getName() 
				+ ".clear()");
		setCommand("");
		setCommandEnvironment("");
		setCommandPlatform("");
		setCommandResultCode("");
		setCommandResultMessage("");
	}
}
