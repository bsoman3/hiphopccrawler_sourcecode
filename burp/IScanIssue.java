package burp;

/*
 * @(#)IScanIssue.java
 *
 * Copyright PortSwigger Ltd. All rights reserved.
 * 
 * This code may be used to extend the functionality of Burp Suite and Burp
 * Suite Professional, provided that this usage does not violate the 
 * license terms for those products. 
 */

/**
 * This interface is used to allow extensions to access details of issues
 * generated by Burp Scanner.
 */

public interface IScanIssue {
	/**
	 * Returns the name of the application host.
	 * 
	 * @return The name of the application host.
	 */
	String getHost();

	/**
	 * Returns the port number used by the application.
	 * 
	 * @return The port number used by the application.
	 */
	int getPort();

	/**
	 * Returns the protocol used by the application.
	 * 
	 * @return The protocol used by the application.
	 */
	String getProtocol();

	/**
	 * Returns the URL for which the issue was generated.
	 * 
	 * @return The URL for which the issue was generated.
	 */
	java.net.URL getUrl();

	/**
	 * Returns a descriptive name of the issue type.
	 * 
	 * @return A descriptive name of the issue type (e.g. "SQL injection").
	 */
	String getIssueName();

	/**
	 * Returns a descriptive name of the issue severity level.
	 * 
	 * @return A descriptive name of the issue severity level (e.g. "High").
	 */
	String getSeverity();

	/**
	 * Returns a descriptive name of the issue confidence level.
	 * 
	 * @return A descriptive name of the issue confidence level (e.g.
	 *         "Certain").
	 */
	String getConfidence();

	/**
	 * Returns a general description of this type of issue.
	 * 
	 * @return A general description of this type of issue.
	 */
	String getIssueBackground();

	/**
	 * Returns a general description of the remediation for this type of issue.
	 * 
	 * @return A general description of the remediation for this type of issue.
	 */
	String getRemediationBackground();

	/**
	 * Returns detailed information about the specific instance of the issue.
	 * 
	 * @return If available, detailed information about the specific instance of
	 *         the issue.
	 */
	String getIssueDetail();

	/**
	 * Returns detailed information about the remediation for the specific
	 * instance of the issue.
	 * 
	 * @return If available, detailed information about the remediation for the
	 *         specific instance of the issue.
	 */
	String getRemediationDetail();

	/**
	 * Returns the HTTP messages on the basis of which the issue was generated.
	 * 
	 * @return The HTTP messages on the basis of which the issue was generated.
	 */
	IHttpRequestResponse[] getHttpMessages();
}
