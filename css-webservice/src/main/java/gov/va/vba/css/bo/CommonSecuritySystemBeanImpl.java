package gov.va.vba.css.bo;

import gov.va.vba.framework.auditing.AuditIDGenerator;
import gov.va.vba.framework.common.AuditContext;
import gov.va.vba.framework.css.cssiam.domain.entities.CssUser;
import gov.va.vba.framework.services.CommonSecurityServiceV2;

public class CommonSecuritySystemBeanImpl implements CommonSecuritySystemBean {

	private CommonSecurityServiceV2 commonSecurityServiceV2;

	public CommonSecuritySystemBeanImpl() {
		super();
	}

	public CommonSecurityServiceV2 getCommonSecurityServiceEJB() {
		return commonSecurityServiceV2;
	}

	public void setCommonSecurityServiceEJB(CommonSecurityServiceV2 commonSecurityServiceEJB) {
		this.commonSecurityServiceV2 = commonSecurityServiceEJB;
	}
	
	public CssUser getCSSStationsByApplication(String username, String applicationName, String clientIpAddress) {
		
		//AuditContext must contain: applicationName, clientIPAddress, stationID, userID
		AuditContext auditContex = createNewAuditContext(applicationName, username, clientIpAddress);
		
		CssUser cssUser = commonSecurityServiceV2.getCssUserStationsByApplication(username, applicationName, auditContex);
		
		return cssUser;
	}
	
	/**
	 * Create an auditContext to pass it to the EJB. The EJB have an intercepter that will execute an audit to this EJB call.
	 * @param application Application that a user is intending to login
	 * @param username The user identifier
	 * @param ipAddress IP Address that the user is trying to access the system from
	 * @return a newly create auditContext with the input parameters
	 */
	private AuditContext createNewAuditContext(String application,
			String username, String ipAddress) {
		AuditContext auditContext = new AuditContext();
		auditContext.setAuditID(AuditIDGenerator.generateAuditID());
		auditContext.setApplicationName(application);
		auditContext.setClientIPAddress(ipAddress);
		auditContext.setUserId(username);
		auditContext.setStationID("-1");
		return auditContext;
	}
	
}
