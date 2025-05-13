package gov.va.vba.css.bo;

import gov.va.vba.framework.auditing.AuditIDGenerator;
import gov.va.vba.framework.auditing.LoginAuditer;
import gov.va.vba.framework.common.AuditContext;
import gov.va.vba.framework.css.cssiam.domain.entities.CssUser;
import gov.va.vba.framework.domain.vo.ServiceVO;
import gov.va.vba.framework.esb.transformers.TuxedoSecurityProfile;
import gov.va.vba.framework.services.CommonSecurityServiceV2;
import gov.va.vba.framework.services.CssUserRepositoryException;
import gov.va.vba.framework.services.CssUserRepositoryUnknownException;
import gov.va.vba.framework.services.TuxedoException;

public class CommonSecuritySystemBeanImpl implements CommonSecuritySystemBean {
	
	private static String unselectedStation = "-1";

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
	
	@Override
	public CssUser getCSSStationsByApplication(String username, String applicationName, String clientIpAddress) throws CSSAuthorizationException, CSSFrameworkLayerException {

		//CSS username is always Uppercase 
		username = username.toUpperCase();
		
		AuditContext auditContex = createNewAuditContext(applicationName, username, clientIpAddress, unselectedStation);
		
		CssUser cssUser;
		
		try {
			cssUser = commonSecurityServiceV2.getCssUserStationsByApplication(username, applicationName, auditContex);
		} catch (CssUserRepositoryException e) {
			throw new CSSAuthorizationException(e.getMessage());
		} catch (CssUserRepositoryUnknownException e) {
			throw new CSSFrameworkLayerException(e.getMessage());
		} catch (Exception e) {
			if (e.getCause() != null && e.getCause() instanceof CssUserRepositoryException || e.getCause() instanceof CssUserRepositoryUnknownException) {
				throw new CSSFrameworkLayerException(e.getCause().getMessage(), e);
			}
			throw new CSSFrameworkLayerException(e.getMessage());
		}
		
		return cssUser;
	}

	@Override
	public TuxedoSecurityProfile getCSSSecurityProfile(String username,
			String applicationCSSName, String stationId, String ipAddress) throws CSSAuthorizationException, CSSFrameworkLayerException {

		TuxedoSecurityProfile cssProfile = null;
		
		//CSS username is always Uppercase 
		username = username.toUpperCase();
		
		AuditContext auditContex = createNewAuditContext(applicationCSSName, username, ipAddress, stationId);
		
		try {
			cssProfile = commonSecurityServiceV2.getSecurityProfile(new ServiceVO(auditContex.getUserId(), 
					auditContex.getStationID(), auditContex.getClientIPAddress(), auditContex.getApplicationName(), ServiceVO.SecurityService.CSSPROFILE), 
					auditContex, null);
			
			switch (cssProfile.getRetCode()) {
			case '0'://Success
				//Auditing a successful login
				auditLoginAttempt(auditContex,true);
				break;

			case '1': //Authorization error in CSSPROFILE
				//Auditing a unsuccessful login
				auditLoginAttempt(auditContex,false);
				throw new CSSAuthorizationException("Unable to authorize user against CSS: "+cssProfile.getMessage());
				
			case '2'://Exception caught in the EJB Framework Layer
				//Auditing a unsuccessful login
				auditLoginAttempt(auditContex,false);
				throw new CSSFrameworkLayerException("Exception caugth in Framework Sub-layers: "+cssProfile.getMessage());
				
			default:
				auditLoginAttempt(auditContex,false);
				throw new CSSFrameworkLayerException("Unrecognized return code from Framework Sub-layers: "+cssProfile.getMessage());
			}
			
		} catch (TuxedoException e) {
			throw new CSSFrameworkLayerException("Exception caught while contacting Framework Sub-layers: "+e.getMessage(), e);
		}
		
		return cssProfile;
	}
	
	
	/**
	 * Create an auditContext to pass it to the EJB. The EJB have an intercepter that will execute an audit to this EJB call.
	 * @param application Application that a user is intending to login
	 * @param username The user identifier
	 * @param ipAddress IP Address that the user is trying to access the system from
	 * @return a newly create auditContext with the input parameters
	 */
	private AuditContext createNewAuditContext(String application,
			String username, String ipAddress, String stationId) {
		AuditContext auditContext = new AuditContext();
		auditContext.setAuditID(AuditIDGenerator.generateAuditID());
		auditContext.setApplicationName(application);
		auditContext.setClientIPAddress(ipAddress);
		auditContext.setUserId(username);
		auditContext.setStationID(stationId);
		return auditContext;
	}
	
	/**
	 * Audit the login operation and its result
	 * @param auditContext
	 * @param isSuccessAttempt
	 */
	protected void auditLoginAttempt(AuditContext auditCtx, boolean isSuccessAttempt) {
		new LoginAuditer().audit(auditCtx, isSuccessAttempt);
	}
}
