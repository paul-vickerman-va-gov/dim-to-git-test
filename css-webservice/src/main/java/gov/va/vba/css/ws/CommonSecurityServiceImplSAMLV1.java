package gov.va.vba.css.ws;

import gov.va.vba.css.bo.CSSAuthorizationException;
import gov.va.vba.css.bo.CSSFrameworkLayerException;
import gov.va.vba.css.bo.CommonSecuritySystemBean;
import gov.va.vba.css.security.exceptions.CssWsException;
import gov.va.vba.css.security.service.CssSecurityContextService;
import gov.va.vba.css.ws.css_webservice_saml_1.CSSAuthorizationFault;
import gov.va.vba.css.ws.css_webservice_saml_1.CSSFrameworkLayerFault;
import gov.va.vba.css.ws.css_webservice_saml_1.CommonSecurityServiceSAMLWS;
import gov.va.vba.css.ws.css_webservice_saml_1.CssUserRepositoryFault;
import gov.va.vba.css.ws.css_webservice_saml_1.CssUserRepositoryUnknownFault;
import gov.va.vba.css.ws.types.services.v1.CssSecurityProfile;
import gov.va.vba.css.ws.types.services.v1.CssUser;
import gov.va.vba.framework.esb.transformers.TuxedoSecurityProfile;

import javax.jws.HandlerChain;
import javax.jws.WebMethod;
import javax.jws.WebService;

import org.dozer.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

/**
 * Web Service that allows an authenticated user to get information about the list of accessible stations for an
 * application. Also will get CSS Security Profile of the user for an specific station and an application. 
 * @author VBACOVANEGI
 *
 */

@HandlerChain(file = "./service_handler_saml.xml")
@WebService(wsdlLocation = "schemas/css_webservice-saml_1_0_0.wsdl",portName = "CommonSecurityServicePortSAMLV1",serviceName="CommonSecurityServiceSAMLV1", targetNamespace= "http://ws.css.vba.va.gov/css-webservice-saml-1.0", endpointInterface = "gov.va.vba.css.ws.css_webservice_saml_1.CommonSecurityServiceSAMLWS")
public class CommonSecurityServiceImplSAMLV1 extends SpringBeanAutowiringSupport implements CommonSecurityServiceSAMLWS {


	@Autowired
	CommonSecuritySystemBean commonSecuritySystemBean;
	
    @Autowired
	private CssSecurityContextService securityContextService;
	
	@Autowired
	Mapper dozzerMapper;
	
	/**
	 * Get the CSS Security Profile of the user calling the Web Service, extracting the User username from the SAML
	 * Assertion part of the security header of the Web Service Request. The username, together with the application name
	 * and the stationId is used to get the Security Profile of the user, that can in turn be used to exercise specific
	 * authorization rules.   
	 *  
	 * @param applicationCSSName Application name as is stored in the CSS System (i.e. VBMS, CASEFLOW)
	 * @param stationId Station Identifier. A three digit string that represents the station that the user is associated with
	 * to access the application
	 * @return TuxedoSecurityProfile Object containing information from Corporate Database that can be used for Security Purposes 
	 * @throws CSSAuthorizationFault 
	 * @throws CSSFrameworkLayerFault 
	 */
	@WebMethod
	@Override
	public CssSecurityProfile getSecurityProfile(String applicationCSSName, String stationId) throws CSSAuthorizationFault, CSSFrameworkLayerFault {
		String username = null;
		String ipAddress = null;
		
		TuxedoSecurityProfile cssProfile;
		
		try {
			username = securityContextService.getUserName();
			ipAddress = securityContextService.getClientIPAddress();
			cssProfile = commonSecuritySystemBean.getCSSSecurityProfile(username, applicationCSSName, stationId, ipAddress);
		} catch (CSSAuthorizationException e1) {
			throw new CSSAuthorizationFault("User is not authorized for station provided", null, e1);
		} catch (CSSFrameworkLayerException e2) {
			throw new CSSFrameworkLayerFault("Unable to get authorization due to a framework fault", null, e2);
		} catch (CssWsException e3) {
			throw new CSSAuthorizationFault("Unable to get user details from the incoming request", null, e3);
		} 
		
		CssSecurityProfile response = dozzerMapper.map(cssProfile, CssSecurityProfile.class);
		
		return response;
		
	}
	
	/**
	 * Get the CSS User that represent a user in the Common Security System for authorization purposes.  
	 * @param applicationCSSName Application name as is stored in the CSS System (i.e. VBMS, CASEFLOW)
	 * @return CSS User has associated mainly the application that the user is trying to reach, 
	 * the list of stations that the User has associated for that application. Each station on that list
	 * contains information that shows if the station in available to the user, or if not, the reason why is not available. 
	 * @throws CssUserRepositoryFault 
	 * @throws CssUserRepositoryUnknownFault 
	 */
	@WebMethod
	@Override
	public CssUser getCssUserStationsByApplication(String applicationCSSName) throws CssUserRepositoryFault, CssUserRepositoryUnknownFault {

		String username = null;
		String ipAddress = null;
		gov.va.vba.framework.css.cssiam.domain.entities.CssUser user;
		
		try {
			username = securityContextService.getUserName();
			ipAddress = securityContextService.getClientIPAddress();
			user = commonSecuritySystemBean.getCSSStationsByApplication(username, applicationCSSName, ipAddress);
		} catch (CSSAuthorizationException e1) {
			throw new CssUserRepositoryFault("User is not authorized to access the application", null, e1);
		} catch (CSSFrameworkLayerException e2) {
			throw new CssUserRepositoryUnknownFault("Unable to get user authroization due to a framework fault", null, e2);
		} catch (CssWsException e3) {
			throw new CssUserRepositoryFault("Unable to get user details from the incoming request", null, e3);
		} 
		
		CssUser cssUserResponse = dozzerMapper.map(user, CssUser.class);
		
		return cssUserResponse;
	}

}
