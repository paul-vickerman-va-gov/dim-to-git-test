package gov.va.vba.css.ws;

import gov.va.vba.css.bo.CSSAuthorizationException;
import gov.va.vba.css.bo.CSSFrameworkLayerException;
import gov.va.vba.css.bo.CommonSecuritySystemBean;
import gov.va.vba.css.security.exceptions.CssWsException;
import gov.va.vba.css.security.service.CssSecurityContextService;
import gov.va.vba.css.ws.css_webservice_ws_1.CSSAuthorizationFault;
import gov.va.vba.css.ws.css_webservice_ws_1.CSSFrameworkLayerFault;
import gov.va.vba.css.ws.css_webservice_ws_1.CommonSecurityServiceWS;
import gov.va.vba.css.ws.css_webservice_ws_1.CssUserRepositoryFault;
import gov.va.vba.css.ws.css_webservice_ws_1.CssUserRepositoryUnknownFault;
import gov.va.vba.css.ws.types.services.v1.CssSecurityProfile;
import gov.va.vba.css.ws.types.services.v1.CssUser;
import gov.va.vba.framework.esb.proxy.handler.HandlerContext;
import gov.va.vba.framework.esb.proxy.model.UserContext;
import gov.va.vba.framework.esb.transformers.TuxedoSecurityProfile;
import gov.va.vba.framework.logging.Logger;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebMethod;
import javax.jws.WebService;

import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.dozer.Mapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.context.support.SpringBeanAutowiringSupport;

/**
 * Web Service that allows an authenticated user to get information about the list of accessible stations for an
 * application. Also will get CSS Security Profile of the user for an specific station and an application. 
 * @author VBACOVANEGI
 *
 */

@HandlerChain(file = "./service_handler_ws_framework.xml")
@WebService(wsdlLocation = "schemas/css_webservice-ws_1_0_0.wsdl",portName = "CommonSecurityServicePortWSV1",serviceName="CommonSecurityServiceWSV1", targetNamespace= "http://ws.css.vba.va.gov/css-webservice-ws-1.0", endpointInterface = "gov.va.vba.css.ws.css_webservice_ws_1.CommonSecurityServiceWS")
public class CommonSecurityServiceImplWSV1 extends SpringBeanAutowiringSupport implements CommonSecurityServiceWS {


	@Autowired
	CommonSecuritySystemBean commonSecuritySystemBean;
	
    @Autowired
	private CssSecurityContextService securityContextService;
	
	@Autowired
	Mapper dozzerMapper;
	
	@Resource
	WebServiceContext wsCtx;
	
	private static Logger logger = Logger.getLogger(CommonSecurityServiceImplWSV1.class);
	
	/**
	 * Get the CSS Security Profile of the user calling the Web Service, extracting the User username from the Security Headers
	 * of the Web Service Request. The username, together with the application name and the stationId is used to get the 
	 * Security Profile of the user on the Handler Chain, that can in turn be used to exercise specific
	 * authorization rules.   
	 *  
	 * to access the application
	 * @return TuxedoSecurityProfile Object containing information from Corporate Database that can be used for Security Purposes 
	 * @throws CSSAuthorizationFault 
	 * @throws CSSFrameworkLayerFault 
	 */
	@WebMethod
	@Override
	public CssSecurityProfile getSecurityProfileFromContext() throws CSSAuthorizationFault, CSSFrameworkLayerFault {
		TuxedoSecurityProfile cssProfile;
		MessageContext ctx;
		UserContext user;
		try {
			
			ctx = (MessageContext) wsCtx.getMessageContext();
			user = (UserContext)ctx.get(HandlerContext.ATTR_CTX_USERCONTEXT);
		
			if (user==null || user.getUserProfile()==null || user.getUserProfile().getSecurityProfile() == null){
				logger.debug("Not user security profile present in the UseContext");
				throw new CSSFrameworkLayerException("Unable to get the User Context from the WS Session");
			}
				cssProfile = user.getUserProfile().getSecurityProfile();
		} catch (CSSFrameworkLayerException e2) {
			throw new CSSFrameworkLayerFault("Unable to get authorization due to a framework fault", null, e2);
		} catch (CssWsException e3) {
			throw new CSSAuthorizationFault("Unable to get user details from the incoming request", null, e3);
		} 
		
		CssSecurityProfile response = dozzerMapper.map(cssProfile, CssSecurityProfile.class);
		
		return response;
		
	}
	
	/**
	 * Get the CSS User that represent a user in the Common Security System for authorization purposes. The 
	 * CSS User will be returned for the application associated to the System user making the call (Security headers)
	 * @param username The username that the Web Service will get the Stations by Application Information  
	 * @return CSS User has associated mainly the application that the user is trying to reach, 
	 * the list of stations that the User has associated for that application. Each station on that list
	 * contains information that shows if the station in available to the user, or if not, the reason why is not available. 
	 * @throws CssUserRepositoryFault 
	 * @throws CssUserRepositoryUnknownFault 
	 */
	@WebMethod
	@Override
	public CssUser getCssUserStationsByApplicationUsername(String username) throws CssUserRepositoryFault, CssUserRepositoryUnknownFault {
		MessageContext ctx;
		UserContext userContext;
		String ipAddress = null;
		String applicationCSSName = null;
		
		gov.va.vba.framework.css.cssiam.domain.entities.CssUser user;
		
		try {
			
			ctx = (MessageContext) wsCtx.getMessageContext();
			userContext = (UserContext)ctx.get(HandlerContext.ATTR_CTX_USERCONTEXT);
		
			if (userContext==null){
				logger.debug("Not user security profile present in the UseContext");
				throw new CSSFrameworkLayerException("Unable to get the User Context from the WS Session");
			}
				
			ipAddress = userContext.getClientIpAddress();
			applicationCSSName = userContext.getApplicationName();
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
