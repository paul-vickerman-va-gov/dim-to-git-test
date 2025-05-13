package gov.va.vba.css.security.service.handler;

import java.util.List;
import java.util.Properties;

import javax.xml.namespace.QName;

public class WssSecurityBean {

    private String keyAlias;
    private String keyPassword;
    private String cryptoFile;
    private String audience;
    private List<QName> encryptExclusions;
    
    protected Properties cryptoproperties;

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getCryptoFile() {
        return cryptoFile;
    }

    public void setCryptoFile(String cryptoFile) {
        this.cryptoFile = cryptoFile;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

	public Properties getCryptoproperties() {
		return cryptoproperties;
	}

	public void setCryptoproperties(Properties cryptoproperties) {
		this.cryptoproperties = cryptoproperties;
	}

	public List<QName> getEncryptExclusions() {
		return encryptExclusions;
	}

	public void setEncryptExclusions(List<QName> encryptExclusions) {
		this.encryptExclusions = encryptExclusions;
	}
}