package com.nunimbus.keycloak.extensions.actions.forms;

import org.keycloak.Config;
import org.keycloak.authentication.FormAction;
import org.keycloak.authentication.FormActionFactory;
import org.keycloak.authentication.FormContext;
import org.keycloak.authentication.forms.RegistrationPage;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
//import org.keycloak.models.GroupModel;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.messages.Messages;
import org.passay.PasswordGenerator;
import org.passay.CharacterRule;

import javax.ws.rs.core.MultivaluedMap;

import java.util.ArrayList;
import java.util.List;

/**
* Registration flow which adds encrypted attributes to the user's profile.
* 
* REQUIRES:
* - nextcloud.custom theme
* 
* REQUIRED BY:
* - `encrypted-attribute-mapper-saml` extension.
* 
* To enable:
* - Authentication > Flows
* - Create a copy of the Registration flow
* - Under the "Copy Of Registration Registration Form" Auth Type, click
*   Actions > Add execution
* - Select "Generate Encrypted Attributes"
*
* @author Andrew Summers
* @version $Revision: 1 $
*/
public class RegistrationGenerateEncryptedAttributes implements FormAction, FormActionFactory {
    public static final String PROVIDER_ID = "registration-encrypted-attributes"; // max 36 char

    @Override
    public String getHelpText() {
        return "Adds encrypted attributes to the user's profile.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return null;
    }

    @Override
    public void validate(org.keycloak.authentication.ValidationContext context) {
    	MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        formData.containsKey("hardened-encryption");
        
    	if (
    			formData.containsKey("hardened-encryption") && 
    			formData.getFirst("hardened-encryption").equals("on")
    	) {
    		if (
    				(
    					formData.containsKey("encryption-message") &&
    					! formData.getFirst("encryption-message").equals("I understand the risks of forgetting my password.")
    				) || ! formData.containsKey("encryption-message")    				
    		) {
    	        errors.add(new FormMessage("hardened-encryption", "You must precisely type the message to agree to enabling hardened encryption."));
    		}
    	}

        if (errors.size() > 0) {
        	context.error(Errors.INVALID_REGISTRATION);
        	context.validationError(formData, errors);
            return;

        } else {
            context.success();
        }
        return;
    }

    @Override
    public void success(FormContext context) {
    	MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
    	Boolean hardenedEncryption = false;

    	if (
    			formData.containsKey("hardened-encryption") && 
    			formData.getFirst("hardened-encryption").equals("on")
    	) {
    		hardenedEncryption = true;
    	}

    	UserModel user = context.getUser();
        
        CharacterRule ascii = new CharacterRule(ASCIICharacterData.ASCII); 
		PasswordGenerator passwordGenerator = new PasswordGenerator();
		String key = passwordGenerator.generatePassword(128, ascii);
		String encrypted = "";

		if (hardenedEncryption == true) {			
			try {
		    	String password = formData.getFirst(RegistrationPage.FIELD_PASSWORD);
				encrypted = CryptoUtils.encrypt(key, password);
				user.setSingleAttribute("passwordEncryptionKey", encrypted);

/**/
		    	System.err.println("REGISTRATION: Creating pw-encrypted values:");
		    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				System.err.println("Encrypted: " + encrypted.substring(0, 8));
				System.err.println("Password:  " + password);
				System.err.println("Key:       " + key.substring(0, 8));
				System.err.println();
				System.err.println();
/**/
			} catch (Exception e) {
				System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				//e.printStackTrace();
			}
		}
		else {
			try {
		        String credential = user.credentialManager().getStoredCredentialsStream().findFirst().get().getValue();
		        encrypted = CryptoUtils.encrypt(key, credential);
				user.setSingleAttribute("encryptionKey", encrypted);

/**/
		        System.err.println("REGISTRATION: Creating credential encrypted values:");
		    	System.err.println(new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				encrypted = CryptoUtils.encrypt(key, credential);
				System.err.println("Encrypted:   " + encrypted.substring(0, 8));
				System.err.println("Credential:  " + credential.substring(0, 8));
				System.err.println("Key:         " + key.substring(0, 8));
				System.err.println();
				System.err.println();
/**/
			} catch (Exception e) {
				System.err.println("ERROR: " + new Throwable().getStackTrace()[0].getFileName() + ":" + new Throwable().getStackTrace()[0].getLineNumber());
				//e.printStackTrace();
			}
		}
    }

    @Override
    public void buildPage(FormContext context, LoginFormsProvider form) {
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }


    @Override
    public void close() {

    }

    @Override
    public String getDisplayType() {
        return "Generate Encrypted Attributes";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    private static AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };
    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }
    @Override
    public FormAction create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {

    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}