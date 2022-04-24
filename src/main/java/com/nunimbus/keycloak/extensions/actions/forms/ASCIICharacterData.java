package com.nunimbus.keycloak.extensions.actions.forms;

import org.passay.CharacterData;
import org.passay.EnglishCharacterData;

public enum ASCIICharacterData implements CharacterData {

	/** Lower case characters. */
	LowerCase("INSUFFICIENT_LOWERCASE", EnglishCharacterData.LowerCase.getCharacters()),

	/** Upper case characters. */
	UpperCase("INSUFFICIENT_UPPERCASE", EnglishCharacterData.UpperCase.getCharacters()),

	/** Digit characters. */
	Digit("INSUFFICIENT_DIGIT", "0123456789"),

	/** Alphabetical characters (upper and lower case). */
	Alphabetical("INSUFFICIENT_ALPHABETICAL", UpperCase.getCharacters() + LowerCase.getCharacters()),

	/** Special characters. */
	Special("INSUFFICIENT_SPECIAL",
			// ASCII symbols
			"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
	
	ASCII("INSUFFICIENT_ASCII", Alphabetical.getCharacters() + Digit.getCharacters() + Special.getCharacters());

	/** Error code. */
	private final String errorCode;

	/** Characters. */
	private final String characters;

	/**
	 * Creates a new english character data.
	 *
	 * @param code       Error code.
	 * @param charString Characters as string.
	 */
	ASCIICharacterData(final String code, final String charString) {
		errorCode = code;
		characters = charString;
	}

	@Override
	public String getErrorCode() {
		return errorCode;
	}

	@Override
	public String getCharacters() {
		return characters;
	}
}
