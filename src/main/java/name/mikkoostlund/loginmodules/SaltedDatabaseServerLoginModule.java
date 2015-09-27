/* 
 * Copyright (c) 2013, Taylor Hornby [Password Hashing With PBKDF2 (http://crackstation.net/hashing-security.htm)]
 * Copyright (c) 2015, Mikko Östlund
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation 
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */

package name.mikkoostlund.loginmodules;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import org.jboss.security.auth.spi.DatabaseServerLoginModule;

public class SaltedDatabaseServerLoginModule extends DatabaseServerLoginModule {

	private static final String OPT_HASH_SEPARATOR_REGEX = "hashSeparatorRegex";
	private static final String OPT_PBKDF2_ALGORITHM = "pbkdf2Algorithm";
	private static final String OPT_ITERATION_INDEX = "iterationIndex";
	private static final String OPT_SALT_INDEX = "saltIndex";
	private static final String OPT_PBKDF2_INDEX = "pbkdf2Index";

	private static final String[] ALL_VALID_OPTIONS = {
		OPT_PBKDF2_ALGORITHM, OPT_HASH_SEPARATOR_REGEX, OPT_ITERATION_INDEX, OPT_SALT_INDEX, OPT_PBKDF2_INDEX 
	};

	protected String pbkdf2Algorithm = "PBKDF2WithHmacSHA256";
	protected String hashSeparatorRegex = ":";
	protected Integer iterationIndex = 0;
	protected Integer saltIndex = 1;
	protected Integer pbkdf2Index = 2;

	public void initialize(Subject subject, CallbackHandler callbackHandler,
			Map<String, ?> sharedState, Map<String, ?> options) {
		addValidOptions(ALL_VALID_OPTIONS);
		super.initialize(subject, callbackHandler, sharedState, options);
		Object tmp = options.get(OPT_PBKDF2_ALGORITHM);
		if (tmp != null) {
			pbkdf2Algorithm = (String)tmp;
		}
		tmp = options.get(OPT_HASH_SEPARATOR_REGEX);
		if (tmp != null) {
			hashSeparatorRegex = (String)tmp;
		}
		tmp = options.get(OPT_ITERATION_INDEX);
		if (tmp != null) {
			iterationIndex = (Integer)tmp;
		}
		tmp = options.get(OPT_SALT_INDEX);
		if (tmp != null) {
			saltIndex = (Integer)tmp;
		} 
		tmp = options.get(OPT_PBKDF2_INDEX);
		if (tmp != null) {
			pbkdf2Index = (Integer)tmp;
		}
	}

	@Override
	public boolean validatePassword(String inputPassword, String expectedPassword) {
		try {
			return validatePassword(inputPassword.toCharArray(), expectedPassword);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return false;
	}

    /**
     * Validates a password using a hash.
     *
     * @param   inputPassword        the password to check
     * @param   expectedPassword     the hash of the valid password
     * @return                  true if the password is correct, false if not
     */
	public boolean validatePassword(char[] inputPassword, String expectedPassword)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		// Decode the hash into its parameters
		String[] params = expectedPassword.split(hashSeparatorRegex);
		int iterations = Integer.parseInt(params[iterationIndex]);
		byte[] salt = fromHex(params[saltIndex]);
		byte[] hash = fromHex(params[pbkdf2Index]);
		// Compute the hash of the provided password, using the same salt,
		// iteration count, and hash length
		byte[] testHash = pbkdf2(inputPassword, salt, iterations, hash.length);
		// Compare the hashes in constant time. The password is correct if
		// both hashes match.
		return slowEquals(hash, testHash);
	}

    /**
     * Converts a string of hexadecimal characters into a byte array.
     *
     * @param   hex         the hex string
     * @return              the hex string decoded into a byte array
     */
    private static byte[] fromHex(String hex)
    {
        byte[] binary = new byte[hex.length() / 2];
        for(int i = 0; i < binary.length; i++)
        {
            binary[i] = (byte)Integer.parseInt(hex.substring(2*i, 2*i+2), 16);
        }
        return binary;
    }

    /**
     *  Computes the PBKDF2 hash of a password.
     *
     * @param   password    the password to hash.
     * @param   salt        the salt
     * @param   iterations  the iteration count (slowness factor)
     * @param   bytes       the length of the hash to compute in bytes
     * @return              the PBDKF2 hash of the password
     */
    private byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory skf = SecretKeyFactory.getInstance(pbkdf2Algorithm);
        return skf.generateSecret(spec).getEncoded();
    }

    /**
     * Compares two byte arrays in length-constant time. This comparison method
     * is used so that password hashes cannot be extracted from an on-line 
     * system using a timing attack and then attacked off-line.
     * 
     * @param   a       the first byte array
     * @param   b       the second byte array 
     * @return          true if both byte arrays are the same, false if not
     */
    private static boolean slowEquals(byte[] a, byte[] b)
    {
        int diff = a.length ^ b.length;
        for(int i = 0; i < a.length && i < b.length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
