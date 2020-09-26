package com.rsa.shamir;


import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class Console {

	/**
	 * The console interface to create an RSA key pair and shard the private key into k of n 
	 * shares using Shamir's secret sharing algorithm
	 *
	 * @author Shahzad Anjum
	 */
	
	public static void main(String[] args) {
		try {

            if (args.length < 1) {
                System.err.println("need at least one argument");
                help();
                System.exit(-1);
            }

            if (args[0].equals("generate-shard-encrypt-reassemble-decrypt-assert")) {
            	if (args.length == 2 && args[1] != null) {
            		
            		String plainText = args[1];
            		
            		int n = 5;
            		int k = 2;
            		
            		generate_encrypt_reassemble_decrypt_assert(n, k, plainText);            	}
            	else 
            	{
                    System.err.println("must provide the plaintext without spaces");
            	}
                
            } 
            else if (args[0].equals("help")) {
                help();
            } else {
                System.err.println("unknown action");
                help();
            }

        } catch (Exception e) {
            System.err.println(e);
            e.printStackTrace();
            System.exit(-1);
        }

	}
	
	/* The command generate_encrypt_reassemble_decrypt_assert performs all 5 steps mentioned below
	 * 1.	Creates the RSA key pair with a Private Key broken into 5 shards.
	2.	Encrypts a random plain text string using the RSA Public Key.
	3.	Reassembles the Private Key using shard 2 & 5.
	4.	Decrypts the cypher text back into the plain text using the reassembled Private Key.
	5.	Asserts the decrypted plain text is equal to the original random plain text in Step 2.
	*/
	 private static void generate_encrypt_reassemble_decrypt_assert(int n, int k, String plainText) throws Exception {
	        
		 //N = 5 (number of shards)
		 //K = 2 (at least 2 shards will be required to decrypt the plain text
		 final Scheme scheme = new Scheme(new SecureRandom(), 5, 2);
		 //final byte[] secret = "hello there".getBytes(StandardCharsets.UTF_8);
		 final byte[] secret = plainText.getBytes(StandardCharsets.UTF_8);
		 final Map<Integer, byte[]> parts = scheme.split(secret);
		
		 System.out.println("Reassembling the Private Key using shard 2 & 5...");
		 final Map<Integer, byte[]> reassembledParts = new HashMap<Integer, byte[]>();
		 reassembledParts.put(2, parts.get(2));
		 reassembledParts.put(5, parts.get(5));
		 
		 
		 final byte[] recovered = scheme.join(parts);
		    
		 System.out.println("Asserting the decrypted plain text is equal to the original random plain text...");
		 System.out.println("Original plain text: " + plainText + "\nRecovered plain text: " + new String(recovered, StandardCharsets.UTF_8));
	}
	 
	
	 
	 
	
	/**
     * prints help to STDOUT
     */
    private static void help() {
        System.out.println("java -jar rsa-cli.jar generate-shard-encrypt-reassemble-decrypt-assert <plainText>");
        System.out.println("--");
        System.out.println("NOTE: plainText should have no spaces");
    }

}
