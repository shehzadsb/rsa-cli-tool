# rsa-cli-tool
CLI program that creates an RSA key pair and shards the private key into k of n shares using Shamir's secret sharing algorithm. You can use libraries for both the RSA key pairs and Shamir Secret Sharing.

## 1.	How to Build the app
mvn package

The maven command will create a JAR file rsa-cli-1.0-jar-with-dependencies.jar in /target directory.

## 2.	How to Run the app
java -jar rsa-cli-1.0-jar-with-dependencies.jar generate-shard-encrypt-reassemble-decrypt-assert thisisyoursecret

The above command will run a test that 
1.	Creates the RSA key pair with a Private Key broken into 5 shards (in the same directory where JAR file exists)
2.	Encrypts a random plain text string using the RSA Public Key.
3.	Reassembles the Private Key using shard 2 & 5.
4.	Decrypts the cypher text back into the plain text using the reassembled Private Key.
5.	Asserts the decrypted plain text is equal to the original random plain text in Step 2.


## 3.	How to other unit tests
There are about 8 other unit tests in the SchemeTest.java. Please run the following maven command to run them:

mvn test


## 4. How to get help

java -jar rsa-cli-1.0-jar-with-dependencies.jar help

