package com.polytech;


import java.security.*;
import javax.crypto.*;

import java.io.*;

public class SqueletonEntity{

	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
	
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public SqueletonEntity(){
		// INITIALIZATION

		// generate a public/private key
		try{
			// get an instance of KeyPairGenerator  for RSA	
			// Initialize the key pair generator for 1024 length
			// Generate the key pair
			
			// save the public/private key
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}

	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			// use of java.security.Signature
			// Init the signature with the private key

			// update the message
			// sign
			return null;
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// use of java.security.Signature
			// init the signature verification with the public key

			// update the message
			// check the signature
			return false;
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			// Init the signature with the private key

			// get an instance of the java.security.MessageDigest with MD5
			// process the digest
			
			// return the encrypted digest
			return null;
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			// Init the signature with the private key
			// decrypt the signature
			
			// get an instance of the java.security.MessageDigest with MD5
			// process the digest
			
			// check if digest1 == digest2
			return false;

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
			// init the Cipher in ENCRYPT_MODE and aPK
			// use doFinal on the byte[] and return the ciphered byte[]
			return null;
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			// get an instance of RSA Cipher
			// init the Cipher in DECRYPT_MODE and aPK
			// use doFinal on the byte[] and return the deciphered byte[]
			return null;
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}


}