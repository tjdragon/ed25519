package org.tj.jwsedemo;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.EdECPublicKey;

public class ED {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        final KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
        final KeyPair kp = kpg.generateKeyPair();
        System.out.println(kp);

        final EdECPublicKey pk = (EdECPublicKey)kp.getPublic();
        System.out.println(pk);
    }
}
