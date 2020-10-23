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

//        KeyFactory kf = KeyFactory.getInstance("EdDSA");
//        boolean xOdd = ...
//        BigInteger y = ...
//        NamedParameterSpec paramSpec = new NamedParameterSpec("Ed25519");
//        EdECPublicKeySpec pubSpec = new EdECPublicKeySpec(paramSpec, new EdPoint(xOdd, y));
//        PublicKey pubKey = kf.generatePublic(pubSpec);
    }
}
