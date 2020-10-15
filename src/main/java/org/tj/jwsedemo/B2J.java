package org.tj.jwsedemo;

import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class B2J {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());

        final byte[] publicKeyBytes = Base64.getUrlDecoder().decode("k_0mKEkDIcl8vdoMJe3WALYBT6gzZQFD97n1SzqgSDI=");
        final KeyFactory keyFactory = KeyFactory.getInstance("Ed25519");
        final SubjectPublicKeyInfo pubKeyInfo = new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), publicKeyBytes);
        final X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubKeyInfo.getEncoded());
        final PublicKey publicKey = keyFactory.generatePublic(x509KeySpec);
        final String encodedB64PubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        System.out.println("encodedB64PubKey: " + encodedB64PubKey);
    }
}
