package org.tj.jwsedemo;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

public class JWSEd25519Demo {
    static void log(final Object o) {
        System.out.println("" + o);
    }

    public static void main(String[] args) throws JOSEException {
        log("JWS Ed25519 Demo");

        // Generate Key Pair Using BC
        Security.addProvider(new BouncyCastleProvider());
        final Ed25519KeyPairGenerator ed25519KeyPairGenerator = new Ed25519KeyPairGenerator();
        ed25519KeyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        final AsymmetricCipherKeyPair asymmetricCipherKeyPair = ed25519KeyPairGenerator.generateKeyPair();
        final Ed25519PrivateKeyParameters privateKey = (Ed25519PrivateKeyParameters) asymmetricCipherKeyPair.getPrivate();
        final Ed25519PublicKeyParameters publicKey = (Ed25519PublicKeyParameters) asymmetricCipherKeyPair.getPublic();
        assert privateKey.getEncoded().length == 32;
        assert publicKey.getEncoded().length == 32;
        final String edPrivateKey = Base64.getUrlEncoder().encodeToString(privateKey.getEncoded());
        final String edPublicKey = Base64.getUrlEncoder().encodeToString(publicKey.getEncoded());
        log("edPrivateKey: " + edPrivateKey);
        log("edPublicKey: " + edPublicKey);

        // Creation of OctetKeyPair
        final String x = edPublicKey;
        final String d = edPrivateKey;
        final OctetKeyPair octetKeyPairJWK = new OctetKeyPair.Builder(Curve.Ed25519, new Base64URL(x)).d(new Base64URL(d)).build();
        log("octetKeyPairJWK: " + octetKeyPairJWK.toJSONObject());

        // Signing and creation of JWS
        final JWSSigner signer = new Ed25519Signer(octetKeyPairJWK);
        final String payload = "Edwards, what have you done?";

        final JWSObject jwsObject = new JWSObject(
                new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(octetKeyPairJWK.getKeyID()).build(),
                new Payload(payload));

        jwsObject.sign(signer);

        final String jws = jwsObject.serialize();
        log("jws: " + jws);

        // Verification
        final JWSVerifier verifier = new Ed25519Verifier(octetKeyPairJWK.toPublicJWK());
        assert jwsObject.verify(verifier);
        assert "Edwards, what have you done?".equals(jwsObject.getPayload().toString());
    }
}
