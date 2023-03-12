package com.api.signapp.controllers;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.desafiobry.exceptions.SignatureVerificationException;
import org.desafiobry.exceptions.SigningException;
import org.desafiobry.signingutilities.SignerCertKey;
import org.desafiobry.signingutilities.SigningUtilities;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

@RestController
@CrossOrigin(origins = "*", maxAge = 3600)
@RequestMapping("/")
public class SignAppController {

    SigningUtilities signingUtilities;

    public SignAppController() {
        try {
            this.signingUtilities = new SigningUtilities(new SHA256Digest(), "SHA256WithRSA", new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
        } catch (OperatorCreationException e) {
            // Could not build DigestCalculatorProvider from Bouncy Castle library
            System.exit(1);
        }
    }

    // signFile signs the document present in 'file' with the certificate and private key provided by pfx and protected
    // under 'password'.
    @PostMapping("/signature")
    public ResponseEntity<Object> signFile(@RequestPart("file") MultipartFile file,
                                           @RequestPart("pfx") MultipartFile pfx,
                                           @RequestParam("password") String password) {

        byte[] pfxBytes, fileBytes;
        SignerCertKey signerCertKey;

        try {
            fileBytes = file.getBytes();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Could not read file's bytes");
        }

        try {
            pfxBytes = pfx.getBytes();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Could not read pfx file's bytes");
        }

        try {
            // Visto que o corpo da requisição especificado pelo desafio não contém um campo para o alias,
            // supõe-se que o certificado e chave privada presente no arquivo .pfx não possuem alias.
            // Quando o .pfx não possui um alias, o alias padrão é "1"
            signerCertKey = SigningUtilities.loadCertKeyFromPKCS12(pfxBytes, "1",password.toCharArray());
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Could not load keystore data. Check if " +
                    "the provided file is correct and if password is correct.");
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An internal error occurred while loading " +
                    "the PKCS#12 keystore.");
        } catch (CertificateException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("The certificate of the provided keystore could " +
                    "not be loaded.");
        } catch (UnrecoverableKeyException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("The private key of the provided keystore " +
                    "could not be recovered. The password could be incorrect.");
        }

        X509Certificate signerCertificate = signerCertKey.getX509Certificate();
        PrivateKey signerKey = signerCertKey.getPrivateKey();

        if (signerCertificate == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Could not load certificate from the provided" +
                    "keystore. Note that certificates with alias are not supported.");
        }

        if (signerKey == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Could not load private key from the provided " +
                    "keystore. Note that private keys with alias are not supported.");
        }

        try {
            byte[] signature = signingUtilities.signData(fileBytes, signerKey, signerCertificate);
            // Codificando a assinatura para o formato Base64.
            String base64Signature = Base64.getEncoder().encodeToString(signature);
            return ResponseEntity.status(HttpStatus.OK).body(base64Signature);
        } catch (OperatorCreationException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal error during signature operation.");
        } catch (CertificateEncodingException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("An error occurred when trying encode the " +
                    "signing certificate. Verify if the certificate file is correct.");
        } catch (SigningException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("An error occurred while performing the signature.");
        }
    }

    // verifySignature verifica a assinatura do arquivo assinado 'signedFile'.
    @PostMapping("/verify")
    public ResponseEntity<Object> verifySignature(@RequestPart("file") MultipartFile signedFile) {
        byte[] signedFileBytes;
        boolean validSignature;

        try {
            signedFileBytes = signedFile.getBytes();
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Could not read file's bytes");
        }

        try {
            validSignature = SigningUtilities.verifySignature(signedFileBytes);
        } catch (OperatorCreationException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal error during signature operation.");
        } catch (CertificateException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Certificate error. Verify if the certificate is correct.");
        } catch (IOException | CMSException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("An error occurred while processing the signed " +
                    "data. Verify if the data is correct");
        } catch (SignatureVerificationException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("An error occurred while verifying the signature.");
        }

        String bodyString;
        if (validSignature) {
            bodyString = "VALIDO";
        } else {
            bodyString = "INVALIDO";
        }
        return ResponseEntity.status(HttpStatus.OK).body(bodyString);
    }
}
