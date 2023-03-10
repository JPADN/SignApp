package com.api.signapp.controllers;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.example.SignerCertKey;
import org.example.SigningUtilities;
import org.example.exceptions.SignatureVerificationException;
import org.example.exceptions.SigningException;
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
            // Quando o certificado e chave do arquivo .pfx não possuem alias, o alias utilizado é "1".
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
            byte[] signature = SigningUtilities.signData(fileBytes, signerKey, signerCertificate);
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
