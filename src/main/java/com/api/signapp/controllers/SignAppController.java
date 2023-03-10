package com.api.signapp.controllers;

import org.example.SignerCertKey;
import org.example.SigningUtilities;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
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

        byte[] fileBytes;
        InputStream pfxInputStream;

        try {
            fileBytes = file.getBytes();
            pfxInputStream = pfx.getInputStream();
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Could not perform signature generation.");
        }

        // Quando o certificado e chave do arquivo .pfx não possuem alias, o alias utilizado é "1".
        SignerCertKey signerCertKey = SigningUtilities.loadCertKeyFromPKCS12(pfxInputStream, "1",password.toCharArray());

        X509Certificate signerCertificate = signerCertKey.getX509Certificate();
        PrivateKey signerKey = signerCertKey.getPrivateKey();

        System.out.println(signerCertificate);
        System.out.println(signerKey);

        try {
            byte[] signature = SigningUtilities.signData(fileBytes, signerKey, signerCertificate);
            String base64Signature = Base64.getEncoder().encodeToString(signature);
            return ResponseEntity.status(HttpStatus.OK).body(base64Signature);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Could not perform signature generation.");
        }
    }
//try {
//        keyStore = KeyStore.getInstance("PKCS12");
//        keyStore.load(pkcs12InputStream, password);
//
//        // Recuperando a chave privada e o certificado da entidade assinante
//        PrivateKey signerKey = (PrivateKey) keyStore.getKey(alias, password);
//        X509Certificate signerCertificate = (X509Certificate) keyStore.getCertificate(alias);
//    } catch (IOException e) {
//        // IOException - if there is an I/O or format problem with the keystore data, if a password is required but not given, or if the given password
//
//    } catch (
//    NoSuchAlgorithmException e) {
//        // NoSuchAlgorithmException - if the algorithm for recovering the key cannot be found
//    } catch (
//    CertificateException e) {
//        // CertificateException - if any of the certificates in the keystore could not be loaded
//    } catch (
//    KeyStoreException e) {
//        // if the keystore has not been initialized (loaded).
//        // Internal error
//    } catch (
//    UnrecoverableKeyException e) {
//        // if the key cannot be recovered (e.g., the given password is wrong).
//    }

    @PostMapping("/verify")
    public ResponseEntity<Object> verifySignature(@RequestPart("file") MultipartFile signedFile) {
        byte[] signedFileBytes;
        try {
            signedFileBytes = signedFile.getBytes();
        } catch (IOException e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Could not perform signature verification.");
        }

        boolean validSignature = false;
        try {
            validSignature = SigningUtilities.verifySignature(signedFileBytes);
        } catch (Exception e) {
            e.printStackTrace();
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
