/*

 * This class is part of the white paper entitled

 * "Digital Signatures for PDF documents"

 * written by Bruno Lowagie

 * 

 * For more info, go to: http://itextpdf.com/learn

 */



 

import java.io.FileInputStream;

import java.io.FileOutputStream;

import java.io.IOException;

import java.security.GeneralSecurityException;

import java.security.KeyStore;

import java.security.PrivateKey;

import java.security.Security;

import java.security.cert.Certificate;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

 

import com.itextpdf.text.DocumentException;

import com.itextpdf.text.Rectangle;

import com.itextpdf.text.pdf.PdfReader;

import com.itextpdf.text.pdf.PdfSignatureAppearance;

import com.itextpdf.text.pdf.PdfStamper;

import com.itextpdf.text.pdf.security.BouncyCastleDigest;

import com.itextpdf.text.pdf.security.DigestAlgorithms;

import com.itextpdf.text.pdf.security.ExternalDigest;

import com.itextpdf.text.pdf.security.ExternalSignature;

import com.itextpdf.text.pdf.security.MakeSignature;

import com.itextpdf.text.pdf.security.MakeSignature.CryptoStandard;

import com.itextpdf.text.pdf.security.PrivateKeySignature;

 

public class PDF_Sign {

 

    public static final String KEYSTORE = "keyNumbero2.jsk";

    public static final char[] PASSWORD = "provaprova".toCharArray();

    public static final String SRC = "hello_signed7.pdf";

    public static final String DEST = "hello_signed9.pdf";

    

    public void sign(String src, String dest,

            Certificate[] chain,

            PrivateKey pk, String digestAlgorithm, String provider,

            CryptoStandard subfilter,

            String reason, String location)

                    throws GeneralSecurityException, IOException, DocumentException {

        // Creating the reader and the stamper

        PdfReader reader = new PdfReader(src);

        FileOutputStream os = new FileOutputStream(dest);

        PdfStamper stamper = PdfStamper.createSignature(reader, os, '\0', null, true);

        // Creating the appearance

        PdfSignatureAppearance appearance = stamper.getSignatureAppearance();

        appearance.setReason(reason);

        appearance.setLocation(location);

       // appearance.setVisibleSignature( "sig");

        // Creating the signature

        ExternalDigest digest = new BouncyCastleDigest();

        ExternalSignature signature = new PrivateKeySignature(pk, digestAlgorithm, provider);

        MakeSignature.signDetached(appearance, digest, signature, chain, null, null, null, 0, subfilter);

    }

    

    public static void main(String[] args) throws GeneralSecurityException, IOException, DocumentException {
    	
    	Scanner input = new Scanner(System.in);
    	System.out.println("[Inserire path del certificato...]");
    	String keystore = input.next();
    	System.out.println("[Inserire password del certificato...]");
    	char[] password = input.next().toCharArray();
    	System.out.println("[Inserire path del Pdf da firmare...]");
    	String src= input.next();
    	System.out.println("[Inserire path dell'output...]");
    	String dest = input.next();

        BouncyCastleProvider provider = new BouncyCastleProvider();

        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());

        ks.load(new FileInputStream(keystore), password);

        String alias = (String)ks.aliases().nextElement();

        PrivateKey pk = (PrivateKey) ks.getKey(alias, password);

        Certificate[] chain = ks.getCertificateChain(alias);

        PDF_Sign app = new PDF_Sign();

        app.sign(src, String.format(dest, 1), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CMS, "Test 1", "UNISA");

       /* app.sign(src, String.format(dest, 2), chain, pk, DigestAlgorithms.SHA512, provider.getName(), CryptoStandard.CMS, "Test 2", "Ghent");

        app.sign(src, String.format(dest, 3), chain, pk, DigestAlgorithms.SHA256, provider.getName(), CryptoStandard.CADES, "Test 3", "Ghent");

        app.sign(src, String.format(dest, 4), chain, pk, DigestAlgorithms.RIPEMD160, provider.getName(), CryptoStandard.CADES, "Test 4", "Ghent");*/

        System.out.println("[Il documento "+ dest + " è stato firmato con successo!]");
        System.out.println("________________________________________________________");
    }

}
