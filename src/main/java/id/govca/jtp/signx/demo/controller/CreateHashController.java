package id.govca.jtp.signx.demo.controller;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.HashMap;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.BouncyCastleDigest;
import com.itextpdf.signatures.IExternalDigest;
import com.itextpdf.signatures.IExternalSignature;
import com.itextpdf.signatures.PdfSignatureAppearance;
import com.itextpdf.signatures.PdfSigner;

import id.govca.jtp.signx.demo.utils.ServerSignature;

@CrossOrigin
@RestController
public class CreateHashController {

	@PostMapping("/signExternal")
	public ResponseEntity<?> signExternal(
			@RequestParam("cert_url") 	String certURL,
			@RequestParam("src_path") 	String source,
			@RequestParam("dest_path") 	String destination,
			@RequestParam("reason") 	String reason,
			@RequestParam("location") 	String location,
			@RequestParam("llx") 		int llx,
			@RequestParam("lly") 		int lly,
			@RequestParam("urx") 		int urx,
			@RequestParam("ury") 		int ury) 
	{
		try {
			CertificateFactory factory = CertificateFactory.getInstance("X.509");
			URL certUrl = new URL(certURL);
			Certificate[] chain = new Certificate[1];
			chain[0] = factory.generateCertificate(certUrl.openStream());
			
			PdfReader reader = new PdfReader(source);
			PdfSigner signer = new PdfSigner(reader, new FileOutputStream(destination), new StampingProperties());

			// Create the signature appearance
	        Rectangle rect = new Rectangle(llx, lly, urx, ury);
	        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
	        appearance
	                .setReason(reason)
	                .setLocation(location)
	                .setPageRect(rect)
	                .setPageNumber(1);
	        signer.setFieldName("sig");

	        IExternalDigest digest = new BouncyCastleDigest();
	        IExternalSignature signature = new ServerSignature();
	        
	        // Sign the document using the detached mode, CMS or CAdES equivalent.
	        signer.signDetached(digest, signature, chain, null, null, null,
	                0, PdfSigner.CryptoStandard.CMS);
	        
	        HashMap<String, String> mapSuccess = new HashMap<>();
			mapSuccess.put("status", "success");
			mapSuccess.put("message", "Berhasil menandatangani berkas PDF");
			
			return new ResponseEntity<Object>(mapSuccess, HttpStatus.OK);
		} catch (IOException | GeneralSecurityException e) {
			
			HashMap<String, String> mapError = new HashMap<>();
			mapError.put("status", "error");
			mapError.put("message", e.getMessage());
			
			return new ResponseEntity<Object>(mapError, HttpStatus.BAD_REQUEST);
		}
		
	}
}
