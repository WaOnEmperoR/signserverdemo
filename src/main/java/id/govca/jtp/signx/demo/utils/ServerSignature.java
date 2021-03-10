package id.govca.jtp.signx.demo.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;

import org.springframework.beans.factory.annotation.Value;

import com.itextpdf.kernel.PdfException;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ServerSignature implements IExternalSignature{

	@Value("${spring.webservices.path}")
	private String signURL;
	
	@Override
	public String getHashAlgorithm() {
		return DigestAlgorithms.SHA256;
	}

	@Override
	public String getEncryptionAlgorithm() {
		return "RSA";
	}

	@Override
	public byte[] sign(byte[] message) throws GeneralSecurityException {

		try {
			URL url = new URL(signURL);
			HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	        conn.setDoOutput(true);
	        conn.setRequestMethod("POST");
	        conn.connect();
	        
	        OutputStream os = conn.getOutputStream();
            os.write(message);
            os.flush();
            os.close();

            InputStream is = conn.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] b = new byte[32];
            int read;
            while ((read = is.read(b)) != -1) {
                baos.write(b, 0, read);
            }

            is.close();
            
            return baos.toByteArray();
		} catch (IOException e) {
			log.error(e.getMessage());
			throw new PdfException(e);
		}
        
	}

}
