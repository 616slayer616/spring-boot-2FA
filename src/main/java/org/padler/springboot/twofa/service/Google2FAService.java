package org.padler.springboot.twofa.service;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.SecureRandom;

import static org.apache.commons.codec.CharEncoding.UTF_8;

@Service
public class Google2FAService {

    public static final String SPACE = "%20";
    public static final String PLUS = "+";
    public static final String PARAM_SECRET = "?secret=";
    public static final String PARAM_ISSUER = "&issuer=";
    public static final String PNG = "png";
    public static final String TOTP = "otpauth://totp/";

    public String generateSecretKey() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[20];
        random.nextBytes(bytes);
        Base32 base32 = new Base32();
        return base32.encodeToString(bytes);
    }

    public String getOTP(String secretKey) {
        Base32 base32 = new Base32();
        byte[] bytes = base32.decode(secretKey);
        String hexKey = Hex.encodeHexString(bytes);
        return de.taimos.totp.TOTP.getOTP(hexKey);
    }

    public boolean validateOTP(String otp, String secretKey) {
        return otp.equals(getOTP(secretKey));
    }

    public ByteArrayOutputStream generateQRCode(String secretKey, String account, String issuer, int height, int width)
            throws WriterException, IOException {
        return generateQRCode(generateQRPayload(secretKey, account, issuer), height, width);
    }

    private ByteArrayOutputStream generateQRCode(String barCodeData, int height, int width)
            throws WriterException, IOException {
        BitMatrix matrix = new MultiFormatWriter().encode(barCodeData, BarcodeFormat.QR_CODE,
                width, height);
        try (ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            MatrixToImageWriter.writeToStream(matrix, PNG, out);
            return out;
        }
    }

    private String generateQRPayload(String secretKey, String account, String issuer) {
        try {
            return TOTP
                    + URLEncoder.encode(issuer + ":" + account, UTF_8).replace(PLUS, SPACE)
                    + PARAM_SECRET + URLEncoder.encode(secretKey, UTF_8).replace(PLUS, SPACE)
                    + PARAM_ISSUER + URLEncoder.encode(issuer, UTF_8).replace(PLUS, SPACE);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }


}
