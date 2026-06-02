const express = require('express');
const { default: signpdf } = require('node-signpdf');
const { plainAddPlaceholder } = require('node-signpdf/dist/helpers');
const forge = require('node-forge');

const app = express();
app.use(express.json({ limit: '50mb' }));

app.post('/sign', (req, res) => {
    try {
        const { pdf_base64, pem_string } = req.body;
        if (!pdf_base64 || !pem_string) {
            return res.status(400).json({ error: "Data pdf_base64 dan pem_string wajib dikirim." });
        }

        let pdfBuffer = Buffer.from(pdf_base64, 'base64');
        pdfBuffer = plainAddPlaceholder({
            pdfBuffer,
            reason: 'Penandatanganan Elektronik Dokumen JALDISMA',
            signatureLength: 8192,
        });

        const privateKeyPemMatch = pem_string.match(/-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]+?-----END (RSA )?PRIVATE KEY-----/);
        const certPemMatch = pem_string.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
        
        if (!privateKeyPemMatch || !certPemMatch) {
             return res.status(400).json({ error: "Format sertifikat .pem tidak valid atau tidak lengkap." });
        }

        const privateKeyPem = privateKeyPemMatch[0];
        const certPem = certPemMatch[0];
        
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
        const cert = forge.pki.certificateFromPem(certPem);
        
        const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, cert, '');
        const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
        const p12Buffer = Buffer.from(p12Der, 'binary');

        const signedPdfBuffer = signpdf.sign(pdfBuffer, p12Buffer, { passphrase: '' });

        res.json({
            success: true,
            signed_pdf_base64: signedPdfBuffer.toString('base64')
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
    console.log(`API TTE JALDISMA Berjalan di port ${PORT}`);
});
