const { default: signpdf } = require('node-signpdf');
const { plainAddPlaceholder } = require('node-signpdf/dist/helpers');
const forge = require('node-forge');

module.exports = async (req, res) => {
    if (req.method === 'POST') {
        try {
            const { pdf_base64, pem_string } = req.body;
            if (!pdf_base64 || !pem_string) {
                return res.status(400).json({ error: "Data pdf_base64 dan pem_string wajib dikirim." });
            }

            // 1. Konversi Base64 PDF menjadi Buffer
            let pdfBuffer = Buffer.from(pdf_base64, 'base64');

            // 2. Tambahkan Ruang Kosong (Placeholder ByteRange)
            pdfBuffer = plainAddPlaceholder({
                pdfBuffer,
                reason: 'Penandatanganan Elektronik Dokumen JALDISMA',
                signatureLength: 8192,
            });

            // 3. Konversi format .pem menjadi P12 Buffer
            const privateKeyPemMatch = pem_string.match(/-----BEGIN (RSA )?PRIVATE KEY-----[\s\S]+?-----END (RSA )?PRIVATE KEY-----/);
            const certPemMatch = pem_string.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
            
            if (!privateKeyPemMatch || !certPemMatch) {
                 return res.status(400).json({ error: "Format sertifikat .pem tidak valid atau tidak lengkap." });
            }

            const privateKey = forge.pki.privateKeyFromPem(privateKeyPemMatch[0]);
            const cert = forge.pki.certificateFromPem(certPemMatch[0]);
            
            const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, cert, '');
            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            const p12Buffer = Buffer.from(p12Der, 'binary');

            // 4. Eksekusi Kriptografi: Suntikkan Sertifikat
            const signedPdfBuffer = signpdf.sign(pdfBuffer, p12Buffer, { passphrase: '' });

            // 5. Kembalikan file PDF
            res.status(200).json({
                success: true,
                signed_pdf_base64: signedPdfBuffer.toString('base64')
            });

        } catch (error) {
            console.error(error);
            res.status(500).json({ error: error.message });
        }
    } else {
        res.status(405).json({ error: "Method not allowed" });
    }
};
