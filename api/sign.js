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

            let pdfBuffer = Buffer.from(pdf_base64, 'base64');
            pdfBuffer = plainAddPlaceholder({
                pdfBuffer,
                reason: 'Penandatanganan Elektronik Dokumen JALDISMA',
                signatureLength: 8192,
            });

            // PERBAIKAN: Regex super fleksibel untuk menangkap semua jenis header Private Key
            const privateKeyPemMatch = pem_string.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/);
            const certPemMatch = pem_string.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
            
            if (!privateKeyPemMatch) {
                 return res.status(400).json({ error: "Format Gagal: PRIVATE KEY tidak ditemukan di dalam file .pem." });
            }
            if (!certPemMatch) {
                 return res.status(400).json({ error: "Format Gagal: CERTIFICATE tidak ditemukan di dalam file .pem." });
            }

            const privateKey = forge.pki.privateKeyFromPem(privateKeyPemMatch[0]);
            const cert = forge.pki.certificateFromPem(certPemMatch[0]);
            
            const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, cert, '');
            const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
            const p12Buffer = Buffer.from(p12Der, 'binary');

            const signedPdfBuffer = signpdf.sign(pdfBuffer, p12Buffer, { passphrase: '' });

            res.status(200).json({
                success: true,
                signed_pdf_base64: signedPdfBuffer.toString('base64')
            });

        } catch (error) {
            console.error(error);
            // Menangkap error spesifik jika Private Key terenkripsi butuh Passphrase (PIN)
            if (error.message.includes('encrypted')) {
                return res.status(500).json({ error: "Sertifikat terkunci (Encrypted). Silakan dekripsi file .pem Anda terlebih dahulu atau hubungi Admin." });
            }
            res.status(500).json({ error: error.message });
        }
    } else {
        res.status(405).json({ error: "Method not allowed" });
    }
};
