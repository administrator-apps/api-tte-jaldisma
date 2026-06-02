const { default: signpdf } = require('node-signpdf');
const { plainAddPlaceholder } = require('node-signpdf/dist/helpers');
const forge = require('node-forge');

module.exports = async (req, res) => {
    if (req.method === 'POST') {
        try {
            // Menangkap tambahan passphrase dari Google Apps Script
            const { pdf_base64, pem_string, passphrase } = req.body;
            if (!pdf_base64 || !pem_string) {
                return res.status(400).json({ error: "Data pdf_base64 dan pem_string wajib dikirim." });
            }

            let pdfBuffer = Buffer.from(pdf_base64, 'base64');
            pdfBuffer = plainAddPlaceholder({
                pdfBuffer,
                reason: 'Penandatanganan Elektronik Dokumen JALDISMA',
                signatureLength: 8192,
            });

            const privateKeyPemMatch = pem_string.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/);
            const certPemMatch = pem_string.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
            
            if (!privateKeyPemMatch || !certPemMatch) {
                 return res.status(400).json({ error: "Format Gagal: PRIVATE KEY atau CERTIFICATE tidak ditemukan." });
            }

            const privateKeyPem = privateKeyPemMatch[0];
            const certPem = certPemMatch[0];
            
            let privateKey;
            // LOGIKA DEKRIPSI PASSPHRASE
            if (privateKeyPem.includes('ENCRYPTED')) {
                if (!passphrase) {
                    return res.status(400).json({ error: "Sertifikat terenkripsi, tetapi Passphrase (PIN) tidak dimasukkan di Profil!" });
                }
                // Membuka gembok Private Key menggunakan passphrase
                privateKey = forge.pki.decryptRsaPrivateKey(privateKeyPem, passphrase);
                if (!privateKey) {
                    return res.status(400).json({ error: "Passphrase / PIN yang Anda masukkan salah! Gagal membuka sertifikat." });
                }
            } else {
                privateKey = forge.pki.privateKeyFromPem(privateKeyPem);
            }

            const cert = forge.pki.certificateFromPem(certPem);
            
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
            res.status(500).json({ error: error.message });
        }
    } else {
        res.status(405).json({ error: "Method not allowed" });
    }
};
