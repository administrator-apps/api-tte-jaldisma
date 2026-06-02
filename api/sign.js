const { default: signpdf } = require('node-signpdf');
const { plainAddPlaceholder } = require('node-signpdf/dist/helpers');
const forge = require('node-forge');

module.exports = async (req, res) => {
    if (req.method === 'POST') {
        try {
            const { pdf_base64, p12_base64, passphrase } = req.body;
            
            if (!pdf_base64 || !p12_base64) {
                return res.status(400).json({ error: "Data PDF dan File Sertifikat wajib dikirim." });
            }

            // 1. Siapkan PDF
            let pdfBuffer = Buffer.from(pdf_base64, 'base64');
            pdfBuffer = plainAddPlaceholder({
                pdfBuffer,
                reason: 'Penandatanganan Elektronik Dokumen JALDISMA',
                signatureLength: 8192,
            });

            // 2. Baca file yang diunggah
            let p12Buffer = Buffer.from(p12_base64, 'base64');
            let decodedString = p12Buffer.toString('utf8');
            let finalPassphrase = passphrase || '';

            // =========================================================
            // AUTO-DETECT: Apakah ini file teks (.pem) atau biner (.p12)
            // =========================================================
            if (decodedString.includes('-----BEGIN')) {
                // JIKA USER MENGUNGGAH FILE .PEM (TEKS)
                const privateKeyPemMatch = decodedString.match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----/);
                const certPemMatch = decodedString.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/);
                
                if (!privateKeyPemMatch || !certPemMatch) {
                     return res.status(400).json({ error: "Sertifikat teks (.pem) tidak memiliki kunci/sertifikat yang lengkap." });
                }

                let privateKey;
                if (privateKeyPemMatch[0].includes('ENCRYPTED')) {
                    if (!passphrase) return res.status(400).json({ error: "Sertifikat .pem ini digembok. Butuh Passphrase / PIN!" });
                    
                    privateKey = forge.pki.decryptRsaPrivateKey(privateKeyPemMatch[0], passphrase);
                    if (!privateKey) return res.status(400).json({ error: "Passphrase / PIN Salah untuk membuka file .pem ini." });
                } else {
                    privateKey = forge.pki.privateKeyFromPem(privateKeyPemMatch[0]);
                }

                const cert = forge.pki.certificateFromPem(certPemMatch[0]);
                
                // Konversi .pem menjadi .p12 biner di memori
                const p12Asn1 = forge.pkcs12.toPkcs12Asn1(privateKey, cert, '');
                const p12Der = forge.asn1.toDer(p12Asn1).getBytes();
                p12Buffer = Buffer.from(p12Der, 'binary');
                finalPassphrase = ''; // Passphrase direset karena file p12 di memori tidak di-password
            }

            // 3. Eksekusi Kriptografi Akhir
            const signedPdfBuffer = signpdf.sign(pdfBuffer, p12Buffer, { passphrase: finalPassphrase });

            res.status(200).json({
                success: true,
                signed_pdf_base64: signedPdfBuffer.toString('base64')
            });

        } catch (error) {
            console.error(error);
            if (error.message.includes('mac verify failure') || error.message.includes('PKCS#12 MAC could not be verified')) {
                return res.status(400).json({ error: "Passphrase / PIN Sertifikat Anda Salah!" });
            }
            if (error.message.includes('Too few bytes to read')) {
                return res.status(400).json({ error: "File sertifikat rusak. Silakan unggah ulang file sertifikat Anda di Profil." });
            }
            res.status(500).json({ error: "Gagal memproses sertifikat: " + error.message });
        }
    } else {
        res.status(405).json({ error: "Method not allowed" });
    }
};
