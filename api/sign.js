const { default: signpdf } = require('node-signpdf');
const { plainAddPlaceholder } = require('node-signpdf/dist/helpers');

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

            // 2. Siapkan File Sertifikat .p12 BSrE Asli
            const p12Buffer = Buffer.from(p12_base64, 'base64');

            // 3. Eksekusi Kriptografi Langsung menggunakan Passphrase (PIN)
            const signedPdfBuffer = signpdf.sign(pdfBuffer, p12Buffer, { passphrase: passphrase || '' });

            res.status(200).json({
                success: true,
                signed_pdf_base64: signedPdfBuffer.toString('base64')
            });

        } catch (error) {
            console.error(error);
            // Menangkap jika PIN BSrE salah
            if (error.message.includes('mac verify failure') || error.message.includes('PKCS#12 MAC could not be verified')) {
                return res.status(400).json({ error: "Passphrase / PIN Sertifikat Anda Salah!" });
            }
            res.status(500).json({ error: "Gagal memproses sertifikat: " + error.message });
        }
    } else {
        res.status(405).json({ error: "Method not allowed" });
    }
};
