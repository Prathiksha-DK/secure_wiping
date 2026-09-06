#!/usr/bin/env python3
import io, os, sys, json, shutil, zipfile, unittest, tempfile
from pathlib import Path

FARIS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(FARIS_ROOT))
sys.path.insert(0, str(FARIS_ROOT / 'application'))

from analysis.artifact_discovery import artifact_discovery_engine
from recovery.file_carving import FileCarver, classify_carved_payload
from validation.recovery_validator import recovery_validator
from application.faris_api import faris_api
from core.paths import resolve_case_dir

class TestWholeDeviceRecoveryEnhancements(unittest.TestCase):
    def test_01_fls_regex_nested_directories_and_inodes(self):
        sample_fls_output = """
d/d 4: Documents
+ r/r 5: Documents/report.pdf
+ d/d 6: Documents/SubFolder
++ r/r 7: Documents/SubFolder/literature_study.docx
+ r/- * 8: Documents/_deleted_notes.txt
r/r 9(realloc): root_data.xlsx
d/d * 10: DeletedDir
+ r/r 11: DeletedDir/evidence.doc
r/r 12-144-1: complex_inode_file.txt
"""
        import re
        line_pattern = re.compile(r"^\s*([\+\*]*\s*)([a-z\-\*\+]+/[a-z\-\*\+]+)\s+(\*?\s*)([\d\-\(\)\w]+):\s*(.+)$")
        parsed_entries = []
        for line in sample_fls_output.strip().splitlines():
            m = line_pattern.match(line.strip())
            self.assertIsNotNone(m, f"Failed to match fls line: {line}")
            prefix, entry_type, del_marker, inode, filepath = m.groups()
            is_deleted = "*" in del_marker or "*" in prefix or "-" in entry_type or entry_type.startswith("r/-")
            is_dir = entry_type.startswith("d")
            clean_name = filepath.strip()
            cat = "directory" if is_dir else artifact_discovery_engine.categorize_filename(clean_name)
            parsed_entries.append({
                "inode": inode.strip(),
                "filepath": clean_name,
                "filename": Path(clean_name).name,
                "is_directory": is_dir,
                "is_deleted": is_deleted,
                "category": cat
            })
        self.assertEqual(len(parsed_entries), 9)
        pdf_entry = next(e for e in parsed_entries if e["filename"] == "report.pdf")
        self.assertEqual(pdf_entry["filepath"], "Documents/report.pdf")
        self.assertEqual(pdf_entry["category"], "document")
        self.assertFalse(pdf_entry["is_deleted"])
        docx_entry = next(e for e in parsed_entries if e["filename"] == "literature_study.docx")
        self.assertEqual(docx_entry["filepath"], "Documents/SubFolder/literature_study.docx")
        self.assertEqual(docx_entry["category"], "document")
        del_entry = next(e for e in parsed_entries if e["filename"] == "_deleted_notes.txt")
        self.assertEqual(del_entry["filepath"], "Documents/_deleted_notes.txt")
        self.assertTrue(del_entry["is_deleted"])
        xlsx_entry = next(e for e in parsed_entries if e["filename"] == "root_data.xlsx")
        self.assertEqual(xlsx_entry["category"], "document")
        self.assertEqual(xlsx_entry["inode"], "9(realloc)")

    def test_02_docx_and_xlsx_carver_classification(self):
        docx_bio = io.BytesIO()
        with zipfile.ZipFile(docx_bio, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
            zf.writestr("word/document.xml", '<w:document><w:body><w:p><w:r><w:t>Forensic Document Test</w:t></w:r></w:p></w:body></w:document>')
        docx_bytes = docx_bio.getvalue()
        name, code, ext = classify_carved_payload("zip", docx_bytes)
        self.assertEqual(code, "docx")
        self.assertEqual(ext, "docx")
        self.assertIn("Word Document", name)

        xlsx_bio = io.BytesIO()
        with zipfile.ZipFile(xlsx_bio, "w") as zf:
            zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types></Types>')
            zf.writestr("xl/workbook.xml", '<workbook></workbook>')
        xlsx_bytes = xlsx_bio.getvalue()
        name, code, ext = classify_carved_payload("zip", xlsx_bytes)
        self.assertEqual(code, "xlsx")
        self.assertEqual(ext, "xlsx")
        self.assertIn("Excel", name)

        zip_bio = io.BytesIO()
        with zipfile.ZipFile(zip_bio, "w") as zf:
            zf.writestr("file.txt", "Plain text in zip")
        zip_bytes = zip_bio.getvalue()
        name, code, ext = classify_carved_payload("zip", zip_bytes)
        self.assertEqual(code, "zip")
        self.assertEqual(ext, "zip")

    def test_03_carver_stream_multi_format_and_chunk_boundary(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "carved_out"
            out_dir.mkdir()
            pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n99\n%%EOF\n"
            docx_bio = io.BytesIO()
            with zipfile.ZipFile(docx_bio, "w") as zf:
                zf.writestr("[Content_Types].xml", '<Types></Types>')
                zf.writestr("word/document.xml", '<w:doc></w:doc>')
            docx_data = docx_bio.getvalue()
            rtf_data = b"{\\rtf1\\ansi\\deff0 {\\fonttbl {\\f0 Courier;}}\\fs24 Test Forensic RTF\\par}"
            stream_data = bytearray(b"\x00" * 512)
            stream_data.extend(pdf_data)
            stream_data.extend(b"\x00" * (512 - (len(pdf_data) % 512)))
            stream_data.extend(docx_data)
            stream_data.extend(b"\x00" * (512 - (len(docx_data) % 512)))
            stream_data.extend(rtf_data)
            stream_data.extend(b"\x00" * 1024)
            carver = FileCarver(chunk_size=1024, sector_size=512)
            records = carver.carve_stream(io.BytesIO(bytes(stream_data)), out_dir, source_name="test_stream")
            self.assertGreaterEqual(len(records), 2)
            extensions = [r["extension"] for r in records]
            self.assertIn("pdf", extensions)
            self.assertIn("docx", extensions)

    def test_04_recovery_validator_all_document_formats(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            txt_file = p / "evidence_notes.txt"
            txt_file.write_text("Case evidence recovered from target storage drive.\nExaminer: Forensics Lab\nStatus: Verified.", encoding="utf-8")
            res_txt = recovery_validator.validate_file(txt_file)
            self.assertEqual(res_txt["validation_status"], "VALID")
            self.assertEqual(res_txt["confidence"], "HIGH")

            csv_file = p / "financial_data.csv"
            csv_file.write_text("id,name,amount\n1,Alice,500.00\n2,Bob,750.50\n", encoding="utf-8")
            res_csv = recovery_validator.validate_file(csv_file)
            self.assertEqual(res_csv["validation_status"], "VALID")

            pdf_file = p / "document.pdf"
            pdf_file.write_bytes(b"%PDF-1.5\n%Header\n1 0 obj << /Type /Catalog >> endobj\nxref\ntrailer << /Size 1 >>\nstartxref\n50\n%%EOF\n")
            res_pdf = recovery_validator.validate_file(pdf_file)
            self.assertEqual(res_pdf["validation_status"], "VALID")
            self.assertEqual(res_pdf["confidence"], "HIGH")

            docx_file = p / "literature_study.docx"
            with zipfile.ZipFile(docx_file, "w") as zf:
                zf.writestr("[Content_Types].xml", '<Types></Types>')
                zf.writestr("word/document.xml", '<w:doc>Valid Document Content</w:doc>')
            res_docx = recovery_validator.validate_file(docx_file)
            self.assertEqual(res_docx["validation_status"], "VALID")
            self.assertEqual(res_docx["confidence"], "HIGH")
            self.assertIn("Word Document", res_docx["reason"])

            rtf_file = p / "notes.rtf"
            rtf_file.write_bytes(b"{\\rtf1\\ansi\\deff0 {\\fonttbl{\\f0 Times;}}\\fs20 Valid RTF document}")
            res_rtf = recovery_validator.validate_file(rtf_file)
            self.assertEqual(res_rtf["validation_status"], "VALID")

    def test_05_export_preserves_directory_hierarchies(self):
        test_case_id = f"test_exp_{int(os.getpid())}"
        case_dir = resolve_case_dir(test_case_id)
        try:
            fs_tree = case_dir / "recovery" / "filesystem_tree"
            sub_dir = fs_tree / "SecureWipe_Test" / "NestedDocs"
            sub_dir.mkdir(parents=True, exist_ok=True)
            doc1 = sub_dir / "literature_study.docx"
            doc1.write_bytes(b"PK\x03\x04" + b"\x00" * 200 + b"word/document.xml" + b"\x00" * 100)
            pdf1 = fs_tree / "SecureWipe_Test" / "case_review.pdf"
            pdf1.write_bytes(b"%PDF-1.4\nSample Evidence PDF\n%%EOF")
            txt1 = fs_tree / "evidence.txt"
            txt1.write_text("Important root evidence", encoding="utf-8")

            with tempfile.TemporaryDirectory() as export_dest:
                res = faris_api.export_verified_artifacts(test_case_id, export_dest)
                self.assertEqual(res["status"], "SUCCESS")
                self.assertGreaterEqual(res["exported_count"], 3)
                dest_p = Path(export_dest)
                self.assertTrue((dest_p / "SecureWipe_Test" / "NestedDocs" / "literature_study.docx").exists())
                self.assertTrue((dest_p / "SecureWipe_Test" / "case_review.pdf").exists())
                self.assertTrue((dest_p / "evidence.txt").exists())
        finally:
            if case_dir.exists():
                shutil.rmtree(case_dir, ignore_errors=True)

if __name__ == "__main__":
    unittest.main()
