def create_minimal_malicious_pdf():
    """Create minimal PDF with JavaScript for testing"""
    
    content = """%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction<</S/JavaScript/JS(app.alert('Test malicious PDF'))>>>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000108 00000 n 
0000000165 00000 n 
trailer<</Size 4/Root 1 0 R>>
startxref
230
%%EOF"""
    
    with open("malicious_test.pdf", "wb") as f:
        f.write(content.encode('latin-1'))
    
    print("Created malicious_test.pdf")

if __name__ == "__main__":
    create_minimal_malicious_pdf()
