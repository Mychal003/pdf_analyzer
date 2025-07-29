from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
import os

def create_suspicious_pdf(filename="test_suspicious.pdf"):
    """Create a PDF with suspicious elements for testing"""
    
    # Raw PDF content with JavaScript and other suspicious elements
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
/OpenAction 5 0 R
/AA << /O 5 0 R >>
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Resources <<
/Font <<
/F1 4 0 R
>>
>>
/Contents 6 0 R
>>
endobj

4 0 obj
<<
/Type /Font
/Subtype /Type1
/BaseFont /Helvetica
>>
endobj

5 0 obj
<<
/Type /Action
/S /JavaScript
/JS (app.alert('This is a test malicious PDF!'); this.print();)
>>
endobj

6 0 obj
<<
/Length 100
>>
stream
BT
/F1 12 Tf
50 750 Td
(This is a test PDF with suspicious elements) Tj
ET
endstream
endobj

7 0 obj
<<
/Type /Action
/S /Launch
/F (calc.exe)
>>
endobj

8 0 obj
<<
/Type /Filespec
/F (embedded_file.txt)
/EF << /F 9 0 R >>
>>
endobj

9 0 obj
<<
/Length 20
/Filter [/ASCIIHexDecode]
>>
stream
546869732069732061206D616C696369
endstream
endobj

xref
0 10
0000000000 65535 f 
0000000009 00000 n 
0000000100 00000 n 
0000000157 00000 n 
0000000290 00000 n 
0000000371 00000 n 
0000000474 00000 n 
0000000624 00000 n 
0000000681 00000 n 
0000000748 00000 n 
trailer
<<
/Size 10
/Root 1 0 R
>>
startxref
828
%%EOF"""

    with open(filename, 'w') as f:
        f.write(pdf_content)
    
    print(f"Created suspicious test PDF: {filename}")
    print("This PDF contains:")
    print("- JavaScript code (/JS)")
    print("- Auto-action (/AA)")
    print("- Open action (/OpenAction)")
    print("- Launch action (/Launch)")
    print("- Embedded file (/EmbeddedFile)")

def create_high_object_count_pdf(filename="test_many_objects.pdf"):
    """Create PDF with many objects to trigger high object count warning"""
    
    pdf_start = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 50
>>
stream
BT
/F1 12 Tf
50 750 Td
(Test PDF with many objects) Tj
ET
endstream
endobj

"""
    
    # Generate many dummy objects (1500 objects to trigger warning)
    dummy_objects = ""
    for i in range(5, 1505):
        dummy_objects += f"""{i} 0 obj
<<
/Type /Test
/Value {i}
>>
endobj

"""
    
    # Calculate xref positions
    xref_start = len(pdf_start) + len(dummy_objects)
    
    xref_section = f"""xref
0 1505
0000000000 65535 f 
"""
    
    # Add xref entries for each object
    pos = len("%PDF-1.4\n")
    for line in (pdf_start + dummy_objects).split('\n')[1:]:
        if line.strip().endswith(' 0 obj'):
            xref_section += f"{pos:010d} 00000 n \n"
        pos += len(line) + 1
    
    trailer = f"""trailer
<<
/Size 1505
/Root 1 0 R
>>
startxref
{xref_start}
%%EOF"""
    
    full_content = pdf_start + dummy_objects + xref_section + trailer
    
    with open(filename, 'w') as f:
        f.write(full_content)
    
    print(f"Created high object count PDF: {filename}")
    print(f"Contains 1500+ objects to trigger high object count warning")

def create_encrypted_pdf_simulation(filename="test_encrypted_simulation.pdf"):
    """Create PDF that appears to have encryption elements"""
    
    pdf_content = """%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids [3 0 R]
/Count 1
>>
endobj

3 0 obj
<<
/Type /Page
/Parent 2 0 R
/MediaBox [0 0 612 792]
/Contents 4 0 R
>>
endobj

4 0 obj
<<
/Length 60
>>
stream
BT
/F1 12 Tf
50 750 Td
(This PDF simulates encryption elements) Tj
ET
endstream
endobj

5 0 obj
<<
/Type /Encrypt
/Filter /Standard
/V 1
/R 2
/O <68656C6C6F20776F726C64>
/U <68656C6C6F20776F726C64>
/P -4
>>
endobj

xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000074 00000 n 
0000000131 00000 n 
0000000238 00000 n 
0000000348 00000 n 
trailer
<<
/Size 6
/Root 1 0 R
/Encrypt 5 0 R
>>
startxref
456
%%EOF"""

    with open(filename, 'w') as f:
        f.write(pdf_content)
    
    print(f"Created simulated encrypted PDF: {filename}")
    print("Contains /Encrypt object")

if __name__ == "__main__":
    print("Generating test PDF files for security analysis...")
    print("=" * 50)
    
    create_suspicious_pdf()
    print()
    create_high_object_count_pdf()
    print()
    create_encrypted_pdf_simulation()
    
    print("\nTest files created! You can now test them with your PDF analyzer.")
    print("Expected results:")
    print("- test_suspicious.pdf: HIGH_RISK (JavaScript, Launch, etc.)")
    print("- test_many_objects.pdf: LOW_RISK (high object count)")
    print("- test_encrypted_simulation.pdf: LOW_RISK (encryption)")
