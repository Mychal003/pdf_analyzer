from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.enums import TA_CENTER, TA_LEFT
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

def generuj_testowy_pdf_z_linkami():
    """
    Generuje testowy plik PDF zawierający różne typy linków - bezpieczne oraz potencjalnie niebezpieczne
    """
    nazwa_pliku = "test_pdf_z_linkami.pdf"
    doc = SimpleDocTemplate(nazwa_pliku, pagesize=A4)
    
    # Style
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Tytul', fontName='Helvetica-Bold', fontSize=16, alignment=TA_CENTER, spaceAfter=20))
    styles.add(ParagraphStyle(name='Naglowek', fontName='Helvetica-Bold', fontSize=14, spaceBefore=15, spaceAfter=10))
    styles.add(ParagraphStyle(name='Link', fontName='Helvetica', fontSize=12, spaceBefore=5, spaceAfter=5))
    styles.add(ParagraphStyle(name='Opis', fontName='Helvetica-Oblique', fontSize=10, textColor=colors.gray, spaceBefore=2, spaceAfter=10))
    
    # Zawartość
    elementy = []
    
    # Tytuł
    elementy.append(Paragraph("Testowy plik PDF z różnymi typami linków", styles['Tytul']))
    elementy.append(Spacer(1, 20))
    
    # Bezpieczne linki
    elementy.append(Paragraph("Bezpieczne linki (HTTPS)", styles['Naglowek']))
    elementy.append(Paragraph("<a href='https://www.gov.pl/'>https://www.gov.pl/</a> - Oficjalna strona rządowa Polski", styles['Link']))
    elementy.append(Paragraph("<a href='https://www.pzu.pl/'>https://www.pzu.pl/</a> - Strona firmy ubezpieczeniowej", styles['Link']))
    elementy.append(Paragraph("<a href='https://www.nask.pl/'>https://www.nask.pl/</a> - NASK - Naukowa i Akademicka Sieć Komputerowa", styles['Link']))
    elementy.append(Paragraph("Te linki są bezpieczne, ponieważ używają protokołu HTTPS i prowadzą do zaufanych domen.", styles['Opis']))
    
    # Linki HTTP (nieszyfrowane)
    elementy.append(Paragraph("Linki nieszyfrowane (HTTP)", styles['Naglowek']))
    elementy.append(Paragraph("<a href='http://example.com/'>http://example.com/</a> - Przykładowa domena", styles['Link']))
    elementy.append(Paragraph("<a href='http://info.cern.ch/'>http://info.cern.ch/</a> - Pierwsza strona WWW w historii", styles['Link']))
    elementy.append(Paragraph("Te linki używają niezabezpieczonego protokołu HTTP, co może stanowić zagrożenie dla bezpieczeństwa.", styles['Opis']))
    
    # Skrócone linki
    elementy.append(Paragraph("Skrócone linki", styles['Naglowek']))
    elementy.append(Paragraph("<a href='https://bit.ly/3lKfKU9'>https://bit.ly/3lKfKU9</a> - Skrócony link do jakiejś strony", styles['Link']))
    elementy.append(Paragraph("<a href='https://tinyurl.com/2jc9uv8p'>https://tinyurl.com/2jc9uv8p</a> - Inny skrócony link", styles['Link']))
    elementy.append(Paragraph("Skrócone linki ukrywają docelowy adres URL, co może być wykorzystane w atakach phishingowych.", styles['Opis']))
    
    # Linki z nietypowymi TLD
    elementy.append(Paragraph("Linki z nietypowymi rozszerzeniami domen", styles['Naglowek']))
    elementy.append(Paragraph("<a href='https://example.xyz/'>https://example.xyz/</a> - Domena z rozszerzeniem .xyz", styles['Link']))
    elementy.append(Paragraph("<a href='https://example.tk/'>https://example.tk/</a> - Domena z rozszerzeniem .tk (darmowe domeny)", styles['Link']))
    elementy.append(Paragraph("Nietypowe rozszerzenia domen (.xyz, .tk, .ml itp.) są często używane przez oszustów, ponieważ są tanie lub darmowe.", styles['Opis']))
    
    # Linki z adresami IP
    elementy.append(Paragraph("Linki zawierające adresy IP", styles['Naglowek']))
    elementy.append(Paragraph("<a href='http://192.168.1.1/'>http://192.168.1.1/</a> - Link do routera lokalnego", styles['Link']))
    elementy.append(Paragraph("<a href='https://104.18.22.164/'>https://104.18.22.164/</a> - Link do serwera za pomocą IP", styles['Link']))
    elementy.append(Paragraph("Linki zawierające adresy IP zamiast nazw domen mogą wskazywać na próbę oszustwa, ponieważ ukrywają prawdziwą nazwę domeny.", styles['Opis']))
    
    # Linki do plików
    elementy.append(Paragraph("Linki do plików", styles['Naglowek']))
    elementy.append(Paragraph("<a href='https://example.com/download.exe'>https://example.com/download.exe</a> - Link do pliku wykonywalnego", styles['Link']))
    elementy.append(Paragraph("<a href='https://example.com/dokument.pdf'>https://example.com/dokument.pdf</a> - Link do innego PDF", styles['Link']))
    elementy.append(Paragraph("Linki do plików wykonywalnych mogą stanowić poważne zagrożenie bezpieczeństwa.", styles['Opis']))
    
    # Generowanie dokumentu
    doc.build(elementy)
    print(f"Wygenerowano testowy plik PDF: {nazwa_pliku}")

if __name__ == "__main__":
    print("Generating test PDF files for security analysis...")
    print("=" * 50)
    
    create_suspicious_pdf()
    print()
    create_high_object_count_pdf()
    print()
    create_encrypted_pdf_simulation()
    print()
    generuj_testowy_pdf_z_linkami()
    
    print("\nTest files created! You can now test them with your PDF analyzer.")
    print("Expected results:")
    print("- test_suspicious.pdf: HIGH_RISK (JavaScript, Launch, etc.)")
    print("- test_many_objects.pdf: LOW_RISK (high object count)")
    print("- test_encrypted_simulation.pdf: LOW_RISK (encryption)")
    print("- test_pdf_z_linkami.pdf: LOW_RISK (various links)")
