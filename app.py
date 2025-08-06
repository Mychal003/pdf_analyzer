from flask import Flask, request, jsonify, render_template
import os
import json
import tempfile
import logging
from werkzeug.utils import secure_filename
from pdfid import PDFiD, PDFiD2JSON
import uuid
from datetime import datetime
from flask import Flask, request, jsonify, render_template
from flask_talisman import Talisman
import fitz  # PyMuPDF
import re


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

Talisman(app, 
    force_https=False,
    strict_transport_security=False,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
    },
)


if os.name == 'nt':  # Windows
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'temp_uploads')
    log_file = os.path.join(os.getcwd(), 'logs', 'pdf_analyzer.log')
else:  # Linux/Mac
    app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'temp_uploads')
    log_file = os.path.join(os.getcwd(), 'logs', 'pdf_analyzer.log')

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.dirname(log_file), exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler()
    ]
)

ALLOWED_EXTENSIONS = {'pdf'}
DANGER_KEYWORDS = ['/JS', '/JavaScript', '/AA', '/OpenAction', '/Launch', '/EmbeddedFile']

TRANSLATIONS = {
    'No file provided': 'Nie przesłano pliku',
    'No file selected': 'Nie wybrano pliku',
    'Only PDF files are allowed': 'Dozwolone są tylko pliki PDF',
    'File processing failed': 'Przetwarzanie pliku nie powiodło się',
    'Analysis failed': 'Analiza nie powiodła się',
    'PDF is encrypted': 'PDF jest zaszyfrowany',
    'High number of objects': 'Duża liczba obiektów'
}

def translate_message(message):
    """Translate message to Polish"""
    return TRANSLATIONS.get(message, message)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_delete_file(file_path):
    """Securely delete file by overwriting with zeros before deletion"""
    try:
        if not os.path.exists(file_path):
            return True
            
        # Get file size
        file_size = os.path.getsize(file_path)
        
        # Overwrite file with zeros multiple times for security
        with open(file_path, 'r+b') as f:
            # First pass: zeros
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())  # Force write to disk
            
            # Second pass: random data
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
            
            # Third pass: zeros again
            f.seek(0)
            f.write(b'\x00' * file_size)
            f.flush()
            os.fsync(f.fileno())
        
        # Finally delete the file
        os.remove(file_path)
        logging.info(f"File securely deleted: {file_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error securely deleting file {file_path}: {str(e)}")
        # Fallback to regular deletion
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.warning(f"File deleted with fallback method: {file_path}")
        except:
            logging.error(f"Failed to delete file even with fallback: {file_path}")
        return False

def extract_links_from_pdf(file_path):
    """Extract links from PDF and analyze them for potential risks"""
    links = []
    suspicious_domains = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'rebrand.ly',
        'tiny.cc', 'tr.im', 'cutt.ly', 'shorturl.at', 'rb.gy', 'soo.gd'
    ]
    
    try:
        doc = fitz.open(file_path)
        for page_num in range(len(doc)):
            page = doc[page_num]
            page_links = page.get_links()
            
            for link in page_links:
                if 'uri' in link:
                    url = link['uri']
                    is_suspicious = False
                    reason = []
                    
                    # Check for URL shorteners
                    for domain in suspicious_domains:
                        if domain in url.lower():
                            is_suspicious = True
                            reason.append("skrócony URL")
                            break
                    
                    # Check for non-HTTPS
                    if url.startswith('http://'):
                        is_suspicious = True
                        reason.append("nieszyfrowane połączenie")
                    
                    # Check for unusual TLDs
                    unusual_tlds = ['.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf']
                    for tld in unusual_tlds:
                        if url.lower().endswith(tld):
                            is_suspicious = True
                            reason.append(f"nietypowa domena {tld}")
                            break
                    
                    # Check for IP addresses in URLs
                    if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
                        is_suspicious = True
                        reason.append("adres IP zamiast domeny")
                    
                    links.append({
                        'url': url,
                        'page': page_num + 1,
                        'suspicious': is_suspicious,
                        'reason': ", ".join(reason) if reason else None
                    })
        
        return links
    
    except Exception as e:
        logging.error(f"Error extracting links: {str(e)}")
        return []

def analyze_pdf_safety(file_path):
    """Analyze PDF and return safety assessment"""
    try:
        xmlDoc = PDFiD(file_path, allNames=False, extraData=True, disarm=False, force=False)
        
        # Convert to JSON for easier processing
        json_result = PDFiD2JSON(xmlDoc, False)
        data = json.loads(json_result)[0]['pdfid']
        
        # Extract links from the PDF
        links = extract_links_from_pdf(file_path)
        
        # Add suspicious links to risk assessment
        suspicious_links_count = sum(1 for link in links if link['suspicious'])
        
        # Safety assessment logic
        risk_score = 0
        warnings = []
        
        # Binary content analysis - each bit represents presence of specific element
        content_binary = {
            'javascript': 0,      # bit 0: JavaScript code
            'actions': 0,         # bit 1: Automatic actions
            'launch': 0,          # bit 2: Launch actions
            'embedded': 0,        # bit 3: Embedded files
            'forms': 0,           # bit 4: Forms
            'encryption': 0,      # bit 5: Encryption
            'large_objects': 0,   # bit 6: Large number of objects
            'xfa': 0              # bit 7: XFA forms
        }
        
        # Check for dangerous elements and update binary code
        for keyword in data['keywords']['keyword']:
            name = keyword['name']
            count = keyword['count']
            
            if name in ['/JS', '/JavaScript'] and count > 0:
                risk_score += count * 15
                warnings.append(f"Zawiera {count} wystąpień JavaScript")
                content_binary['javascript'] = 1
                
            elif name in ['/AA', '/OpenAction'] and count > 0:
                risk_score += count * 12
                warnings.append(f"Zawiera {count} automatycznych akcji")
                content_binary['actions'] = 1
                
            elif name == '/Launch' and count > 0:
                risk_score += count * 20
                warnings.append(f"Zawiera {count} akcji uruchamiania")
                content_binary['launch'] = 1
                
            elif name == '/EmbeddedFile' and count > 0:
                risk_score += count * 8
                warnings.append(f"Zawiera {count} osadzonych plików")
                content_binary['embedded'] = 1
                
            elif name in ['/AcroForm', '/XFA'] and count > 0:
                if name == '/XFA':
                    risk_score += count * 5
                    content_binary['xfa'] = 1
                    warnings.append(f"Zawiera {count} formularzy XFA")
                else:
                    content_binary['forms'] = 1
        
        # Check for encryption
        encrypt_count = next((k['count'] for k in data['keywords']['keyword'] if k['name'] == '/Encrypt'), 0)
        if encrypt_count > 0:
            risk_score += 3
            warnings.append("PDF jest zaszyfrowany")
            content_binary['encryption'] = 1
        
        # Check for suspicious object counts
        obj_count = next((k['count'] for k in data['keywords']['keyword'] if k['name'] == 'obj'), 0)
        if obj_count > 1000:
            risk_score += 5
            warnings.append(f"Duża liczba obiektów: {obj_count}")
            content_binary['large_objects'] = 1
        
        # Traktuj wszystkie pliki PDF z linkami jako niebezpieczne
        if len(links) > 0:
            # Dodaj co najmniej 15 punktów ryzyka za obecność linków
            risk_score += max(15, len(links) * 3)
            warnings.append(f"Wykryto {len(links)} linków - każdy link może stanowić zagrożenie bezpieczeństwa!")
        
        # Convert binary analysis to string
        binary_string = ''.join([
            str(content_binary['javascript']),
            str(content_binary['actions']),
            str(content_binary['launch']),
            str(content_binary['embedded']),
            str(content_binary['forms']),
            str(content_binary['encryption']),
            str(content_binary['large_objects']),
            str(content_binary['xfa'])
        ])
        
        # Generate error code based on binary analysis
        binary_int = int(binary_string, 2) if binary_string != '00000000' else 0
        error_code = f"PDF-{binary_int:03d}"
        
        # Determine safety level
        if len(links) > 0:
            # Każdy PDF z linkami jest co najmniej MEDIUM_RISK
            if risk_score <= 20:
                safety_level = "MEDIUM_RISK"
            else:
                safety_level = "HIGH_RISK"
        else:
            if risk_score == 0:
                safety_level = "SAFE"
            elif risk_score <= 10:
                safety_level = "LOW_RISK"
            elif risk_score <= 40:
                safety_level = "MEDIUM_RISK"
            else:
                safety_level = "HIGH_RISK"
        
        # Always add link warning for all PDFs
        if len(links) > 0:
            warnings.append("UWAGA: PDF zawiera linki które mogą prowadzić do niebezpiecznych stron!")
        
        return {
            'is_pdf': data['isPdf'] == 'True',
            'safety_level': safety_level,
            'risk_score': risk_score,
            'warnings': warnings,
            'header': data['header'],
            'keywords': data['keywords']['keyword'],
            'content_binary_code': binary_string,
            'content_analysis': content_binary,
            'error_code': error_code,
            'analysis_complete': True,
            'error': None,
            'links': links,
            'links_count': len(links),
            'suspicious_links_count': suspicious_links_count
        }
        
    except Exception as e:
        logging.error(f"Error analyzing PDF: {str(e)}")
        return {
            'is_pdf': False,
            'safety_level': 'ERROR',
            'risk_score': -1,
            'warnings': ['Analiza nie powiodła się'],
            'content_binary_code': '11111111',  # Error state
            'error_code': 'PDF-ERR',
            'analysis_complete': False,
            'error': str(e),
            'links': [],
            'links_count': 0,
            'suspicious_links_count': 0
        }


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
def analyze_pdf():
    """Main endpoint for PDF analysis"""
    if 'file' not in request.files:
        return jsonify({'error': translate_message('No file provided')}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': translate_message('No file selected')}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': translate_message('Only PDF files are allowed')}), 400
    
    # Generate unique filename
    unique_id = str(uuid.uuid4())
    filename = secure_filename(file.filename)
    temp_filename = f"{unique_id}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], temp_filename)
    
    try:
        # Save uploaded file
        file.save(file_path)
        logging.info(f"Analyzing file: {filename} (ID: {unique_id})")
        
        # Analyze PDF immediately
        result = analyze_pdf_safety(file_path)
        result['filename'] = filename
        result['analysis_id'] = unique_id
        result['timestamp'] = datetime.now().isoformat()
        
        # Log result
        logging.info(f"Analysis complete for {filename}: {result['safety_level']}")
        
        return jsonify(result)
        
    except Exception as e:
        logging.error(f"Error processing file {filename}: {str(e)}")
        return jsonify({'error': translate_message('File processing failed')}), 500
        
    finally:
        # CRITICAL: Securely delete the uploaded file immediately after analysis
        if os.path.exists(file_path):
            secure_delete_file(file_path)
            logging.info(f"Uploaded file securely removed: {temp_filename}")

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

# Cleanup function for any leftover files (run on startup)
def cleanup_temp_files():
    """Clean up any temporary files left from previous sessions"""
    try:
        if os.path.exists(app.config['UPLOAD_FOLDER']):
            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.isfile(file_path):
                    secure_delete_file(file_path)
                    logging.info(f"Cleaned up leftover file: {filename}")
    except Exception as e:
        logging.error(f"Error during cleanup: {str(e)}")

# Development server configuration
if __name__ == '__main__':
    print("Starting PDF Analyzer Server...")
    print(f"Upload folder: {app.config['UPLOAD_FOLDER']}")
    print(f"Log file: {log_file}")
    
    # Clean up any leftover files from previous runs
    cleanup_temp_files()
    
    print("Server will be available at: http://localhost:5000")
    print("Note: Files are securely deleted after analysis")
    app.run(host='0.0.0.0', port=5000, debug=True)
