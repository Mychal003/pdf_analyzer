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


app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

Talisman(app, 
    force_https=False,  # Set to True in production with HTTPS
    strict_transport_security=False,  # Enable in production with HTTPS
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'",
        'img-src': "'self' data:",
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'"
    },
    feature_policy={
        'geolocation': "'none'",
        'camera': "'none'",
        'microphone': "'none'"
    }
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

def analyze_pdf_safety(file_path):
    """Analyze PDF and return safety assessment"""
    try:
        xmlDoc = PDFiD(file_path, allNames=False, extraData=True, disarm=False, force=False)
        
        # Convert to JSON for easier processing
        json_result = PDFiD2JSON(xmlDoc, False)
        data = json.loads(json_result)[0]['pdfid']
        
        # Safety assessment logic
        risk_score = 0
        warnings = []
        
        # Check for dangerous elements
        for keyword in data['keywords']['keyword']:
            name = keyword['name']
            count = keyword['count']
            
            if name in DANGER_KEYWORDS and count > 0:
                risk_score += count * 10
                warnings.append(f"Zawiera {count} wystąpień {name}")
        
        # Check for encryption
        encrypt_count = next((k['count'] for k in data['keywords']['keyword'] if k['name'] == '/Encrypt'), 0)
        if encrypt_count > 0:
            risk_score += 5
            warnings.append("PDF jest zaszyfrowany")
        
        # Check for suspicious object counts
        obj_count = next((k['count'] for k in data['keywords']['keyword'] if k['name'] == 'obj'), 0)
        if obj_count > 1000:
            risk_score += 5
            warnings.append(f"Duża liczba obiektów: {obj_count}")
        
        # Determine safety level
        if risk_score == 0:
            safety_level = "SAFE"
        elif risk_score <= 10:
            safety_level = "LOW_RISK"
        elif risk_score <= 40:
            safety_level = "MEDIUM_RISK"
        else:
            safety_level = "HIGH_RISK"
        
        return {
            'is_pdf': data['isPdf'] == 'True',
            'safety_level': safety_level,
            'risk_score': risk_score,
            'warnings': warnings,
            'header': data['header'],
            'keywords': data['keywords']['keyword'],
            'analysis_complete': True,
            'error': None
        }
        
    except Exception as e:
        logging.error(f"Error analyzing PDF: {str(e)}")
        return {
            'is_pdf': False,
            'safety_level': 'ERROR',
            'risk_score': -1,
            'warnings': ['Analiza nie powiodła się'],
            'analysis_complete': False,
            'error': str(e)
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
