# PDF Security Analyzer

Prosty serwer web do analizy bezpieczeństwa plików PDF. Wykorzystuje bibliotekę PDFiD do wykrywania potencjalnie niebezpiecznych elementów w dokumentach PDF.

## 🔍 Co analizuje

- **JavaScript** - kod JS w PDF-ach
- **Automatyczne akcje** - /AA, /OpenAction
- **Uruchamianie programów** - /Launch
- **Osadzone pliki** - /EmbeddedFile
- **Szyfrowanie** - /Encrypt
- **Podejrzane struktury** - duża liczba obiektów

## 📋 Wymagania

- Python 3.7+
- Flask
- Biblioteka PDFiD (dołączona)

## 🚀 Instalacja i uruchomienie

### 1. Przygotowanie środowiska

```bash
cd /path/to/pdf_analizer
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# lub
venv\Scripts\activate     # Windows
```

### 2. Instalacja zależności

```bash
pip install -r requirements.txt
```

### 3. Uruchomienie serwera

```bash
python app.py
```

Serwer będzie dostępny pod adresem: http://localhost:5000

## 🎯 Użytkowanie

### Web Interface
1. Otwórz http://localhost:5000 w przeglądarce
2. Kliknij "Choose File" i wybierz plik PDF
3. Poczekaj na wyniki analizy

### API Endpoints

#### Analiza pliku PDF
```bash
POST /api/analyze
Content-Type: multipart/form-data

curl -X POST -F "file=@document.pdf" http://localhost:5000/api/analyze
```

**Odpowiedź:**
```json
{
  "filename": "document.pdf",
  "safety_level": "SAFE",
  "risk_score": 0,
  "warnings": [],
  "is_pdf": true,
  "header": "%PDF-1.4",
  "analysis_id": "uuid-here",
  "timestamp": "2025-07-29T12:00:00"
}
```

#### Health Check
```bash
GET /api/health

curl http://localhost:5000/api/health
```

## 📊 Poziomy ryzyka

| Poziom | Risk Score | Opis |
|--------|------------|------|
| **SAFE** | 0 | Brak wykrytych zagrożeń |
| **LOW_RISK** | 1-10 | Niewielkie ryzyko (szyfrowanie, dużo obiektów) |
| **MEDIUM_RISK** | 11-50 | Średnie ryzyko |
| **HIGH_RISK** | 50+ | Wysokie ryzyko (JavaScript, Launch, itp.) |

## 🔒 Bezpieczeństwo

- **Automatyczne usuwanie plików** - wszystkie przesłane pliki są usuwane po analizie
- **Bezpieczne nadpisywanie** - pliki są nadpisywane zerami przed usunięciem
- **Brak przechowywania danych** - serwer nie zapisuje żadnych danych użytkowników
- **Walidacja plików** - akceptowane tylko pliki .pdf
- **Limit rozmiaru** - maksymalnie 16MB

## 📁 Struktura projektu

```
pdf_analizer/
├── app.py                 # Główny serwer Flask
├── pdfid.py              # Biblioteka do analizy PDF
├── requirements.txt      # Zależności Python
├── templates/
│   └── index.html       # Interfejs web
├── temp_uploads/        # Katalog tymczasowy (tworzony automatycznie)
├── logs/                # Logi aplikacji
│   └── pdf_analyzer.log
└── README.md           # Ta dokumentacja
```

## 🛠️ Rozwój

### Uruchomienie w trybie deweloperskim
```bash
python app.py
# Debug mode: ON
# Auto-reload: ON
```

### Produkcja
```bash
pip install gunicorn
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

## 📝 Logi

Wszystkie operacje są logowane do:
- Konsola (stdout)
- Plik: `logs/pdf_analyzer.log`

Format logów: `timestamp - level - message`

## ⚠️ Ograniczenia

- Maksymalny rozmiar pliku: 16MB
- Obsługiwane formaty: tylko PDF
- Analiza strukturalna: nie analizuje treści dokumentu
- Środowisko deweloperskie: nie używać w produkcji bez dodatkowych zabezpieczeń

## 🐛 Rozwiązywanie problemów

### Błąd "Permission denied" przy logach
```bash
mkdir -p logs
chmod 755 logs
```

### Błąd importu pdfid
Upewnij się, że plik `pdfid.py` jest w tym samym katalogu co `app.py`

### Serwer nie odpowiada
Sprawdź czy port 5000 nie jest zajęty:
```bash
lsof -i :5000  # Linux/Mac
netstat -an | findstr :5000  # Windows
```
