# Django E-Signature Project (Minimal scaffold)

This is a minimal **Django** scaffold for an e-signature application with:
- Black & white simple theme (Bootstrap)
- MySQL-ready settings (but uses sqlite if MySQL env not provided)
- Models: Document, Signature, SignaturePlacement, SigningToken
- Endpoints: upload document, draw/upload signature, issue signing link, apply signatures (server merge using PyMuPDF)
- Minimal templates and JS hooks (PDF.js integration not included — add pdf.js in templates as needed)

## Quick setup

1. Create a Python venv and install requirements:
```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2. Create a MySQL database (optional). If you want MySQL, set these environment variables:
```
DB_ENGINE=mysql
DB_NAME=your_db_name
DB_USER=your_db_user
DB_PASS=your_db_pass
DB_HOST=localhost
DB_PORT=3306
```
If not provided, the project uses SQLite at `db.sqlite3`.

3. Run migrations and create superuser:
```bash
python manage.py migrate
python manage.py createsuperuser
```

4. Run development server:
```bash
python manage.py runserver
```

5. Upload documents via `/upload/` and test signing flows.

Note: This scaffold is a starting point. You will likely want to:
- Configure a proper email backend.
- Add PDF.js to render PDFs client-side and improve the signature placement UI.
- Secure file uploads and validate PDFs.
