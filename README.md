# FOIS Website Security Header Checker

A beginner-friendly educational Flask project that checks whether six selected HTTP security headers are present in a public website's HTTP response.

## Features
- Simple web dashboard
- Checks six headers: Content-Security-Policy, Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- Shows observed values, explanations, recommendations, and a header-presence score
- Handles common connection errors
- Basic URL checks intended for a local educational prototype

## Requirements
- Python 3.10 or newer
- Internet access to check public sites
- Windows, macOS, or Linux

## Windows setup (VS Code terminal / PowerShell)

1. Extract the ZIP file.
2. Open the extracted `FOIS-Website-Security-Checker` folder in VS Code.
3. Open Terminal → New Terminal.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   ```

5. Activate it:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, select Command Prompt as your VS Code terminal and run:

   ```cmd
   .venv\Scripts\activate.bat
   ```

6. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

7. Run the app:

   ```powershell
   python app.py
   ```

8. Open this address in your browser:

   http://127.0.0.1:5000

Keep the terminal open while using the app. Press Ctrl+C to stop it.

## Windows setup (Command Prompt)

```cmd
py -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

## Files
- `app.py`: Flask backend and header checking logic
- `templates/index.html`: HTML dashboard
- `static/style.css`: visual styling
- `requirements.txt`: Python dependencies

## Important security notes
- This is a learning prototype, not a production-grade public scanning service.
- Only check websites you are authorised to assess.
- Do not expose Flask's development server publicly.
- The score counts header presence only; it does not validate whether values are secure and is not an overall website security score.
- URL/DNS checks in this educational example are not sufficient to guarantee protection against SSRF or DNS-rebinding attacks in a public deployment.
- The app does not exploit vulnerabilities or perform penetration testing.
