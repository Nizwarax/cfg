import os
import json
import base64
from flask import Flask, render_template, request, jsonify, session, redirect
from werkzeug.utils import secure_filename

from decryptors import (
    run_darktunnel,
    run_httpcustom,
    run_httpinjector,
    run_npvtunnel,
    run_ssccustom
)

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-please-change')

# Creator Edition Settings
SETTINGS_FILE = 'creator_settings.json'
def load_brand():
    default = {'name':'VORTEX CFG SCRIPT','creator':'@Dark_System','footer':'Code : @Dark_System'}
    try:
        with open(SETTINGS_FILE,'r',encoding='utf-8') as f:
            default.update(json.load(f))
    except Exception:
        pass
    return default
BRAND = load_brand()
ADMIN_FILE='admin_account.json'
def load_admin():
    data={'username':'admin','password':'admin123'}
    try:
        with open(ADMIN_FILE,'r',encoding='utf-8') as f:
            data.update(json.load(f))
    except Exception:
        pass
    return data

ADMIN=load_admin()


# Map file types to decryption functions
DECRYPTORS = {
    'darktunnel': run_darktunnel,
    'httpcustom': run_httpcustom,
    'httpinjector': run_httpinjector,
    'npvtunnel': run_npvtunnel,
    'ssccustom': run_ssccustom
}

# File extension to type mapping
EXTENSION_MAP = {
    '.dark': 'darktunnel',
    '.hc': 'httpcustom',
    '.ehi': 'httpinjector',
    '.npvt': 'npvtunnel',
    '.npv': 'npvtunnel',
    '.ssc': 'ssccustom'
}


def detect_config_type(filename, file_bytes):
    name = filename.lower()
    for ext, d_type in EXTENSION_MAP.items():
        if name.endswith(ext):
            return d_type
    preview = file_bytes[:512].decode('utf-8', errors='ignore')
    checks = [
        ('dt://', 'darktunnel'),
        ('encryptedLockedConfig', 'darktunnel'),
        ('HTTP Custom', 'httpcustom'),
        ('HABIBI', 'httpcustom'),
        ('NPVTSUB1', 'npvtunnel'),
        ('NPVT1', 'npvtunnel'),
        ('ssc://', 'ssccustom'),
        ('configAesKey', 'httpinjector'),
    ]
    for key, value in checks:
        if key in preview:
            return value
    return None

@app.route('/admin', methods=['GET','POST'])
def admin():
    global BRAND
    if not session.get('admin'):
        if request.method == 'POST' and request.form.get('action')=='login':
            if request.form.get('username') == ADMIN.get('username') and request.form.get('password') == ADMIN.get('password'):
                session['admin']=True
                return redirect('/admin')
        return render_template('admin.html', error='Login gagal' if request.method=='POST' else None)
    if request.method=='POST' and request.form.get('action')=='save':
        BRAND = {
            'name': request.form.get('name','VORTEX CFG SCRIPT'),
            'creator': request.form.get('creator','@Dark_System'),
            'footer': request.form.get('footer','Code : @Dark_System')
        }
        with open(SETTINGS_FILE,'w',encoding='utf-8') as f:
            json.dump(BRAND,f,indent=2,ensure_ascii=False)
    if request.method=='POST' and request.form.get('action')=='account':
        ADMIN['username']=request.form.get('username',ADMIN['username'])
        ADMIN['password']=request.form.get('password',ADMIN['password'])
        with open(ADMIN_FILE,'w',encoding='utf-8') as f:
            json.dump(ADMIN,f,indent=2)
    return render_template('admin.html', logged=True, brand=BRAND, admin=ADMIN)

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect('/')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded', 'success': False}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected', 'success': False}), 400
        
        decryptor_type = request.form.get('type', 'auto')
        file_bytes = file.read()
        if decryptor_type == 'auto':
            decryptor_type = detect_config_type(file.filename, file_bytes)
            if not decryptor_type:
                return jsonify({'error': 'Auto scan gagal mengenali config.', 'success': False}), 400
        
        if decryptor_type not in DECRYPTORS:
            return jsonify({'error': f'Unknown decryptor type: {decryptor_type}', 'success': False}), 400
        
        # File bytes already loaded by scanner
        if not file_bytes:
            return jsonify({'error': 'File is empty', 'success': False}), 400
        
        # Run decryption
        decryptor = DECRYPTORS[decryptor_type]
        result = decryptor(file_bytes)
        
        if result is None:
            return jsonify({
                'error': 'Decryption failed. The file may be corrupted or not a valid config file.',
                'success': False
            }), 400
        
        # Try to parse as JSON for better display
        try:
            parsed = json.loads(result)
            formatted_result = json.dumps(parsed, indent=2, ensure_ascii=False)
        except:
            formatted_result = result
        
        # Get file info
        file_info = {
            'filename': file.filename,
            'size': len(file_bytes),
            'type': decryptor_type,
            'display_name': {
                'darktunnel': 'Dark Tunnel',
                'httpcustom': 'HTTP Custom',
                'httpinjector': 'HTTP Injector',
                'npvtunnel': 'NPV Tunnel',
                'ssccustom': 'SSC Custom'
            }.get(decryptor_type, decryptor_type)
        }
        
        header = f"==============================\n{BRAND['name']}\n==============================\n\nCreator : {BRAND['creator']}\nFormat  : {file_info['display_name']} ({file_info['type']})\nDate    : {__import__('datetime').datetime.now().strftime('%Y-%m-%d')}\nStatus  : Decrypted\n\n==============================\n\n"
        footer = f"\n\n==============================\n{BRAND['footer']}"
        return jsonify({
            'success': True,
            'result': header + formatted_result + footer,
            'file_info': file_info
        })
        
    except Exception as e:
        return jsonify({'error': str(e), 'success': False}), 500


@app.route('/api/scan', methods=['POST'])
def scan():
    files = request.files.getlist('files')
    result=[]
    for f in files:
        data=f.read()
        result.append({'filename':f.filename,'detected':detect_config_type(f.filename,data) or 'unknown','size':len(data)})
    return jsonify({'success':True,'files':result})

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)