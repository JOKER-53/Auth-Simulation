from flask import Blueprint, render_template, request, redirect, session, url_for, jsonify, current_app
from app.simulation import OAuthSimulationEngine

main_bp = Blueprint('main', __name__)

def get_engine() -> OAuthSimulationEngine:
    return current_app.extensions['simulation_engine']

def get_client_ip() -> str:
    # Check X-Forwarded-For if behind a proxy, otherwise fallback to remote_addr
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

@main_bp.route('/')
def index():
    engine = get_engine()
    return render_template(
        'index.html',
        mode=engine.mode,
        token_count=len(engine.tokens),
        log_count=len(engine.audit_logs)
    )

@main_bp.route('/login', methods=['GET', 'POST'])
def login():
    engine = get_engine()
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = engine.users.get(email)
        if not user:
            return render_template(
                'login.html',
                users=engine.users.values(),
                error=f"Unauthorized account: '{email}' is not in the simulated Google directory."
            ), 401

        client_ip = get_client_ip()
        user_agent = request.headers.get('User-Agent', 'Browser')
        token_record = engine.issue_token(email=email, client_ip=client_ip, user_agent=user_agent)

        session['user'] = {
            'email': user.email,
            'name': user.name,
            'google_id': user.google_id,
            'role': user.role,
            'token': token_record.token_id,
            'nonce': token_record.nonce,
            'issued_at': token_record.issued_at
        }
        return redirect(url_for('main.dashboard'))

    return render_template('login.html', users=engine.users.values())

@main_bp.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('main.login'))

    engine = get_engine()
    token_id = session['user'].get('token')
    token_record = engine.tokens.get(token_id)

    return render_template(
        'dashboard.html',
        user=session['user'],
        token_record=token_record,
        mode=engine.mode
    )

@main_bp.route('/access')
def access():
    engine = get_engine()
    # Accept token via query param (?token=) or HTTP Authorization header (Bearer ...)
    token_str = request.args.get('token')
    auth_header = request.headers.get('Authorization')
    if not token_str and auth_header and auth_header.startswith('Bearer '):
        token_str = auth_header.split('Bearer ', 1)[1].strip()

    client_ip = get_client_ip()
    is_valid, message, user = engine.verify_token(token_str, client_ip=client_ip)

    # API JSON response if requested
    if request.headers.get('Accept') == 'application/json' or request.args.get('format') == 'json':
        status_code = 200 if is_valid else (401 if 'Missing' in message or 'Invalid' in message else 403)
        return jsonify({
            'valid': is_valid,
            'message': message,
            'user': {
                'email': user.email,
                'name': user.name,
                'role': user.role,
                'department': user.department,
                'gpa': user.gpa,
                'academic_status': user.academic_status
            } if user else None,
            'mode': engine.mode
        }), status_code

    token_record = engine.tokens.get(token_str) if token_str else None
    return render_template(
        'access.html',
        is_valid=is_valid,
        message=message,
        user=user,
        token_str=token_str,
        token_record=token_record,
        mode=engine.mode
    ), (200 if is_valid else 403)

@main_bp.route('/replay', methods=['GET', 'POST'])
def replay():
    engine = get_engine()
    result = None

    if request.method == 'POST':
        token_str = request.form.get('token', '').strip()
        simulated_ip = request.form.get('attacker_ip', '198.51.100.42').strip()

        is_valid, message, user = engine.verify_token(
            token_str=token_str,
            client_ip=simulated_ip,
            is_replay_test=True
        )

        token_record = engine.tokens.get(token_str)
        result = {
            'executed': True,
            'token': token_str,
            'attacker_ip': simulated_ip,
            'is_valid': is_valid,
            'message': message,
            'user': user,
            'token_record': token_record,
            'mode': engine.mode
        }

    # Pre-populate with the current session token if logged in
    sample_token = session.get('user', {}).get('token', '')
    if not sample_token and engine.tokens:
        sample_token = list(engine.tokens.keys())[-1]

    return render_template(
        'replay.html',
        sample_token=sample_token,
        result=result,
        mode=engine.mode
    )

@main_bp.route('/admin/tokens')
def admin_tokens():
    engine = get_engine()
    return render_template(
        'admin_tokens.html',
        tokens=engine.tokens.values(),
        audit_logs=engine.audit_logs,
        mode=engine.mode
    )

@main_bp.route('/admin/toggle-mode', methods=['POST'])
def toggle_mode():
    engine = get_engine()
    new_mode = 'secure' if engine.mode == 'vulnerable' else 'vulnerable'
    engine.set_mode(new_mode)

    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True, 'mode': new_mode})

    # Return to referrer or admin
    return redirect(request.referrer or url_for('main.admin_tokens'))

@main_bp.route('/admin/reset', methods=['POST'])
def reset_simulation():
    engine = get_engine()
    engine.reset()
    session.clear()

    if request.headers.get('Accept') == 'application/json':
        return jsonify({'success': True})

    return redirect(url_for('main.admin_tokens'))

@main_bp.route('/admin/revoke/<token_str>', methods=['POST'])
def revoke_token(token_str):
    engine = get_engine()
    success = engine.revoke_token(token_str, reason="Revoked via Admin Console")
    return redirect(request.referrer or url_for('main.admin_tokens'))

@main_bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))

@main_bp.route('/api/status')
def api_status():
    engine = get_engine()
    return jsonify({
        'status': 'online',
        'mode': engine.mode,
        'active_tokens': len(engine.tokens),
        'audit_entries': len(engine.audit_logs)
    })
