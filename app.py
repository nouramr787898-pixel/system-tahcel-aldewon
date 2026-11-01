import os, re, sqlite3, secrets, hmac, hashlib, time, json
from datetime import timedelta
from functools import wraps
from pathlib import Path
import click
import requests
from flask import Flask, request, session, g, abort, jsonify, render_template, redirect, Response, stream_with_context
from werkzeug.security import generate_password_hash, check_password_hash


def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(exist_ok=True)
    key_path = Path(app.instance_path) / 'session.key'
    if not key_path.exists():
        try:
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'w') as f: f.write(secrets.token_hex(32))
        except FileExistsError: pass
    app.config.update(SECRET_KEY=os.getenv('SESSION_SECRET') or key_path.read_text(), DATABASE=str(Path(app.instance_path)/'app.db'), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=os.getenv('COOKIE_SECURE','1')=='1', PERMANENT_SESSION_LIFETIME=timedelta(hours=8), MAX_CONTENT_LENGTH=1024*1024)
    if config: app.config.update(config)
    def db():
        if 'db' not in g:
            g.db=sqlite3.connect(app.config['DATABASE'],timeout=15)
            g.db.row_factory=sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON')
        return g.db
    app.db = db
    @app.teardown_appcontext
    def close(_):
        connection=g.pop('db',None)
        if connection is not None: connection.close()
    with app.app_context(): db().executescript(Path(__file__).with_name('schema.sql').read_text())
    def audit(action,target):
        db().execute('INSERT INTO audit(actor_id,action,target) VALUES(?,?,?)',(g.user['id'] if getattr(g,'user',None) else None,action,str(target)))
        db().commit()
    def rows(sql,args=()): return [dict(r) for r in db().execute(sql,args)]
    def data(): return request.get_json(silent=True) or request.form
    def required(d,*keys):
        if any(not isinstance(d.get(k),str) or not d[k].strip() for k in keys): abort(400, 'بيانات ناقصة')
    @app.before_request
    def guard():
        g.user=None
        if session.get('uid'):
            g.user=db().execute("SELECT * FROM users WHERE id=? AND status='Active' AND deleted_at IS NULL AND session_version=?",(session['uid'],session.get('version',-1))).fetchone()
        if 'csrf' not in session: session['csrf']=secrets.token_urlsafe(32)
        if request.method in ('POST','PATCH','DELETE','PUT') and request.path!='/webhook':
            token=request.headers.get('X-CSRF-Token') or request.form.get('csrf','')
            if not hmac.compare_digest(session['csrf'],token): abort(403,'CSRF')
    @app.after_request
    def headers(response):
        response.headers['Content-Security-Policy']="default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['X-Content-Type-Options']='nosniff'
        response.headers['Cache-Control']='no-store'
        return response
    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(429)
    @app.errorhandler(502)
    def error(e): return jsonify(error=e.description),e.code
    def auth(admin=False,owner=False):
        def deco(fn):
            @wraps(fn)
            def run(*args,**kwargs):
                if not g.user: abort(401)
                if admin and g.user['role'] not in ('SUPER ADMIN','SUPPORT'): abort(403)
                if owner and g.user['role']!='SUPER ADMIN': abort(403)
                return fn(*args,**kwargs)
            return run
        return deco
    def account_access(aid,send=False):
        a=db().execute("SELECT a.*,u.status owner_status,u.deleted_at FROM accounts a JOIN users u ON u.id=a.owner_id WHERE a.id=?",(aid,)).fetchone()
        if not a: abort(404)
        if a['owner_status']!='Active' or a['deleted_at']: abort(403)
        if a['kind']!='Business': abort(403,'الحساب الشخصي متاح عبر wa.me فقط')
        if a['owner_id']==g.user['id']: return a
        if not a['consent_at']: abort(403,'لا يوجد تفويض ساري')
        if g.user['role']=='SUPER ADMIN': return a
        grant=db().execute('SELECT * FROM grants WHERE user_id=? AND account_id=?',(g.user['id'],aid)).fetchone()
        if g.user['role']!='SUPPORT' or not grant or (send and not grant['can_send']): abort(403)
        return a
    def conversation(cid,send=False):
        c=db().execute('SELECT * FROM conversations WHERE id=?',(cid,)).fetchone()
        if not c: abort(404)
        return c,account_access(c['account_id'],send)
    @app.get('/')
    def home(): return redirect('/admin' if g.user and g.user['role']!='USER' else '/user' if g.user else '/login')
    @app.get('/login')
    def login_page(): return render_template('login.html',csrf=session['csrf'])
    @app.get('/api/session')
    def current(): return jsonify(csrf=session['csrf'],user={k:g.user[k] for k in ('id','name','role')} if g.user else None)
    @app.post('/api/register')
    def register():
        d=data(); required(d,'name','email','phone','password')
        if len(d['password'])<12 or '@' not in d['email'] or d.get('privacy') not in (True,'on'): abort(400,'يلزم قبول سياسة الخصوصية وكلمة مرور 12 حرفاً على الأقل')
        try:
            cur=db().execute('INSERT INTO users(name,email,phone,password_hash,privacy_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)',(d['name'],d['email'].lower().strip(),d['phone'],generate_password_hash(d['password'])))
            db().execute('INSERT INTO subscriptions(user_id) VALUES(?)',(cur.lastrowid,)); db().commit()
        except sqlite3.IntegrityError: abort(409,'البريد مستخدم')
        return jsonify(ok=True),201
    @app.post('/api/login')
    def login():
        d=data(); required(d,'email','password'); now=int(time.time())
        key=hashlib.sha256((request.remote_addr+'|'+d['email'].lower()).encode()).hexdigest()
        attempt=db().execute('SELECT * FROM attempts WHERE key=?',(key,)).fetchone()
        if attempt and attempt['started']>now-900 and attempt['count']>=10: abort(429)
        db().execute('INSERT INTO attempts VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN started<? THEN 1 ELSE count+1 END,started=CASE WHEN started<? THEN ? ELSE started END',(key,now,now-900,now-900,now)); db().commit()
        u=db().execute("SELECT * FROM users WHERE email=? AND status='Active' AND deleted_at IS NULL",(d['email'].lower().strip(),)).fetchone()
        valid=check_password_hash(u['password_hash'] if u else generate_password_hash('invalid-placeholder'),d['password'])
        if not u or not valid: abort(401,'بيانات الدخول غير صحيحة')
        session.clear(); session.update(uid=u['id'],version=u['session_version'],csrf=secrets.token_urlsafe(32)); session.permanent=True
        db().execute('DELETE FROM attempts WHERE key=?',(key,)); db().execute('UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?',(u['id'],)); db().commit()
        g.user=u; audit('login',u['id'])
        return jsonify(redirect='/user' if u['role']=='USER' else '/admin')
    @app.post('/api/logout')
    def logout(): session.clear(); return jsonify(ok=True)
    @app.get('/admin')
    @auth(admin=True)
    def admin(): return render_template('dashboard.html',user=g.user,admin=True)
    @app.get('/user')
    @auth()
    def user_page(): return render_template('dashboard.html',user=g.user,admin=False)
    @app.get('/api/users')
    @auth(owner=True)
    def users():
        q='%'+request.args.get('q','')+'%'
        result=rows("SELECT u.id,u.name,u.email,u.phone,u.role,u.status,u.created_at,u.last_login,u.conversation_limit,COUNT(a.id) account_count,GROUP_CONCAT(DISTINCT a.kind) account_types FROM users u LEFT JOIN accounts a ON a.owner_id=u.id WHERE u.deleted_at IS NULL AND (u.name LIKE ? OR u.email LIKE ? OR u.phone LIKE ?) GROUP BY u.id ORDER BY u.id DESC",(q,q,q)); audit('users.view','list'); return jsonify(result)
    @app.get('/api/users/<int:uid>')
    @auth(owner=True)
    def user_detail(uid):
        u=db().execute('SELECT id,name,email,phone,role,status,created_at,last_login,conversation_limit FROM users WHERE id=? AND deleted_at IS NULL',(uid,)).fetchone()
        if not u: abort(404)
        audit('user.view',uid)
        return jsonify(user=dict(u),accounts=account_rows(uid),activity=rows('SELECT * FROM audit WHERE actor_id=? ORDER BY id DESC LIMIT 100',(uid,)))
    @app.patch('/api/users/<int:uid>')
    @auth(owner=True)
    def update_user(uid):
        d=data(); u=db().execute('SELECT * FROM users WHERE id=? AND deleted_at IS NULL',(uid,)).fetchone()
        if not u: abort(404)
        if u['role']=='SUPER ADMIN': abort(403,'إدارة حساب المالك عبر الخادم فقط')
        allowed={'status':('Active','Suspended'),'role':('USER','SUPPORT')}
        if 'conversation_limit' in d and (type(d['conversation_limit']) is not int or not 0<=d['conversation_limit']<=1000000): abort(400)
        for field,values in allowed.items():
            if field in d and d[field] not in values: abort(400)
        for field,values in allowed.items():
            if field in d:
                if d[field] not in values: abort(400)
                db().execute(f'UPDATE users SET {field}=?,session_version=session_version+1 WHERE id=?',(d[field],uid))
        if 'conversation_limit' in d:
            if type(d['conversation_limit']) is not int or not 0<=d['conversation_limit']<=1000000: abort(400)
            db().execute('UPDATE users SET conversation_limit=? WHERE id=?',(d['conversation_limit'],uid))
        audit('user.update',uid); return jsonify(ok=True)
    @app.delete('/api/users/<int:uid>')
    @auth(owner=True)
    def delete_user(uid):
        u=db().execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
        if not u: abort(404)
        if u['role']=='SUPER ADMIN': abort(403)
        db().execute("UPDATE users SET deleted_at=CURRENT_TIMESTAMP,status='Suspended',session_version=session_version+1 WHERE id=?",(uid,))
        db().execute("UPDATE accounts SET consent_at=NULL,status='Disconnected' WHERE owner_id=?",(uid,)); audit('user.delete_requested',uid)
        return jsonify(ok=True,retention_days=30)
    def account_rows(uid=None):
        result=rows('''SELECT a.id,a.owner_id,u.name owner,a.phone,a.kind,a.status,a.linked_at,a.consent_at,
          (SELECT COUNT(*) FROM conversations c WHERE c.account_id=a.id) conversations,
          (SELECT COUNT(*) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.account_id=a.id) messages,
          (SELECT COUNT(*) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.account_id=a.id AND m.direction='in') incoming,
          (SELECT COUNT(*) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.account_id=a.id AND m.direction='out') outgoing,
          (SELECT MAX(last_activity) FROM conversations c WHERE c.account_id=a.id) last_activity
          FROM accounts a JOIN users u ON u.id=a.owner_id WHERE u.deleted_at IS NULL''')
        if uid is not None: result=[r for r in result if r['owner_id']==uid]
        if g.user['role']=='USER': result=[r for r in result if r['owner_id']==g.user['id']]
        if g.user['role']=='SUPPORT':
            ids={r['account_id'] for r in rows('SELECT account_id FROM grants WHERE user_id=?',(g.user['id'],))}
            result=[r for r in result if r['id'] in ids and r['kind']=='Business' and r['consent_at']]
        for r in result:
            if r['kind']=='Personal': r['wa_me']='https://wa.me/'+re.sub(r'\D','',r['phone'])
        return result
    @app.get('/api/accounts')
    @auth()
    def accounts(): audit('accounts.view','list'); return jsonify(account_rows())
    @app.post('/api/accounts')
    @auth()
    def add_account():
        d=data(); required(d,'phone','kind')
        if d['kind']!='Personal': abort(400,'ربط Business عبر التحقق الرسمي من الخادم')
        if not re.fullmatch(r'\+?[1-9][0-9]{6,14}',d['phone']): abort(400)
        try: db().execute("INSERT INTO accounts(owner_id,phone,kind) VALUES(?,?,'Personal')",(g.user['id'],d['phone'])); db().commit()
        except sqlite3.IntegrityError: abort(409)
        audit('personal.link',g.user['id']); return jsonify(ok=True),201
    @app.patch('/api/accounts/<int:aid>')
    @auth()
    def account_update(aid):
        a=db().execute('SELECT * FROM accounts WHERE id=?',(aid,)).fetchone()
        if not a: abort(404)
        if a['owner_id']!=g.user['id'] and g.user['role']!='SUPER ADMIN': abort(403)
        d=data()
        if 'consent' in d:
            if a['owner_id']!=g.user['id'] or a['kind']!='Business' or type(d['consent']) is not bool: abort(403)
            db().execute("UPDATE accounts SET consent_at=CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE NULL END,consent_version='1' WHERE id=?",(d['consent'],aid))
        elif d.get('disconnect') is True: db().execute("UPDATE accounts SET status='Disconnected',consent_at=NULL WHERE id=?",(aid,))
        else: abort(400)
        audit('account.update',aid); return jsonify(ok=True)
    @app.post('/api/grants')
    @auth(owner=True)
    def grant():
        d=data(); u=db().execute("SELECT id FROM users WHERE id=? AND role='SUPPORT' AND deleted_at IS NULL",(d.get('user_id'),)).fetchone()
        if not u: abort(400)
        a=account_access(d.get('account_id'))
        if not a['consent_at']: abort(403)
        if d.get('revoke'): db().execute('DELETE FROM grants WHERE user_id=? AND account_id=?',(u['id'],a['id']))
        else: db().execute('INSERT INTO grants VALUES(?,?,?) ON CONFLICT(user_id,account_id) DO UPDATE SET can_send=excluded.can_send',(u['id'],a['id'],int(d.get('can_send') is True)))
        audit('grant.update',a['id']); return jsonify(ok=True)
    @app.get('/api/conversations')
    @auth()
    def inbox():
        result=[]
        for c in rows('SELECT c.*,a.owner_id,a.phone,u.name owner FROM conversations c JOIN accounts a ON a.id=c.account_id JOIN users u ON u.id=a.owner_id ORDER BY c.last_activity DESC'):
            try: account_access(c['account_id'])
            except Exception as e:
                from werkzeug.exceptions import HTTPException
                if isinstance(e,HTTPException) and e.code in (403,404): continue
                raise
            if request.args.get('user') and str(c['owner_id'])!=request.args['user']: continue
            if request.args.get('phone') and request.args['phone'] not in c['phone']: continue
            if request.args.get('date') and not c['last_activity'].startswith(request.args['date']): continue
            q=request.args.get('q','').lower()
            if q and not any(q in str(c[k]).lower() for k in ('contact','contact_name','owner')): continue
            result.append(c)
        audit('conversations.view','list'); return jsonify(result)
    @app.get('/api/conversations/<int:cid>/messages')
    @auth()
    def messages(cid):
        conversation(cid); audit('messages.view',cid)
        return jsonify(rows('SELECT id,direction,body,created_at,status FROM messages WHERE conversation_id=? ORDER BY id',(cid,)))
    @app.post('/api/conversations/<int:cid>/messages')
    @auth()
    def send(cid):
        d=data(); required(d,'body'); c,a=conversation(cid,True)
        if len(d['body'])>4096: abort(400)
        if a['status']!='Connected' or not c['last_inbound'] or time.time()-c['last_inbound']>86400: abort(409,'الرد النصي يتطلب اتصالاً ونافذة مراسلة سارية خلال 24 ساعة')
        token=os.getenv(a['token_key'] or '')
        if not token: abort(409,'بيانات اتصال Meta غير متاحة')
        try:
            resp=requests.post(f"https://graph.facebook.com/{os.getenv('META_GRAPH_VERSION','v23.0')}/{a['phone_id']}/messages",headers={'Authorization':'Bearer '+token},json={'messaging_product':'whatsapp','to':c['contact'],'type':'text','text':{'body':d['body']}},timeout=20)
            resp.raise_for_status(); mid=resp.json()['messages'][0]['id']
        except (requests.RequestException,KeyError,ValueError): audit('message.send_failed',cid); abort(502,'تعذر تأكيد الإرسال من Meta؛ تحقق من الحالة قبل إعادة المحاولة')
        db().execute("INSERT INTO messages(conversation_id,meta_id,direction,body,status) VALUES(?,?,'out',?,'sent')",(cid,mid,d['body']))
        db().execute('UPDATE conversations SET last_activity=CURRENT_TIMESTAMP WHERE id=?',(cid,)); audit('message.send',cid)
        return jsonify(ok=True),201
    @app.get('/api/events')
    @auth()
    def events():
        uid=g.user['id']; version=g.user['session_version']
        @stream_with_context
        def stream():
            previous=None
            for _ in range(12):
                fresh=db().execute("SELECT * FROM users WHERE id=? AND status='Active' AND deleted_at IS NULL AND session_version=?",(uid,version)).fetchone()
                if not fresh:
                    yield 'event: revoked\ndata: {}\n\n'; return
                g.user=fresh
                visible=[]
                for a in db().execute("SELECT id FROM accounts WHERE kind='Business'").fetchall():
                    try: account_access(a['id']); visible.append(a['id'])
                    except Exception as error:
                        from werkzeug.exceptions import HTTPException
                        if not isinstance(error,HTTPException): raise
                snapshot=[]
                for aid in visible:
                    snapshot.append(tuple(db().execute("SELECT COUNT(m.id),COALESCE(MAX(m.id),0),GROUP_CONCAT(m.status) FROM messages m JOIN conversations c ON c.id=m.conversation_id WHERE c.account_id=?",(aid,)).fetchone()))
                signature=hashlib.sha256(repr((visible,snapshot)).encode()).hexdigest()
                if signature!=previous:
                    yield 'data: '+json.dumps({'changed':True})+'\n\n'; previous=signature
                else: yield ': heartbeat\n\n'
                time.sleep(2)
        return Response(stream(),mimetype='text/event-stream',headers={'X-Accel-Buffering':'no'})
    @app.get('/api/analytics')
    @auth(owner=True)
    def analytics():
        def count(sql): return db().execute(sql).fetchone()[0]
        scope=" FROM conversations c JOIN accounts a ON a.id=c.account_id JOIN users u ON u.id=a.owner_id WHERE a.kind='Business' AND a.consent_at IS NOT NULL AND u.deleted_at IS NULL AND u.status='Active'"
        stats={'users':count('SELECT COUNT(*) FROM users WHERE deleted_at IS NULL'),'active':count("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND status='Active'"),'today':count("SELECT COUNT(*) FROM users WHERE deleted_at IS NULL AND date(created_at)=date('now')"),'accounts':count('SELECT COUNT(*) FROM accounts a JOIN users u ON u.id=a.owner_id WHERE u.deleted_at IS NULL'),'business':count("SELECT COUNT(*) FROM accounts a JOIN users u ON u.id=a.owner_id WHERE u.deleted_at IS NULL AND a.kind='Business' AND a.status='Connected'"),'conversations':count('SELECT COUNT(*)'+scope)}
        for direction,label in [('in','incoming'),('out','outgoing')]: stats[label]=count("SELECT COUNT(*) FROM messages WHERE direction='"+direction+"' AND conversation_id IN (SELECT c.id"+scope+")")
        stats['growth']=rows("SELECT date(created_at) day,COUNT(*) total FROM users WHERE deleted_at IS NULL GROUP BY day ORDER BY day")
        stats['activity']=rows("SELECT date(m.created_at) day,m.direction,COUNT(*) total FROM messages m WHERE m.conversation_id IN (SELECT c.id"+scope+") GROUP BY day,m.direction ORDER BY day")
        audit('analytics.view','all'); return jsonify(stats)
    @app.get('/api/audit')
    @auth(owner=True)
    def logs():
        audit('audit.view','list'); return jsonify(rows('SELECT a.*,u.name actor FROM audit a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 500'))
    @app.get('/api/subscriptions')
    @auth(owner=True)
    def subscriptions():
        audit('subscriptions.view','list'); return jsonify(rows('SELECT s.*,u.name FROM subscriptions s JOIN users u ON u.id=s.user_id WHERE u.deleted_at IS NULL'))
    @app.patch('/api/subscriptions/<int:uid>')
    @auth(owner=True)
    def subscription(uid):
        d=data()
        if d.get('plan') not in ('Free','Pro','Business') or d.get('status') not in ('Active','Suspended'): abort(400)
        if not db().execute('SELECT id FROM users WHERE id=? AND deleted_at IS NULL',(uid,)).fetchone(): abort(404)
        db().execute('INSERT INTO subscriptions(user_id,plan,status) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET plan=excluded.plan,status=excluded.status',(uid,d['plan'],d['status'])); audit('subscription.update',uid); return jsonify(ok=True)
    @app.get('/webhook')
    def verify():
        token=os.getenv('META_VERIFY_TOKEN')
        if not token or request.args.get('hub.mode')!='subscribe' or not hmac.compare_digest(request.args.get('hub.verify_token',''),token): abort(403)
        return request.args.get('hub.challenge','')
    @app.post('/webhook')
    def webhook():
        secret=os.getenv('META_APP_SECRET'); raw=request.get_data()
        if not secret or not hmac.compare_digest(request.headers.get('X-Hub-Signature-256',''),'sha256='+hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()): abort(403)
        payload=request.get_json(silent=True)
        if not isinstance(payload,dict): abort(400)
        for entry in payload.get('entry',[]):
            for change in entry.get('changes',[]):
                value=change.get('value',{}); phone_id=value.get('metadata',{}).get('phone_number_id')
                a=db().execute("SELECT a.*,u.conversation_limit FROM accounts a JOIN users u ON u.id=a.owner_id WHERE a.phone_id=? AND a.waba_id=? AND a.kind='Business' AND a.status='Connected' AND u.status='Active' AND u.deleted_at IS NULL",(phone_id,str(entry.get('id')))).fetchone()
                if not a: continue
                for msg in value.get('messages',[]):
                    if msg.get('type')!='text' or not msg.get('id') or not msg.get('from'): continue
                    if db().execute('SELECT id FROM messages WHERE meta_id=?',(msg['id'],)).fetchone(): continue
                    c=db().execute('SELECT id FROM conversations WHERE account_id=? AND contact=?',(a['id'],msg['from'])).fetchone()
                    if not c:
                        n=db().execute('SELECT COUNT(*) FROM conversations c JOIN accounts a ON a.id=c.account_id WHERE a.owner_id=?',(a['owner_id'],)).fetchone()[0]
                        if n>=a['conversation_limit']: continue
                        contacts=value.get('contacts',[]); name=next((x.get('profile',{}).get('name',msg['from']) for x in contacts if x.get('wa_id')==msg['from']),msg['from'])
                        db().execute('INSERT OR IGNORE INTO conversations(account_id,contact,contact_name) VALUES(?,?,?)',(a['id'],msg['from'],name))
                        c=db().execute('SELECT id FROM conversations WHERE account_id=? AND contact=?',(a['id'],msg['from'])).fetchone()
                    try: timestamp=int(msg.get('timestamp',0))
                    except (ValueError,TypeError): continue
                    timestamp=min(timestamp,int(time.time()))
                    db().execute("INSERT OR IGNORE INTO messages(conversation_id,meta_id,direction,body,created_at) VALUES(?,?,'in',?,datetime(?,'unixepoch'))",(c['id'],msg['id'],msg.get('text',{}).get('body',''),timestamp))
                    db().execute('UPDATE conversations SET last_activity=CURRENT_TIMESTAMP,last_inbound=MAX(COALESCE(last_inbound,0),?) WHERE id=?',(timestamp,c['id']))
                for status in value.get('statuses',[]):
                    if status.get('status') in ('sent','delivered','read','failed'):
                        db().execute('UPDATE messages SET status=? WHERE meta_id=? AND conversation_id IN (SELECT id FROM conversations WHERE account_id=?)',(status['status'],status.get('id'),a['id']))
        db().commit(); return jsonify(ok=True)
    @app.cli.command('create-admin')
    @click.option('--email',prompt=True)
    @click.option('--name',prompt=True)
    @click.password_option()
    def create_admin(email,name,password):
        if len(password)<12: raise click.ClickException('Minimum password length: 12')
        try: db().execute("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,'SUPER ADMIN')",(name,email.lower().strip(),'',generate_password_hash(password))); db().commit()
        except sqlite3.IntegrityError: raise click.ClickException('Email already exists')
        click.echo('Owner account created.')
    @app.cli.command('link-business')
    @click.option('--owner',type=int,required=True)
    @click.option('--phone-id',required=True)
    @click.option('--token-key',required=True)
    @click.option('--waba-id',required=True)
    def link_business(owner,phone_id,token_key,waba_id):
        if not re.fullmatch(r'[A-Z][A-Z0-9_]*',token_key) or not phone_id.isdigit() or not waba_id.isdigit(): raise click.ClickException('Invalid identifiers')
        if not db().execute("SELECT id FROM users WHERE id=? AND status='Active' AND deleted_at IS NULL",(owner,)).fetchone(): raise click.ClickException('Owner not found')
        token=os.getenv(token_key)
        if not token: raise click.ClickException('Token variable missing')
        version=os.getenv('META_GRAPH_VERSION','v23.0'); headers={'Authorization':'Bearer '+token}
        try:
            r=requests.get(f'https://graph.facebook.com/{version}/{phone_id}',headers=headers,params={'fields':'display_phone_number'},timeout=20); r.raise_for_status(); info=r.json()
            waba=waba_id
            r=requests.get(f'https://graph.facebook.com/{version}/{waba}/phone_numbers',headers=headers,timeout=20); r.raise_for_status()
            if phone_id not in [p['id'] for p in r.json()['data']]: raise ValueError()
        except (requests.RequestException,KeyError,ValueError): raise click.ClickException('Meta verification failed; no account linked')
        db().execute("INSERT INTO accounts(owner_id,phone,kind,phone_id,waba_id,status,token_key) VALUES(?,?,'Business',?,?,'Connected',?)",(owner,info['display_phone_number'],phone_id,waba,token_key)); db().commit()
        click.echo('Verified business account linked. Owner must grant consent in their dashboard.')
    @app.cli.command('purge-deleted')
    def purge():
        for u in rows("SELECT id FROM users WHERE deleted_at IS NOT NULL AND datetime(deleted_at)<=datetime('now','-30 days')"):
            uid=u['id']; db().execute('DELETE FROM messages WHERE conversation_id IN (SELECT c.id FROM conversations c JOIN accounts a ON a.id=c.account_id WHERE a.owner_id=?)',(uid,))
            db().execute('DELETE FROM conversations WHERE account_id IN (SELECT id FROM accounts WHERE owner_id=?)',(uid,))
            db().execute('DELETE FROM grants WHERE user_id=? OR account_id IN (SELECT id FROM accounts WHERE owner_id=?)',(uid,uid)); db().execute('DELETE FROM accounts WHERE owner_id=?',(uid,)); db().execute('DELETE FROM subscriptions WHERE user_id=?',(uid,))
            db().execute("UPDATE users SET name='Deleted user',email=?,phone='',password_hash='',privacy_at=NULL,last_login=NULL WHERE id=?",(f'deleted-{uid}@invalid.local',uid))
        db().commit(); click.echo('Retention purge completed; minimal audit records retained.')
    return app

app=create_app()
