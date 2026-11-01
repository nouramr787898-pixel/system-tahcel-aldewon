import hashlib
import hmac
import json
import time
from unittest.mock import Mock
import pytest
from werkzeug.security import generate_password_hash
from app import create_app

@pytest.fixture()
def app(tmp_path):
    app=create_app({'TESTING':True,'DATABASE':str(tmp_path/'test.db'),'SESSION_COOKIE_SECURE':False})
    with app.app_context():
        db=app.db()
        for uid,role in [(1,'SUPER ADMIN'),(2,'USER'),(3,'USER'),(4,'SUPPORT')]:
            db.execute('INSERT INTO users(id,name,email,phone,password_hash,role) VALUES(?,?,?,?,?,?)',(uid,f'User {uid}',f'u{uid}@example.com','1234567',generate_password_hash('valid-password-123'),role))
        for aid,owner,kind,consent in [(1,2,'Business','2026-01-01'),(2,3,'Business',None),(3,2,'Personal',None)]:
            db.execute("INSERT INTO accounts(id,owner_id,phone,kind,phone_id,waba_id,status,consent_at,token_key) VALUES(?,?,?,?,?,?,'Connected',?,'WA_TOKEN')",(aid,owner,str(aid)*8,kind,str(aid),'55',consent))
            db.execute('INSERT INTO conversations(id,account_id,contact,contact_name,last_inbound) VALUES(?,?,?,?,?)',(aid,aid,'20123456789','Customer',int(time.time())))
            db.execute("INSERT INTO messages(conversation_id,meta_id,direction,body) VALUES(?,?,'in','private message')",(aid,'m'+str(aid)))
        db.commit()
    return app

def client(app,uid=None):
    c=app.test_client()
    with c.session_transaction() as s:
        s['csrf']='test-csrf'
        if uid:s['uid']=uid;s['version']=0
    return c

def mutate(c,path,body=None,method='post'):
    return getattr(c,method)(path,json=body or {},headers={'X-CSRF-Token':'test-csrf'})

@pytest.mark.parametrize('path',['/admin','/api/users','/api/audit','/api/analytics','/api/subscriptions'])
def test_user_cannot_admin(app,path): assert client(app,2).get(path).status_code==403

def test_login_registration_csrf(app):
    c=client(app)
    assert c.post('/api/login',json={}).status_code==403
    assert mutate(c,'/api/register',{'name':'New','email':'new@example.com','phone':'20123456789','password':'long-password-123','privacy':True,'role':'SUPER ADMIN'}).status_code==201
    with app.app_context(): assert app.db().execute("SELECT role FROM users WHERE email='new@example.com'").fetchone()[0]=='USER'
    assert mutate(c,'/api/login',{'email':'new@example.com','password':'long-password-123'}).json['redirect']=='/user'
    assert c.get('/user').status_code==200

def test_owner_and_admin_scopes(app):
    assert [c['id'] for c in client(app,2).get('/api/conversations').json]==[1]
    assert client(app,2).get('/api/conversations/2/messages').status_code==403
    assert client(app,1).get('/api/conversations/2/messages').status_code==403
    assert client(app,1).get('/api/conversations/3/messages').status_code==403
    assert [c['id'] for c in client(app,1).get('/api/conversations').json]==[1]
    assert client(app,1).get('/api/conversations/1/messages').status_code==200

def test_support_grant_and_revoke(app):
    s=client(app,4); a=client(app,1)
    assert s.get('/api/conversations/1/messages').status_code==403
    assert mutate(a,'/api/grants',{'user_id':4,'account_id':1}).status_code==200
    assert s.get('/api/conversations/1/messages').status_code==200
    assert mutate(s,'/api/conversations/1/messages',{'body':'hello'}).status_code==403
    assert mutate(client(app,2),'/api/accounts/1',{'consent':False},'patch').status_code==200
    assert s.get('/api/conversations/1/messages').status_code==403
    assert a.get('/api/conversations/1/messages').status_code==403

def test_no_secrets(app):
    c=client(app,1)
    for path in ['/api/users','/api/users/2','/api/accounts']:
        response=c.get(path)
        assert response.status_code==200
        for forbidden in ['password_hash','token_key','WA_TOKEN','session_version']: assert forbidden not in response.text

def test_suspend_invalidates_session(app):
    c=client(app,2); a=client(app,1)
    assert mutate(a,'/api/users/2',{'status':'Suspended'},'patch').status_code==200
    assert c.get('/api/accounts').status_code==401
    assert a.get('/api/conversations/1/messages').status_code==403
    assert mutate(a,'/api/users/2',{'status':'Active'},'patch').status_code==200
    assert c.get('/api/accounts').status_code==401

def test_admin_cannot_self_escalate_or_delete_owner(app):
    a=client(app,1)
    assert mutate(a,'/api/users/2',{'role':'SUPER ADMIN'},'patch').status_code==400
    assert mutate(a,'/api/users/1',{},'delete').status_code==403
    assert mutate(client(app,2),'/api/accounts/2',{'consent':True},'patch').status_code==403

def test_deletion_retention(app):
    a=client(app,1)
    assert mutate(a,'/api/users/2',{},'delete').status_code==200
    assert a.get('/api/conversations/1/messages').status_code==403
    with app.app_context():
        assert app.db().execute('SELECT COUNT(*) FROM messages WHERE conversation_id=1').fetchone()[0]==1
        app.db().execute("UPDATE users SET deleted_at=datetime('now','-31 days') WHERE id=2");app.db().commit()
    assert app.test_cli_runner().invoke(args=['purge-deleted']).exit_code==0
    with app.app_context():
        assert app.db().execute('SELECT COUNT(*) FROM messages WHERE conversation_id=1').fetchone()[0]==0
        assert app.db().execute("SELECT COUNT(*) FROM audit WHERE action='user.delete_requested'").fetchone()[0]==1

def signed(c,payload,secret='app-secret'):
    raw=json.dumps(payload).encode()
    return c.post('/webhook',data=raw,content_type='application/json',headers={'X-Hub-Signature-256':'sha256='+hmac.new(secret.encode(),raw,hashlib.sha256).hexdigest()})

def test_signed_webhook_is_scoped_idempotent(app,monkeypatch):
    monkeypatch.setenv('META_APP_SECRET','app-secret');c=client(app)
    payload={'entry':[{'id':'55','changes':[{'value':{'metadata':{'phone_number_id':'1'},'messages':[{'id':'new-mid','from':'20123456789','type':'text','timestamp':str(int(time.time())),'text':{'body':'new incoming'}}]}}]}]}
    assert signed(c,payload,'bad').status_code==403
    assert signed(c,payload).status_code==200
    assert signed(c,payload).status_code==200
    with app.app_context(): assert app.db().execute("SELECT COUNT(*) FROM messages WHERE meta_id='new-mid'").fetchone()[0]==1
    payload['entry'][0]['id']='wrong-waba';payload['entry'][0]['changes'][0]['value']['messages'][0]['id']='wrong-mid'
    assert signed(c,payload).status_code==200
    with app.app_context(): assert app.db().execute("SELECT COUNT(*) FROM messages WHERE meta_id='wrong-mid'").fetchone()[0]==0

def test_send_uses_correct_business_and_audits(app,monkeypatch):
    monkeypatch.setenv('WA_TOKEN','secret-not-for-ui')
    sent=[]
    def post(url,**kwargs):
        sent.append((url,kwargs));r=Mock();r.json.return_value={'messages':[{'id':'sent-id'}]};return r
    monkeypatch.setattr('app.requests.post',post)
    c=client(app,1)
    assert mutate(c,'/api/conversations/2/messages',{'body':'bad'}).status_code==403
    assert mutate(c,'/api/conversations/1/messages',{'body':'reply'}).status_code==201
    assert sent[0][0].endswith('/1/messages')
    assert sent[0][1]['json']['to']=='20123456789'
    with app.app_context():
        assert app.db().execute("SELECT COUNT(*) FROM audit WHERE action='message.send'").fetchone()[0]==1
        app.db().execute('UPDATE conversations SET last_inbound=1 WHERE id=1');app.db().commit()
    assert mutate(c,'/api/conversations/1/messages',{'body':'late'}).status_code==409

def test_api_failure_does_not_record_sent(app,monkeypatch):
    import requests
    monkeypatch.setenv('WA_TOKEN','secret')
    monkeypatch.setattr('app.requests.post',Mock(side_effect=requests.Timeout))
    assert mutate(client(app,1),'/api/conversations/1/messages',{'body':'reply'}).status_code==502
    with app.app_context(): assert app.db().execute("SELECT COUNT(*) FROM messages WHERE direction='out'").fetchone()[0]==0

def test_limits_and_validation(app):
    assert mutate(client(app,1),'/api/users/2',{'conversation_limit':-1},'patch').status_code==400
    assert client(app,1).get('/api/analytics').json['conversations']==1
    assert client(app,1).get('/admin').status_code==200
    assert client(app).get('/api/accounts').status_code==401

def test_events_recheck_access(app):
    c=client(app,2);r=c.get('/api/events',buffered=False)
    first=next(r.response)
    assert b'changed' in first
    r.close()

def test_stream_revocation_is_observed(app,monkeypatch):
    import sqlite3
    monkeypatch.setattr('app.time.sleep',lambda _:None)
    c=client(app,2);r=c.get('/api/events',buffered=False)
    assert b'changed' in next(r.response)
    with sqlite3.connect(app.config['DATABASE']) as db:
        db.execute("UPDATE users SET status='Suspended' WHERE id=2")
    assert b'event: revoked' in next(r.response)
    r.close()

def test_business_link_requires_verified_membership(app,monkeypatch):
    monkeypatch.setenv('WA_TOKEN','token')
    info=Mock();info.json.return_value={'display_phone_number':'+20100000000'}
    membership=Mock();membership.json.return_value={'data':[{'id':'999'}]}
    monkeypatch.setattr('app.requests.get',Mock(side_effect=[info,membership]))
    result=app.test_cli_runner().invoke(args=['link-business','--owner','2','--phone-id','777','--waba-id','55','--token-key','WA_TOKEN'])
    assert result.exit_code!=0
    with app.app_context(): assert app.db().execute("SELECT COUNT(*) FROM accounts WHERE phone_id='777'").fetchone()[0]==0

def test_user_search_and_account_consent_cannot_be_forged(app):
    a=client(app,1)
    assert [u['id'] for u in a.get('/api/users?q=u2@example.com').json]==[2]
    assert mutate(a,'/api/accounts/2',{'consent':True},'patch').status_code==403
    assert mutate(client(app,2),'/api/accounts',{'phone':'+20100100100','kind':'Business','phone_id':'777'}).status_code==400
