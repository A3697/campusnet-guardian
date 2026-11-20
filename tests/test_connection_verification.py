import pytest

from campusnet import detector, runner as runner_module
from campusnet.config import Config
from campusnet.detector import NetStatus
from campusnet.providers.base import LoginResult
from campusnet.providers.srun import SrunProvider
from campusnet.runner import Runner
from conftest import FakeSession, make_response


@pytest.fixture
def probes(monkeypatch):
    monkeypatch.setattr(detector, 'HIJACK_PROBES', [('http://probe.example/check', 204, None)])
    monkeypatch.setattr(detector, 'CONTENT_PROBES', [('http://www.qq.com/', 'real-content')])


def test_normal_https_redirect_is_followed_and_is_not_a_portal(probes):
    session = FakeSession([
        ('probe.example', make_response('', 204)),
        (lambda u:u=='http://www.qq.com/', make_response('', 302, {'location':'https://www.qq.com/'}, 'http://www.qq.com/')),
        (lambda u:u=='https://www.qq.com/', make_response('real-content', url='https://www.qq.com/')),
    ])
    result = detector.check_online(session)
    assert result.online and not result.portal_url
    assert 'https://www.qq.com/' in session.urls


def test_real_portal_redirect_survives_a_later_normal_website_redirect(probes, monkeypatch):
    monkeypatch.setattr(detector, 'HIJACK_PROBES', [('http://probe.example/check',204,None),('http://second.example/check',204,None)])
    portal='http://campus.example/login'
    session=FakeSession([
        ('probe.example',make_response('',302,{'location':portal})),
        ('second.example',make_response('',204)),
        (lambda u:u=='http://www.qq.com/',make_response('',302,{'location':'https://www.qq.com/'})),
        (lambda u:u=='https://www.qq.com/',make_response('unavailable',503)),
    ])
    result=detector.check_online(session)
    assert not result.online and result.portal_url==portal
    assert 'https://www.qq.com/' not in result.portal_urls


def test_untrusted_redirect_is_not_accepted_as_normal_content(probes):
    session=FakeSession([
        ('probe.example',make_response('',204)),
        ('http://www.qq.com/',make_response('',302,{'location':'http://www.qq.com.attacker.example/login'})),
        ('attacker.example',make_response('real-content')),
    ])
    result=detector.check_online(session)
    assert not result.online and result.portal_url.endswith('/login')
    assert not any('attacker.example' in u for u in session.urls)


@pytest.mark.parametrize('portal', ['', 'http://campus.example/login'])
def test_two_real_websites_can_confirm_access_when_probe_service_is_down(probes,monkeypatch,portal):
    monkeypatch.setattr(detector,'CONTENT_PROBES',[('https://www.qq.com/','qq-content'),('https://www.baidu.com/','baidu-content')])
    probe=make_response('',302,{'location':portal}) if portal else make_response('',429)
    session=FakeSession([('probe.example',probe),('www.qq.com',make_response('qq-content')),('www.baidu.com',make_response('baidu-content'))])
    assert detector.check_online(session).online is (not bool(portal))


def test_a_single_allowed_site_is_insufficient_when_probes_fail(probes):
    session=FakeSession([('probe.example',make_response('',429)),('www.qq.com',make_response('real-content'))])
    assert not detector.check_online(session).online


def test_manual_discovery_only_uses_the_supplied_address(monkeypatch):
    cfg=Config(portal_mode='manual',portal_ip='https://selected.example/login')
    monkeypatch.setattr(detector,'check_online',lambda *a:pytest.fail('Manual discovery must not run unrelated probes'))
    session=FakeSession([('selected.example',make_response('srun_portal',url=cfg.portal_ip))])
    assert detector.detect(session,cfg).best=='srun'
    assert session.urls==[cfg.portal_ip]


def test_discovery_reports_connection_errors_instead_of_unknown_page(monkeypatch):
    from campusnet.session import HttpError
    class Unavailable:
        def get(self,*a,**kw):raise HttpError('connection refused')
    result=detector.detect(Unavailable(),Config(portal_mode='manual',portal_ip='http://selected.example/'),NetStatus())
    assert not result.best and 'connection refused' in result.detail


def test_online_without_redirect_is_not_reported_as_a_failed_login(monkeypatch):
    monkeypatch.setattr(detector,'default_gateway',lambda:'')
    result=detector.detect(FakeSession(),Config(portal_mode='auto'),NetStatus(True))
    assert not result.best and '已联网' in result.detail


@pytest.mark.parametrize('state,web,expected',[(None,True,True),(False,True,False),(True,False,False),(True,True,True)])
def test_portal_account_and_web_connectivity_are_separate(monkeypatch,state,web,expected):
    cfg=Config(username='fixture',provider='srun',portal_ip='https://selected.example/',portal_mode='manual',options={'verify_srun_session':True})
    monkeypatch.setattr(runner_module,'check_online',lambda *a:NetStatus(web))
    monkeypatch.setattr(SrunProvider,'online_state',lambda *a:state)
    status=Runner(cfg).status()
    assert status.online is expected and status.authenticated is state
    if state is True and not web:
        assert '已认证' in status.describe() and '未认证' not in status.describe()
    if state is None:
        assert '暂未确认' in status.describe()


def test_plain_json_srun_status_is_supported():
    session=FakeSession([('rad_user_info',make_response('{"error":"ok","online_ip":"10.0.0.2","user_name":"fixture","message":"online (IPv4)"}'))])
    assert SrunProvider(session,{}).online_state('https://selected.example/','fixture') is True


@pytest.mark.parametrize('ready',[True,False])
def test_login_verifies_again_while_network_becomes_ready(monkeypatch,ready):
    cfg=Config(username='fixture',password='test-only',provider='srun',portal_ip='https://selected.example/',
               options={'verify_srun_session':True,'verify_delay':0})
    monkeypatch.setattr(Config,'resolve_password',lambda self,**kw:self.password)
    monkeypatch.setattr(Runner,'client_ip',property(lambda self:'10.0.0.2'))
    monkeypatch.setattr(runner_module,'local_mac',lambda:'')
    states=iter([NetStatus(False),NetStatus(False,authenticated=True),NetStatus(ready,authenticated=True),NetStatus(False,authenticated=True)])
    runner=Runner(cfg)
    monkeypatch.setattr(runner,'status',lambda:next(states))
    calls=[]
    class Provider:
        display_name='fixture'
        def __init__(self,*a):pass
        def login(self,*a):
            calls.append(a)
            return LoginResult(True,'srun','accepted')
    monkeypatch.setattr(runner_module,'get_provider',lambda name:Provider)
    result=runner.ensure_online(wifi_checked=True)
    assert result.ok is ready and result.status_after.authenticated is True
    if not ready:
        assert '已认证' in result.message
    assert len(calls)==1


def test_authenticated_account_is_not_reauthenticated_when_probes_are_unavailable(monkeypatch):
    runner=Runner(Config(username='fixture',options={'random_mac_retry':True}))
    monkeypatch.setattr(runner,'status',lambda:NetStatus(False,authenticated=True))
    monkeypatch.setattr(Config,'resolve_password',lambda *a,**kw:pytest.fail('No new authentication is needed'))
    result=runner.ensure_online(wifi_checked=True)
    assert result.skipped and not result.ok and result.status_after.authenticated is True


def test_manual_discovery_parameters_are_used_for_status_and_authentication():
    cfg=Config(portal_mode='manual',discovered_options={'ac_id':'42','srun_status_path':'/custom/cgi-bin/rad_user_info'},options={'carrier':'cmcc'})
    options=Runner(cfg)._portal_options({})
    assert options['ac_id']=='42' and options['srun_status_path']=='/custom/cgi-bin/rad_user_info'


def test_unknown_account_status_is_not_logged_as_verified(monkeypatch):
    logs=[]
    runner=Runner(Config(options={'verify_srun_session':True}),lambda msg,level:logs.append(msg))
    monkeypatch.setattr(runner,'status',lambda:NetStatus(True))
    monkeypatch.setattr(runner,'ensure_wifi',lambda **kw:type('Wifi',(),{'changed':False})())
    assert runner._watch_round(None)
    assert not any('校园账号会话在线' in msg for msg in logs)
