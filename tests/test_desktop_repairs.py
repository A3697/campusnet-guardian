import datetime
from urllib.parse import parse_qs, urlsplit

from conftest import FakeSession, make_response
from campusnet.config import Config
from campusnet import policy
from campusnet.providers import SrunProvider
from campusnet.runner import Runner
from campusnet.session import _log_url


def test_tun_address_is_replaced_with_server_observed_address():
    session = FakeSession(routes=[
        ('get_challenge', make_response('jsonp({"challenge":"abc123","client_ip":"100.78.1.2","res":"ok"})')),
        ('srun_portal', make_response('jsonp({"error":"ok","suc_msg":"login_ok"})')),
    ])
    result = SrunProvider(session, {}).login('https://example.edu', 'sample', 'sample-password', '198.18.0.1')
    assert result.ok
    query = parse_qs(urlsplit(session.find('srun_portal')[1]).query)
    assert query['ip'] == ['100.78.1.2']
    challenges = [parse_qs(urlsplit(call[1]).query) for call in session.calls if 'get_challenge' in call[1]]
    assert [item['ip'][0] for item in challenges] == ['198.18.0.1', '100.78.1.2']
    assert all('_' in item for item in challenges)


def test_portal_offline_overrides_proxy_internet(monkeypatch):
    runner = Runner(Config(provider='srun', portal_ip='https://example.edu'))
    runner._session = FakeSession(routes=[('rad_user_info', make_response('jsonp({"error":"not_online_error"})'))])
    def public_check(*args):
        raise AssertionError('Public connectivity must not override portal logout')
    monkeypatch.setattr('campusnet.runner.check_online', public_check)
    assert not runner.status().online


def test_unknown_portal_status_keeps_generic_fallback():
    session = FakeSession(routes=[('rad_user_info', make_response('<html>unknown</html>'))])
    assert SrunProvider(session, {}).online_state('https://example.edu') is None


def test_empty_auth_json_is_not_success():
    provider = SrunProvider(FakeSession(), {})
    assert not provider._as_result(make_response('jsonp({})'), '/cgi-bin/srun_portal').ok


def test_auth_query_is_redacted():
    text = _log_url('https://example.edu/cgi-bin/srun_portal?username=test&password=secret&info=encoded')
    assert 'secret' not in text and 'encoded' not in text and 'username' not in text
    assert '/cgi-bin/srun_portal' in text


def test_overnight_schedule_and_pause(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, 'state_path', lambda: str(tmp_path / 'state.json'))
    config = Config(options={'reconnect_interval':5,'reconnect_delay':60,'reconnect_windows':'23:00-07:00'})
    assert not policy.block_reason(config, datetime.datetime(2026,11,2,23,30))
    assert policy.block_reason(config, datetime.datetime(2026,11,2,12,0))
    policy.pause_for(60)
    assert policy.block_reason(config, datetime.datetime(2026,11,2,23,30))
    policy.resume()
    assert not policy.block_reason(config, datetime.datetime(2026,11,2,23,30))
    assert policy.interval_minutes(config) == 5 and policy.reconnect_delay(config) == 60


def test_disabled_radio_does_not_wait_or_connect(monkeypatch):
    from campusnet import wifi
    monkeypatch.setattr(wifi, 'current_ssid', lambda: '')
    monkeypatch.setattr(wifi.platform, 'system', lambda: 'Windows')
    monkeypatch.setattr(wifi, '_run', lambda command: (0, 'Name : WLAN\nRadio status : Hardware On\n Software Off\n'))
    def unexpected(*args, **kwargs):
        raise AssertionError('Disabled Wi-Fi must not delay wired authentication')
    monkeypatch.setattr(wifi, 'wait_for_radio', unexpected)
    monkeypatch.setattr(wifi, 'connect', unexpected)
    result = wifi.ensure_wifi('CampusWiFi', ready_timeout=25, attempts=2)
    assert result.ok and not result.supported and not result.changed


def test_netsh_output_decodes_utf8_and_system_codepage():
    from campusnet import wifi
    text = '无线电状态 : 硬件打开\n 软件关闭'
    assert wifi._decode_output(text.encode('utf-8')) == text
    assert wifi._decode_output(text.encode('utf-16')) == text
    import os
    if os.name == 'nt':
        assert wifi._decode_output(text.encode('mbcs')) == text
    assert wifi._radio_off('无线电状态 : 硬件 开\n 软件 关')
    assert not wifi._radio_off('无线电状态 : 硬件 开\n 软件 开')
