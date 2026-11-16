from pathlib import Path
from tkinter import messagebox

from campusnet import gui, updater, __version__
from test_gui_password import app
from test_updater import info


def available(app):
    release=info(version="0.2.0+desktop.20261117.1")
    app._dispatch(("update_info",release))
    return release


def test_current_or_older_release_does_not_enable_install(app):
    app._dispatch(("update_info",info(version=__version__)))
    assert app._update_info is None and str(app.btn_install_update.cget('state'))=='disabled'
    assert '最新' in app.lbl_update_status.cget('text')


def test_new_release_and_network_errors_leave_retry_available(app):
    available(app)
    assert str(app.btn_install_update.cget('state'))=='normal'
    app._set_busy(True,'')
    app._dispatch(('update_error','无法连接 GitHub'))
    assert not app._busy and str(app.btn_check_update.cget('state'))=='normal'
    assert str(app.btn_install_update.cget('state'))=='normal'
    assert 'GitHub' in app.lbl_update_status.cget('text')


def test_declining_install_does_not_start_work(app,monkeypatch,tmp_path):
    available(app)
    monkeypatch.setattr(updater,'installation_dir',lambda:tmp_path)
    monkeypatch.setattr(messagebox,'askyesno',lambda *a,**kw:False)
    app.install_update()
    assert not app._busy and app._update_cancel is None


def test_download_can_be_cancelled_even_as_it_finishes(app,monkeypatch,tmp_path):
    release=available(app)
    monkeypatch.setattr(updater,'installation_dir',lambda:tmp_path)
    monkeypatch.setattr(messagebox,'askyesno',lambda *a,**kw:True)
    calls=[]
    app._spawn=lambda fn,*args:calls.append(fn)
    app.install_update()
    assert app._busy and calls==[app._job_download_update]
    assert str(app.btn_setup.cget('state'))=='disabled'
    app.cancel_update()
    app._dispatch(('update_downloaded',Path('unused.exe'),release,tmp_path))
    assert not app._busy and calls==[app._job_download_update]
    assert '已取消' in app.lbl_update_status.cget('text')


def test_download_progress_then_handoff_to_installer(app,monkeypatch,tmp_path):
    release=available(app)
    monkeypatch.setattr(updater,'installation_dir',lambda:tmp_path)
    monkeypatch.setattr(messagebox,'askyesno',lambda *a,**kw:True)
    calls=[]
    app._spawn=lambda fn,*args:calls.append(fn)
    app.install_update()
    app._dispatch(('update_progress',50,100))
    assert app.update_progress['value']==50
    app._dispatch(('update_downloaded',Path('unused.exe'),release,tmp_path))
    assert calls[-1]==app._job_install_update and app._busy
    assert app._active_job==app._job_install_update
    app._dispatch(('update_finished',))
    assert not app._busy and app._update_info is None


def test_tray_update_action_preserves_unsaved_account_edits(app):
    app.show_setup()
    app.var_username.set('unsaved-test-account')
    app._show_updates()
    assert app._page=='setup' and app.var_username.get()=='unsaved-test-account'
    assert not app._busy
