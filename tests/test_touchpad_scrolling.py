import tkinter as tk

import pytest

from test_gui_password import app
from test_gui_scrolling import show_logs


def touchpad(app, widget, dy=-20, dx=0):
    if int(app.root.tk.call("package", "vcompare", app.root.tk.call("package", "provide", "Tk"), "9.0")) < 0:
        pytest.skip("Tk 9 touchpad events")
    packed = ((dx & 0xffff) << 16) | (dy & 0xffff)
    if packed >= 0x80000000:
        packed -= 0x100000000
    widget.event_generate("<TouchpadScroll>", delta=packed)
    app.root.update_idletasks()


def test_touchpad_scrolls_page_like_standard_text_control(app):
    show_logs(app)
    normal = tk.Toplevel(app.root)
    text = tk.Text(normal, height=8)
    text.pack()
    text.insert("1.0", "\n".join("Line {}".format(i) for i in range(100)))
    app.root.update()
    try:
        before = app._main_canvas.yview()[0]
        touchpad(app, text)
        assert text.yview()[0] > 0
        touchpad(app, app._main_canvas)
        assert app._main_canvas.yview()[0] > before
    finally:
        normal.destroy()


@pytest.mark.parametrize("dy,dx", [(-1, 0), (-15, 0), (-31, 12), (-17, -8)])
def test_small_and_diagonal_touchpad_events_scroll_without_editing_numbers(app,dy,dx):
    show_logs(app)
    value = app.var_pause.get()
    before = app._main_canvas.yview()[0]
    for _ in range(4):
        touchpad(app,app.spin_pause,dy,dx)
    assert app._main_canvas.yview()[0] > before
    assert app.var_pause.get() == value


def test_horizontal_touchpad_does_not_scroll_vertical_page(app):
    show_logs(app)
    before = app._main_canvas.yview()
    touchpad(app,app.spin_pause,0,24)
    assert app._main_canvas.yview() == before


def test_touchpad_over_clipped_log_scrolls_outer_page_first(app):
    show_logs(app)
    canvas = app._main_canvas
    assert app.log_box.winfo_rooty()+app.log_box.winfo_height() > canvas.winfo_rooty()+canvas.winfo_height()
    before_page, before_log = canvas.yview(),app.log_box.yview()
    touchpad(app,app.log_box)
    assert canvas.yview()[0] > before_page[0]
    assert app.log_box.yview() == before_log


def test_touchpad_visible_log_and_boundary_handoff(app):
    show_logs(app)
    canvas = app._main_canvas
    canvas.yview_moveto(1)
    app.root.update_idletasks()
    before = canvas.yview()
    touchpad(app,app.log_box)
    assert app.log_box.yview()[0] > 0 and canvas.yview() == before
    app.log_box.yview_moveto(0)
    touchpad(app,app.log_box,20)
    assert canvas.yview()[0] < before[0]


def test_touchpad_setup_and_policy_pages(app):
    app.root.deiconify()
    app.root.geometry("{}x{}".format(app._px(540),app._px(460)))
    app.show_setup()
    app.root.update()
    before = app._setup_canvas.yview()[0]
    touchpad(app,app.var_carrier_widget)
    assert app._setup_canvas.yview()[0] > before
    app.show_policy()
    app._policy_win.geometry("{}x{}".format(app._px(500),app._px(440)))
    app._policy_vars[2].set(True)
    app._add_policy_window(12*60,13*60)
    app.root.update()
    row = app._policy_time_rows[-1]
    values = [v.get() for v in row["vars"]]
    before = app._policy_canvas.yview()[0]
    touchpad(app,row["spins"][0])
    assert app._policy_canvas.yview()[0] > before
    assert [v.get() for v in row["vars"]] == values
