"""Exercise real Tk wheel dispatch, including child-widget class bindings."""
from test_gui_password import app


def show_logs(app):
    app.root.deiconify()
    app.root.geometry("{}x{}+20+20".format(app._px(620),app._px(800)))
    app.show_main()
    app.toggle_log(True)
    app._append_log("\n".join("Log line {}".format(i) for i in range(120)))
    app.root.update()
    app._main_canvas.yview_moveto(0)
    app.log_box.yview_moveto(0)
    app.root.update_idletasks()


def wheel(app, widget, delta=-120):
    widget.event_generate("<MouseWheel>",delta=delta)
    app.root.update_idletasks()


def test_wheel_over_clipped_log_reveals_page_before_scrolling_log(app):
    show_logs(app)
    canvas=app._main_canvas
    text=app.log_box
    overhead=app.root.winfo_height()-canvas.winfo_height()
    log_top=text.winfo_rooty()-canvas.winfo_rooty()
    app.root.geometry("{}x{}".format(app.root.winfo_width(),log_top+text.winfo_height()//2+overhead))
    app.root.update()
    assert text.winfo_rooty()+text.winfo_height()>canvas.winfo_rooty()+canvas.winfo_height()
    old_page,old_log=canvas.yview(),text.yview()
    wheel(app,text)
    assert canvas.yview()[0]>old_page[0]
    assert text.yview()==old_log


def test_fully_visible_log_scrolls_itself_and_hands_boundary_to_page(app):
    show_logs(app)
    canvas=app._main_canvas
    canvas.yview_moveto(1)
    app.root.update_idletasks()
    app.log_box.yview_moveto(0)
    page=canvas.yview()
    wheel(app,app.log_box)
    assert app.log_box.yview()[0]>0 and canvas.yview()==page
    app.log_box.yview_moveto(0)
    wheel(app,app.log_box,120)
    assert canvas.yview()[0]<page[0]


def test_wheel_over_pause_input_scrolls_page_without_changing_minutes(app):
    show_logs(app)
    value=app.var_pause.get()
    before=app._main_canvas.yview()
    wheel(app,app.spin_pause)
    assert app.var_pause.get()==value
    assert app._main_canvas.yview()[0]>before[0]


def test_setup_wheel_reaches_lower_fields(app):
    app.root.deiconify()
    app.root.geometry("{}x{}".format(app._px(540),app._px(460)))
    app.show_setup()
    app.root.update()
    before=app._setup_canvas.yview()
    wheel(app,app.var_carrier_widget)
    assert app._setup_canvas.yview()[0]>before[0]


def test_new_policy_time_inputs_scroll_their_own_window_without_editing_time(app):
    app.root.deiconify()
    app.show_policy()
    win=app._policy_win
    win.geometry("{}x{}".format(app._px(500),app._px(440)))
    app._policy_vars[2].set(True)
    app._add_policy_window(12*60,13*60)
    app.root.update()
    row=app._policy_time_rows[-1]
    values=[v.get() for v in row["vars"]]
    from tkinter import Canvas
    canvas=next(w for w in win.winfo_children() if isinstance(w,Canvas))
    old_page=app._main_canvas.yview()
    before=canvas.yview()
    wheel(app,row["spins"][0])
    assert [v.get() for v in row["vars"]]==values
    assert canvas.yview()[0]>before[0]
    assert app._main_canvas.yview()==old_page
