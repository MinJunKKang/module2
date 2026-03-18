import json
import streamlit as st


STYLES = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Noto+Sans+KR:wght@400;500;700&display=swap');

html, body, [class*="css"] {
    background-color: #f5f7fa !important;
    color: #1a1a2e !important;
    font-family: 'Noto Sans KR', sans-serif !important;
    font-size: 16px !important;
}
section[data-testid="stSidebar"] {
    background: #ffffff !important;
    border-right: 2px solid #e2e8f0 !important;
}
header[data-testid="stHeader"] { display: none !important; }

.stTabs [data-baseweb="tab-list"] {
    background: #ffffff !important;
    border-bottom: 2px solid #e2e8f0 !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important;
    color: #718096 !important;
    font-family: 'Noto Sans KR', sans-serif !important;
    font-size: 16px !important;
    font-weight: 600 !important;
    padding: 14px 28px !important;
    border-bottom: 3px solid transparent !important;
}
.stTabs [aria-selected="true"] {
    color: #2563eb !important;
    border-bottom: 3px solid #2563eb !important;
    background: transparent !important;
}

.streamlit-expanderHeader {
    background: #ffffff !important;
    border: 2px solid #e2e8f0 !important;
    border-radius: 8px !important;
    font-size: 16px !important;
    font-weight: 700 !important;
    color: #1a1a2e !important;
    padding: 14px 18px !important;
}
.streamlit-expanderContent {
    background: #ffffff !important;
    border: 2px solid #e2e8f0 !important;
    border-top: none !important;
    border-radius: 0 0 8px 8px !important;
    padding: 16px !important;
}

.stButton > button {
    background: #2563eb !important;
    border: none !important;
    color: #ffffff !important;
    font-family: 'Noto Sans KR', sans-serif !important;
    font-size: 15px !important;
    font-weight: 700 !important;
    border-radius: 8px !important;
    padding: 10px 20px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    background: #1d4ed8 !important;
    transform: translateY(-1px) !important;
}

.stProgress > div > div { background: #2563eb !important; }

div[data-testid="stMarkdownContainer"] p {
    font-size: 15px !important;
    line-height: 1.8 !important;
    color: #2d3748 !important;
}
div[data-testid="stMarkdownContainer"] h1 { font-size: 28px !important; color: #1a1a2e !important; }
div[data-testid="stMarkdownContainer"] h2 { font-size: 22px !important; color: #1a1a2e !important; }
div[data-testid="stMarkdownContainer"] h3 { font-size: 18px !important; color: #1a1a2e !important; }

.stCodeBlock { border-radius: 8px !important; font-size: 14px !important; }
.stAlert { border-radius: 8px !important; font-size: 15px !important; }
</style>
"""


def fake_terminal(tid, responses: dict, host="ServerA", user="www-data"):
    prompt = f"[{user}@{host}]$ "
    escaped = json.dumps(responses, ensure_ascii=False)
    html = f"""
<div style="background:#1e1e2e;border-radius:10px;border:1px solid #ccc;overflow:hidden;
     font-family:'Share Tech Mono',monospace;box-shadow:0 4px 16px rgba(0,0,0,0.15);">
    <div style="background:#2d2d3f;padding:10px 16px;display:flex;align-items:center;gap:8px;border-bottom:1px solid #444;">
        <div style="width:12px;height:12px;border-radius:50%;background:#ff5f57;"></div>
        <div style="width:12px;height:12px;border-radius:50%;background:#febc2e;"></div>
        <div style="width:12px;height:12px;border-radius:50%;background:#28c840;"></div>
        <span style="color:#aaa;font-size:13px;margin-left:10px;">{user}@{host} — bash</span>
        <span style="margin-left:auto;font-size:11px;color:#ff6b6b;font-weight:bold;">● SIMULATION</span>
    </div>
    <div id="out_{tid}" style="color:#a8ff78;font-size:14px;line-height:1.7;height:280px;overflow-y:auto;
         padding:14px 18px;background:#1e1e2e;white-space:pre-wrap;word-break:break-all;">{prompt}</div>
    <div style="display:flex;align-items:center;gap:10px;padding:10px 16px;background:#252535;border-top:1px solid #444;">
        <span style="color:#a8ff78;font-size:14px;white-space:nowrap;">{prompt}</span>
        <input id="in_{tid}" type="text" autocomplete="off" spellcheck="false"
            style="flex:1;background:transparent;color:#a8ff78;border:none;outline:none;
                   font-family:'Share Tech Mono',monospace;font-size:14px;caret-color:#a8ff78;"
            onkeydown="handleKey_{tid}(event)"/>
    </div>
</div>
<script>
(function(){{
    const R={escaped};
    const P={json.dumps(prompt)};
    const H=[];
    let idx=-1;
    window["handleKey_{tid}"]=function(e){{
        const inp=document.getElementById('in_{tid}');
        if(e.key==='Enter'){{
            const cmd=inp.value.trim();
            if(!cmd)return;
            const out=document.getElementById('out_{tid}');
            H.push(cmd); idx=-1; inp.value='';
            out.innerHTML+='<span style="color:#ffd93d;font-weight:bold;">'+esc(cmd)+'</span>\\n';
            if(cmd==='clear'){{ out.textContent=P; return; }}
            const res=R[cmd];
            if(res===undefined) out.innerHTML+='<span style="color:#ff6b6b;">bash: '+esc(cmd.split(' ')[0])+': command not found</span>\\n';
            else if(res!=='') out.innerHTML+='<span style="color:#e2e8f0;">'+esc(res)+'</span>\\n';
            out.innerHTML+=P;
            out.scrollTop=out.scrollHeight;
        }} else if(e.key==='ArrowUp'){{
            e.preventDefault();
            if(idx<H.length-1){{ idx++; inp.value=H[H.length-1-idx]; }}
        }} else if(e.key==='ArrowDown'){{
            e.preventDefault();
            if(idx>0){{ idx--; inp.value=H[H.length-1-idx]; }}
            else{{ idx=-1; inp.value=''; }}
        }}
    }};
    function esc(s){{ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}
}})();
</script>
"""
    st.components.v1.html(html, height=400)


def section_header(label, color="#2563eb"):
    st.markdown(f"""
<div style="color:{color};font-size:13px;font-weight:700;letter-spacing:1px;margin-bottom:12px;
     padding-bottom:6px;border-bottom:2px solid {color}22;">
    {label}
</div>
""", unsafe_allow_html=True)


def vuln_box(items: list):
    rows = "".join(f"<div style='color:#7f1d1d;padding:3px 0;font-size:14px;'>→ {i}</div>" for i in items)
    st.markdown(f"""
<div style="background:#fff5f5;border:2px solid #fca5a5;border-radius:8px;padding:14px 16px;margin-top:10px;">
    <div style="color:#dc2626;font-weight:700;font-size:15px;margin-bottom:8px;">⚠️ 취약점 원인</div>
    {rows}
</div>
""", unsafe_allow_html=True)


def defense_box(items: list):
    rows = "".join(f"<div style='color:#1e3a5f;padding:3px 0;font-size:14px;'>→ {i}</div>" for i in items)
    st.markdown(f"""
<div style="background:#eff6ff;border:2px solid #93c5fd;border-radius:8px;padding:14px 16px;margin-top:10px;">
    <div style="color:#2563eb;font-weight:700;font-size:15px;margin-bottom:8px;">✅ 방어 효과</div>
    {rows}
</div>
""", unsafe_allow_html=True)


def done_hint(text):
    st.markdown(f"""
<div style="color:#718096;font-size:13px;margin-top:8px;">
    ✓ 완료 조건: {text}
</div>
""", unsafe_allow_html=True)