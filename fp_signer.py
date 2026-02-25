# -*- coding: utf-8 -*-
# fp_signer.py (Jython / Burp)

from burp import IBurpExtender, IHttpListener, ITab
from java.awt import BorderLayout
from javax.swing import JPanel, JLabel, JTextField, JCheckBox, JButton, JTextArea, JScrollPane, BoxLayout
import re, time, hashlib, hmac, urllib

try:
    unicode
except NameError:
    unicode = str

def _pct_decode(s):
    return urllib.unquote(s)

def _pct_encode(u):
    if isinstance(u, unicode):
        u = u.encode("utf-8")
    return urllib.quote(u, safe='-._~')

def normalize_path(path):
    if not path.startswith("/"):
        path = "/" + path
    parts = []
    for seg in path.split("/"):
        if seg == "" or seg == ".":
            continue
        if seg == "..":
            if parts: parts.pop()
            continue
        parts.append(_pct_encode(_pct_decode(seg)))
    return "/" + "/".join(parts)

def canon_query(qs):
    if not qs:
        return ""
    pairs = []
    for item in qs.split("&"):
        if not item:
            continue
        k, sep, v = item.partition("=")
        kd = _pct_decode(k)
        vd = _pct_decode(v)
        if kd.lower() == "x-fp-signature":
            continue
        pairs.append((kd, vd))
    pairs.sort() 
    return "&".join("%s=%s" % (_pct_encode(k), _pct_encode(v)) for (k, v) in pairs)

def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()

def hmac_sha256_hex(key_bytes, msg_bytes):
    return hmac.new(key_bytes, msg_bytes, hashlib.sha256).hexdigest()

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self.cb = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("FP Signer")
        self._build_ui()
        callbacks.customizeUiComponent(self.panel)
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)

        self.secret = "1234567"
        self.include_sdk = True
        self.sdk_value = "1.4.8-alpha.1720434476"
        self.sign_content_type = False
        self.unsigned_payload = False
        self.host_regex = re.compile(r"^example\.com(:443)?$", re.I)
        self.tools_enabled = set([callbacks.TOOL_SCANNER])
        self.log("Loaded. Configure in the FP Signer tab.")
        return

    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        form = JPanel()
        form.setLayout(BoxLayout(form, BoxLayout.Y_AXIS))

        def row(label, comp):
            p = JPanel(BorderLayout(5,5))
            p.add(JLabel(label), BorderLayout.WEST); p.add(comp, BorderLayout.CENTER)
            form.add(p)

        self.tfSecret = JTextField("1234567", 30)
        row("Secret:", self.tfSecret)

        self.cbIncludeSdk = JCheckBox("Include X-Fp-Sdk-Version", True)
        form.add(self.cbIncludeSdk)

        self.tfSdk = JTextField("1.4.8-alpha.1720434476", 30)
        row("SDK value:", self.tfSdk)

        self.cbSignCT = JCheckBox("Sign Content-Type (usually OFF)", False)
        form.add(self.cbSignCT)

        self.cbUnsigned = JCheckBox("Use UNSIGNED-PAYLOAD", False)
        form.add(self.cbUnsigned)

        self.tfHostRe = JTextField("^www\\.example\\.com(:443)?$", 30)
        row("Target host regex (matches Host header):", self.tfHostRe)

        self.cbScanner = JCheckBox("Enable for Scanner", True)
        self.cbRepeater = JCheckBox("Enable for Repeater", False)
        self.cbIntruder = JCheckBox("Enable for Intruder", False)
        self.cbProxy = JCheckBox("Enable for Proxy", False)
        form.add(self.cbScanner); form.add(self.cbRepeater); form.add(self.cbIntruder); form.add(self.cbProxy)

        btnApply = JButton("Apply", actionPerformed=self._apply)
        form.add(btnApply)

        self.logArea = JTextArea(8, 80); self.logArea.setEditable(False)
        self.panel.add(form, BorderLayout.NORTH)
        self.panel.add(JScrollPane(self.logArea), BorderLayout.CENTER)

    def _apply(self, _evt):
        self.secret = self.tfSecret.getText().strip()
        self.include_sdk = self.cbIncludeSdk.isSelected()
        self.sdk_value = self.tfSdk.getText().strip()
        self.sign_content_type = self.cbSignCT.isSelected()
        self.unsigned_payload = self.cbUnsigned.isSelected()
        try:
            self.host_regex = re.compile(self.tfHostRe.getText().strip(), re.I)
        except:
            self.log("Invalid host regex; keeping previous.")

        self.tools_enabled = set()
        if self.cbScanner.isSelected(): self.tools_enabled.add(self.cb.TOOL_SCANNER)
        if self.cbRepeater.isSelected(): self.tools_enabled.add(self.cb.TOOL_REPEATER)
        if self.cbIntruder.isSelected(): self.tools_enabled.add(self.cb.TOOL_INTRUDER)
        if self.cbProxy.isSelected(): self.tools_enabled.add(self.cb.TOOL_PROXY)

        self.log("Applied settings.")

    def getTabCaption(self):
        return "FP Signer"

    def getUiComponent(self):
        return self.panel

    def log(self, msg):
        self.logArea.append(msg + "\n"); self.logArea.setCaretPosition(self.logArea.getDocument().getLength())

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        if toolFlag not in self.tools_enabled:
            return

        req = messageInfo.getRequest()
        info = self.helpers.analyzeRequest(req)
        headers = info.getHeaders()
        body = req[info.getBodyOffset():] 

        request_line = headers.get(0)
        try:
            method, path_qs, _ = request_line.split(" ", 2)
        except:
            return

        if "?" in path_qs:
            raw_path, raw_qs = path_qs.split("?", 1)
        else:
            raw_path, raw_qs = path_qs, ""

        host_value = None
        ct_value = None
        new_headers = []
        for h in headers:
            hl = h.lower()
            if hl.startswith("host:"):
                host_value = h.split(":", 1)[1].strip()
            elif hl.startswith("content-type:"):
                ct_value = h.split(":", 1)[1].strip()
            if hl.startswith("x-fp-date:") or hl.startswith("x-fp-signature:"):
                continue
            if hl.startswith("x-fp-sdk-version:") and not self.include_sdk:
                continue
            new_headers.append(h)

        if host_value is None:
            url = info.getUrl()
            host_value = url.getHost()

        if not self.host_regex.search(host_value):
            return

        xfp_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        hdrs = {"host": host_value, "x-fp-date": xfp_date}
        if self.include_sdk:
            hdrs["x-fp-sdk-version"] = self.sdk_value
        if self.sign_content_type and ct_value:
            hdrs["content-type"] = ct_value

        names = sorted(hdrs.keys())
        ch = "".join(["%s:%s\n" % (k, hdrs[k]) for k in names])
        sh = ";".join(names)

        try:
            body_bytes = body.tostring()
        except:
            body_bytes = bytes(body)

        payload_hash = "UNSIGNED-PAYLOAD" if self.unsigned_payload else sha256_hex(body_bytes)

        canonical = "\n".join([
            method.upper(),
            normalize_path(raw_path),
            canon_query(raw_qs),
            ch.rstrip("\n") + "\n",
            sh,
            payload_hash
        ])

        sts = xfp_date + "\n" + sha256_hex(canonical.encode("utf-8"))
        sig = "v1.1:" + hmac_sha256_hex(self.secret.encode("utf-8"), sts.encode("utf-8"))

        new_headers = list(new_headers)
        new_headers.append("X-Fp-Date: " + xfp_date)
        if self.include_sdk:
            new_headers = [h for h in new_headers if not h.lower().startswith("x-fp-sdk-version:")]
            new_headers.append("X-Fp-Sdk-Version: " + self.sdk_value)
        new_headers.append("X-Fp-Signature: " + sig)

        new_req = self.helpers.buildHttpMessage(new_headers, body)
        messageInfo.setRequest(new_req)

