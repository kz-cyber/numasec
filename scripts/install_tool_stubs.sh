#!/bin/bash
# NumaSec Tool Stubs - For Development/Testing Only
# Creates mock binaries that return minimal valid output
# This allows testing agent logic without installing 2GB of security tools

set -e

STUB_DIR="$HOME/.local/bin"
mkdir -p "$STUB_DIR"

echo "Installing tool stubs to $STUB_DIR"

# nmap stub - returns minimal XML
cat > "$STUB_DIR/nmap" << 'EOF'
#!/bin/bash
echo '<?xml version="1.0"?>
<nmaprun scanner="nmap" args="stub" start="1740000000" startstr="Mock" version="7.94">
  <host>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3000">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Node.js" version="unknown"/>
      </port>
    </ports>
  </host>
  <runstats>
    <finished time="1740000001" timestr="Mock" elapsed="1.00"/>
  </runstats>
</nmaprun>'
EOF

# httpx stub - returns JSON
cat > "$STUB_DIR/httpx" << 'EOF'
#!/bin/bash
echo '{"url":"http://127.0.0.1:3000","status_code":200,"title":"Mock","webserver":"nginx","tech":["JavaScript"]}'
EOF

# nuclei stub
cat > "$STUB_DIR/nuclei" << 'EOF'
#!/bin/bash
echo '{"template":"mock-template","matched":"http://127.0.0.1:3000","info":{"name":"Mock Vulnerability","severity":"low"}}'
EOF

# nikto stub
cat > "$STUB_DIR/nikto" << 'EOF'
#!/bin/bash
echo "+ Target IP: 127.0.0.1
+ Target Port: 3000
+ Server: Mock Server
+ No issues found (stub mode)"
EOF

# subfinder stub
cat > "$STUB_DIR/subfinder" << 'EOF'
#!/bin/bash
echo "www.example.com
api.example.com
admin.example.com"
EOF

# whatweb stub
cat > "$STUB_DIR/whatweb" << 'EOF'
#!/bin/bash
echo '[{"target":"http://127.0.0.1:3000","http_status":200,"plugins":{"HTTPServer":["nginx"],"Title":["Mock Site"]}}]'
EOF

# ffuf stub
cat > "$STUB_DIR/ffuf" << 'EOF'
#!/bin/bash
echo '{"results":[{"url":"http://127.0.0.1:3000/admin","status":200,"length":1234}]}'
EOF

# hydra stub
cat > "$STUB_DIR/hydra" << 'EOF'
#!/bin/bash
echo "[3000][http-post-form] host: 127.0.0.1   login: admin   password: admin123"
EOF

# sqlmap stub
cat > "$STUB_DIR/sqlmap" << 'EOF'
#!/bin/bash
echo "[INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[INFO] target is vulnerable to SQL injection"
EOF

# Make all executable
chmod +x "$STUB_DIR"/{nmap,httpx,nuclei,nikto,subfinder,whatweb,ffuf,hydra,sqlmap}

echo "✅ Tool stubs installed"
echo "Add to PATH: export PATH=\"$STUB_DIR:\$PATH\""
echo ""
echo "⚠️  WARNING: These are MOCK tools that return fake data"
echo "    For real pentesting, use: podman run -it numasec"
