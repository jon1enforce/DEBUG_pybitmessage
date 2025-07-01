"""Subclass of HTMLParser.HTMLParser for MessageView widget"""

import inspect
import re
from six.moves.html_parser import HTMLParser
from six.moves.urllib.parse import quote_plus, urlparse
from unqstr import ustr, unic

class SafeHTMLParser(HTMLParser):
    """HTML parser with sanitisation"""
    # from html5lib.sanitiser
    acceptable_elements = (
        'a', 'abbr', 'acronym', 'address', 'area',
        'article', 'aside', 'audio', 'b', 'big', 'blockquote', 'br', 'button',
        'canvas', 'caption', 'center', 'cite', 'code', 'col', 'colgroup',
        'command', 'datagrid', 'datalist', 'dd', 'del', 'details', 'dfn',
        'dialog', 'dir', 'div', 'dl', 'dt', 'em', 'event-source', 'fieldset',
        'figcaption', 'figure', 'footer', 'font', 'header', 'h1',
        'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'ins',
        'keygen', 'kbd', 'label', 'legend', 'li', 'm', 'map', 'menu', 'meter',
        'multicol', 'nav', 'nextid', 'ol', 'output', 'optgroup', 'option',
        'p', 'pre', 'progress', 'q', 's', 'samp', 'section', 'select',
        'small', 'sound', 'source', 'spacer', 'span', 'strike', 'strong',
        'sub', 'sup', 'table', 'tbody', 'td', 'textarea', 'time', 'tfoot',
        'th', 'thead', 'tr', 'tt', 'u', 'ul', 'var', 'video'
    )
    replaces_pre = (
        ("&", "&amp;"), ("\"", "&quot;"), ("<", "&lt;"), (">", "&gt;"))
    replaces_post = (
        ("\n", "<br/>"), ("\t", "&nbsp;&nbsp;&nbsp;&nbsp;"),
        ("  ", "&nbsp; "), ("  ", "&nbsp; "), ("<br/> ", "<br/>&nbsp;"))
    src_schemes = ["data"]
    uriregex1 = re.compile(
        r'((https?|ftp|bitcoin):(?:/{1,3}|[a-z0-9%])'
        r'(?:[a-zA-Z]|[0-9]|[$-_@.&+#]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)'
    )
    uriregex2 = re.compile(r'<a href="([^"]+)&amp;')
    emailregex = re.compile(
        r'\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b')

    @staticmethod
    def replace_pre(text):
        """Perform substring replacement before regex replacements"""
        print(f"DEBUG: [SafeHTMLParser.replace_pre] Processing text (length: {len(text)})")
        for a in SafeHTMLParser.replaces_pre:
            text = text.replace(*a)
            print(f"DEBUG: [SafeHTMLParser.replace_pre] Replaced {a[0]} with {a[1]}")
        return text

    @staticmethod
    def replace_post(text):
        """Perform substring replacement after regex replacements"""
        print(f"DEBUG: [SafeHTMLParser.replace_post] Processing text (length: {len(text)})")
        for a in SafeHTMLParser.replaces_post:
            text = text.replace(*a)
            print(f"DEBUG: [SafeHTMLParser.replace_post] Replaced {a[0]} with {a[1]}")
        if len(text) > 1 and text[0] == " ":
            text = "&nbsp;" + text[1:]
            print("DEBUG: [SafeHTMLParser.replace_post] Replaced leading space with &nbsp;")
        return text

    def __init__(self, *args, **kwargs):
        print("DEBUG: [SafeHTMLParser.__init__] Initializing SafeHTMLParser")
        HTMLParser.__init__(self, *args, **kwargs)
        self.reset()
        self.reset_safe()
        self.has_html = None
        self.allow_picture = None

    def reset_safe(self):
        """Reset runtime variables specific to this class"""
        print("DEBUG: [SafeHTMLParser.reset_safe] Resetting parser state")
        self.elements = set()
        self.raw = u""
        self.sanitised = u""
        self.has_html = False
        self.allow_picture = False
        self.allow_external_src = False

    def add_if_acceptable(self, tag, attrs=None):
        """Add tag if it passes sanitisation"""
        print(f"DEBUG: [SafeHTMLParser.add_if_acceptable] Processing tag: {tag}")
        if tag not in self.acceptable_elements:
            print(f"DEBUG: [SafeHTMLParser.add_if_acceptable] Tag {tag} not in acceptable_elements")
            return
        
        self.sanitised += "<"
        if inspect.stack()[1][3] == "handle_endtag":
            self.sanitised += "/"
        self.sanitised += tag
        
        if attrs is not None:
            print(f"DEBUG: [SafeHTMLParser.add_if_acceptable] Processing {len(attrs)} attributes")
            for attr, val in attrs:
                original_val = val
                if tag == "img" and attr == "src" and not self.allow_picture:
                    val = ""
                    print("DEBUG: [SafeHTMLParser.add_if_acceptable] Picture not allowed, clearing src")
                elif attr == "src" and not self.allow_external_src:
                    url = urlparse(val)
                    if url.scheme not in self.src_schemes:
                        val = ""
                        print(f"DEBUG: [SafeHTMLParser.add_if_acceptable] External src not allowed, clearing src (scheme: {url.scheme})")
                
                self.sanitised += " " + quote_plus(attr)
                if val is not None:
                    if original_val != val:
                        print(f"DEBUG: [SafeHTMLParser.add_if_acceptable] Attribute {attr} modified from '{original_val}' to '{val}'")
                    self.sanitised += "=\"" + val + "\""
        
        if inspect.stack()[1][3] == "handle_startendtag":
            self.sanitised += "/"
        self.sanitised += ">"
        print(f"DEBUG: [SafeHTMLParser.add_if_acceptable] Added tag: {tag}")

    def handle_starttag(self, tag, attrs):
        print(f"DEBUG: [SafeHTMLParser.handle_starttag] Handling start tag: {tag}")
        if tag in self.acceptable_elements:
            self.has_html = True
            print(f"DEBUG: [SafeHTMLParser.handle_starttag] Tag {tag} is acceptable HTML")
        self.add_if_acceptable(tag, attrs)

    def handle_endtag(self, tag):
        print(f"DEBUG: [SafeHTMLParser.handle_endtag] Handling end tag: {tag}")
        self.add_if_acceptable(tag)

    def handle_startendtag(self, tag, attrs):
        print(f"DEBUG: [SafeHTMLParser.handle_startendtag] Handling startend tag: {tag}")
        if tag in self.acceptable_elements:
            self.has_html = True
            print(f"DEBUG: [SafeHTMLParser.handle_startendtag] Tag {tag} is acceptable HTML")
        self.add_if_acceptable(tag, attrs)

    def handle_data(self, data):
        print(f"DEBUG: [SafeHTMLParser.handle_data] Handling data (length: {len(data)})")
        self.sanitised += data

    def handle_charref(self, name):
        print(f"DEBUG: [SafeHTMLParser.handle_charref] Handling charref: {name}")
        self.sanitised += "&#" + name + ";"

    def handle_entityref(self, name):
        print(f"DEBUG: [SafeHTMLParser.handle_entityref] Handling entityref: {name}")
        self.sanitised += "&" + name + ";"

    def feed(self, data):
        print(f"DEBUG: [SafeHTMLParser.feed] Feeding data (length: {len(data) if data else 0})")
        try:
            data = unic(ustr(data))
            print("DEBUG: [SafeHTMLParser.feed] Successfully converted input data to unicode")
        except TypeError as e:
            print(f"DEBUG: [SafeHTMLParser.feed] TypeError during data conversion: {e}")
            pass
        
        HTMLParser.feed(self, data)
        
        print("DEBUG: [SafeHTMLParser.feed] Applying pre-replacements")
        tmp = SafeHTMLParser.replace_pre(data)
        
        print("DEBUG: [SafeHTMLParser.feed] Applying URI regex substitutions")
        tmp = self.uriregex1.sub(r'<a href="\1">\1</a>', tmp)
        tmp = self.uriregex2.sub(r'<a href="\1&', tmp)
        tmp = self.emailregex.sub(r'<a href="mailto:\1">\1</a>', tmp)
        
        print("DEBUG: [SafeHTMLParser.feed] Applying post-replacements")
        tmp = SafeHTMLParser.replace_post(tmp)
        
        self.raw += tmp
        print(f"DEBUG: [SafeHTMLParser.feed] Final processed data length: {len(tmp)}")

    def is_html(self, text=None, allow_picture=False):
        """Detect if string contains HTML tags"""
        print(f"DEBUG: [SafeHTMLParser.is_html] Checking for HTML (allow_picture: {allow_picture})")
        if text:
            print(f"DEBUG: [SafeHTMLParser.is_html] Processing text (length: {len(text)})")
            self.reset()
            self.reset_safe()
            self.allow_picture = allow_picture
            self.feed(text)
            self.close()
        print(f"DEBUG: [SafeHTMLParser.is_html] HTML detected: {self.has_html}")
        return self.has_html
