from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel
from java.awt import BorderLayout
import re
import json

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Body Only (Pretty JSON)")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return BodyOnlyTab(self.callbacks, controller, editable)

class BodyOnlyTab(IMessageEditorTab):
    def __init__(self, callbacks, controller, editable):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._editable = editable
        self._editor = callbacks.createMessageEditor(None, editable)
        self._panel = JPanel(BorderLayout())
        self._panel.add(self._editor.getComponent(), BorderLayout.CENTER)

    def getUiComponent(self):
        return self._panel

    def getTabCaption(self):
        return "Body Only"

    def isEnabled(self, content, isRequest):
        return content is not None and not isRequest

    def isModified(self):
        return self._editor.isMessageModified()

    def getMessage(self):
        return self._editor.getMessage()

    def setMessage(self, content, isRequest):
        if content is None or isRequest:
            self._editor.setMessage(None, False)
            return

        try:
            # Convert byte array to string
            response_str = self._helpers.bytesToString(content)
            
            # Find the header/body separator
            header_end = self._findHeaderEnd(response_str)
            if header_end == -1:
                self._editor.setMessage(None, False)
                return

            body = response_str[header_end:]
            
            # Remove JSON guards (Facebook, Google, etc.)
            body = self._removeJsonGuards(body).strip()
            
            # Try to parse as JSON
            if self._isJson(body):
                try:
                    json_obj = json.loads(body)
                    pretty_json = json.dumps(json_obj, indent=2, ensure_ascii=False)
                    
                    # Create fake response with pretty JSON and correct content type
                    fake_response = (
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: application/json\r\n"
                        "Content-Length: {}\r\n\r\n"
                        "{}"
                    ).format(len(pretty_json.encode('utf-8')), pretty_json)
                    
                    self._editor.setMessage(self._helpers.stringToBytes(fake_response), False)
                    return
                except ValueError as e:
                    self._callbacks.printError("JSON parsing error: " + str(e))
            
            # If not JSON or parsing failed, show raw body but still try to pretty print if it looks like JSON
            if self._looksLikeJson(body):
                try:
                    json_obj = json.loads(body)
                    pretty_json = json.dumps(json_obj, indent=2, ensure_ascii=False)
                    content_type = "application/json"
                except:
                    pretty_json = body
                    content_type = "text/plain"
            else:
                pretty_json = body
                content_type = "text/plain"
            
            fake_response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: {}\r\n"
                "Content-Length: {}\r\n\r\n"
                "{}"
            ).format(content_type, len(pretty_json.encode('utf-8')), pretty_json)
            
            self._editor.setMessage(self._helpers.stringToBytes(fake_response), False)
            
        except Exception as e:
            self._callbacks.printError("BodyOnlyTab error: " + str(e))
            self._editor.setMessage(None, False)

    def _findHeaderEnd(self, response_str):
        """Find the end of HTTP headers using various possible separators"""
        patterns = [
            '\r\n\r\n',  # Standard HTTP
            '\n\n',      # Some servers
            '\r\n\n',    # Mixed
            '\n\r\n'     # Rare but possible
        ]
        
        for pattern in patterns:
            pos = response_str.find(pattern)
            if pos != -1:
                return pos + len(pattern)
        return -1

    def _removeJsonGuards(self, body):
        """Remove common JSON guards like Facebook's for(;;);"""
        guards = [
            r'^\s*for\s*\(\s*;\s*;\s*\)\s*;\s*',  # Facebook
            r'^\s*while\s*\(\s*1\s*\)\s*;\s*',    # Others
            r'^\s*\)\]\}\'\s*',                   # Google
            r'^\s*/\*\*/\s*'                      # Some APIs
        ]
        
        for guard in guards:
            body = re.sub(guard, '', body)
        
        return body

    def _isJson(self, body):
        """Check if string is valid JSON"""
        body = body.strip()
        return body.startswith('{') or body.startswith('[')

    def _looksLikeJson(self, body):
        """Check if string looks like JSON (even if malformed)"""
        body = body.strip()
        return (body.startswith('{') and body.endswith('}')) or (body.startswith('[') and body.endswith(']'))
