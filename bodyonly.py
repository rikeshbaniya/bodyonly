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
            response_str = self._helpers.bytesToString(content)
            header_end = self._findHeaderEnd(response_str)
            if header_end == -1:
                self._editor.setMessage(None, False)
                return

            body = response_str[header_end:]
            body = self._removeJsonGuards(body).strip()

            if self._isJson(body):
                try:
                    json_obj = json.loads(body)
                    pretty_json = json.dumps(json_obj, indent=2, ensure_ascii=False)
                except ValueError as e:
                    self._callbacks.printError("JSON parsing error: " + str(e))
                    pretty_json = body
            else:
                pretty_json = body

            # Force Content-Type to application/json always
            fake_response = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: {}\r\n\r\n"
                "{}"
            ).format(len(pretty_json.encode('utf-8')), pretty_json)

            self._editor.setMessage(self._helpers.stringToBytes(fake_response), False)

        except Exception as e:
            self._callbacks.printError("BodyOnlyTab error: " + str(e))
            self._editor.setMessage(None, False)

    def _findHeaderEnd(self, response_str):
        patterns = ['\r\n\r\n', '\n\n', '\r\n\n', '\n\r\n']
        for pattern in patterns:
            pos = response_str.find(pattern)
            if pos != -1:
                return pos + len(pattern)
        return -1

    def _removeJsonGuards(self, body):
        guards = [
            r'^\s*for\s*\(\s*;\s*;\s*\)\s*;\s*',
            r'^\s*while\s*\(\s*1\s*\)\s*;\s*',
            r'^\s*\)\]\}\'\s*',
            r'^\s*/\*\*/\s*'
        ]
        for guard in guards:
            body = re.sub(guard, '', body)
        return body

    def _isJson(self, body):
        body = body.strip()
        return body.startswith('{') or body.startswith('[')
