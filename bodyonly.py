from burp import IBurpExtender, IMessageEditorTabFactory, IMessageEditorTab
from javax.swing import JPanel
from java.awt import BorderLayout
import re

class BurpExtender(IBurpExtender, IMessageEditorTabFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        callbacks.setExtensionName("Body Only (Pretty JSON)")
        callbacks.registerMessageEditorTabFactory(self)

    def createNewInstance(self, controller, editable):
        return BodyOnlyTab(self.callbacks, controller, editable)

class BodyOnlyTab(IMessageEditorTab):
    def __init__(self, callbacks, controller, editable):
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
            response_str = content.tostring()

            # Extract body from full response
            header_end = response_str.index("\r\n\r\n")
            body = response_str[header_end + 4:]

            # Remove Facebook guard (e.g., for (;;);)
            body = re.sub(r"^for\s*\(;;\);", "", body)

            # Try to parse just the JSON body
            if body.strip().startswith("{") or body.strip().startswith("["):
                fake_headers = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Content-Length: {}\r\n\r\n"
                ).format(len(body.encode("utf-8")))
                fake_response = fake_headers + body
                self._editor.setMessage(fake_response.encode(), False)
            else:
                self._editor.setMessage(None, False)
        except Exception:
            self._editor.setMessage(None, False)
